use axum::extract::Query;
use axum::response::IntoResponse;
use axum_extra::extract::cookie::{Cookie, SameSite};
use axum_extra::extract::CookieJar;
use macaroon::Macaroon;
use openid::{Token, Userinfo, Provider};
use rand::{thread_rng, Rng};
use reqwest::Url;
use ring::digest;
use ruma::api::client::error::ErrorKind;
use serde::{Deserialize, Serialize};

use crate::{services, Result, Error};

const COOKIE_STATE_EXPIRATION_SECS: i64 = 10 * 60;
const MAC_VALID_SECS: i64 = 10;
const PROOF_KEY_LEN: usize = 32;
const NONCE_LEN: usize = 32;

#[derive(Deserialize, Serialize)]
struct State {
    after_auth: String,
    proof_key: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SsoRedirectParams {
    pub redirect_url: String,
}

/// # `GET  /_matrix/client/v3/login/sso/redirect`
///
/// Redirect user to SSO interface.
///
pub async fn get_sso_redirect(
    Query(params): Query<SsoRedirectParams>,
    // State(uia_session): State<Option<()>>,
    cookies: CookieJar,
) -> Result<impl IntoResponse> {
    let SsoRedirectParams { redirect_url } = params;

    let client = services().globals.oidc.as_ref().unwrap();
    let key = services().globals.macaroon.as_ref()
.ok_or(Error::BadConfig(&"Missing macaroon key in config file."))?;

    use base64::{
        alphabet,
        engine::{self, general_purpose},
        Engine as _,
    };

    const CUSTOM_ENGINE: engine::GeneralPurpose =
        engine::GeneralPurpose::new(&alphabet::URL_SAFE, general_purpose::NO_PAD);

    // https://datatracker.ietf.org/doc/html/rfc7636#section-4.1
    let mut arr = [0u8; PROOF_KEY_LEN];

    thread_rng().fill(&mut arr[..]);
    let proof_key = CUSTOM_ENGINE.encode(arr);

    thread_rng().fill(&mut arr[..]);
    let nonce = CUSTOM_ENGINE.encode(arr);

    let state = State {
        after_auth: redirect_url.to_string(),
        proof_key,
    };

    let state = serde_json::to_string(&state).unwrap();

    let key = macaroon::MacaroonKey::generate(key.as_ref());
    let mut macaroon = macaroon::Macaroon::create(None, &key, "key".into()).unwrap();
    let issuer = client.provider.auth_uri();

    let expires = chrono::Utc::now() + chrono::TimeDelta::seconds(COOKIE_STATE_EXPIRATION_SECS);

    macaroon.add_first_party_caveat(format!("state = {state}").into());
    macaroon.add_first_party_caveat(format!("provider = ???", ).into());
    macaroon.add_first_party_caveat(format!("state = {state}").into());
    macaroon.add_first_party_caveat(format!("nonce = {nonce}").into());
    macaroon.add_first_party_caveat(format!("redirect_url = {redirect_url}").into());

    let cookie1 = Cookie::build("openid-state", state_b64)
        .path("/sso_return")
        .secure(false) //FIXME
        // .secure(true)
        .http_only(true)
        .same_site(SameSite::None)
        .max_age(time::Duration::seconds(COOKIE_STATE_EXPIRATION_SECS))
        .finish();
    let updated_jar = cookies.add(cookie1);

    let cookie2 = Cookie::build("openid-state-no-samesite", state_b64)
        .path("/sso_return")
        .http_only(true)
        .max_age(time::Duration::seconds(COOKIE_STATE_EXPIRATION_SECS))
        .finish();
    let updated_jar = cookies.add(cookie1).add(cookie2);


    let auth_url = client.auth_url(&openid::Options {
        scope: Some("email".into()),
        state: Some(state_b64_sha256_b64.to_string()),
        ..Default::default()
    });

    let redirect = axum::response::Redirect::to(auth_url.as_ref());
    Ok((updated_jar, redirect))
}

async fn request_token(
    oidc_client: &openid::DiscoveredClient,
    code: &str,
) -> Result<(Token, Userinfo), Error> {
    let mut token: Token = oidc_client.request_token(code).await
        .map_err(|_| Error::BadRequest(ErrorKind::Unknown, "OICD token request failed."))?
        .into();

    let Some(ref mut id_token) = token.id_token else {
        return Err(Error::BadServerResponse("OICD token did not contain id_token"))?;
    };

    oidc_client.decode_token(id_token)
        .map_err(|_| Error::BadRequest(ErrorKind::Unknown, "Couldn't decode token."))?;
    oidc_client.validate_token(id_token, None, None)
        .map_err(|_| Error::BadRequest(ErrorKind::Unknown, "Couldn't validate token."))?;

    let userinfo = oidc_client.request_userinfo(&token).await
        .map_err(|_| Error::BadServerResponse("Requesting userinfo failed."))?;

    Ok((token, userinfo))
}

// #[derive(Debug)]
// struct User {
//     id: String,
//     login: Option<String>()
//     first_name: Option<String>,
//     last_name: Option<String>,
//     email: Option<String>,
//     image_url: Option<String>,
//     activated: bool,
//     lang_key: Option<String>,
//     authorities: Vec<String>,
// }

// #[derive(Debug, Responder)]
// pub enum ExampleResponse<'a> {
//     Redirect(Redirect),
//     Unauthorized(rocket::response::status::Unauthorized<&'a str>),
// }

#[derive(Debug, Deserialize)]
pub struct Params {
    // pub session_state: String,
    pub state: String,
    pub code: String,
}

pub async fn get_sso_return(
    Query(params): Query<Params>,
    cookies: CookieJar,
) -> Result<impl IntoResponse> {
    let Params { code, state, .. } = params;

    use base64::{
        alphabet,
        engine::{self, general_purpose},
        Engine as _,
    };

    const CUSTOM_ENGINE: engine::GeneralPurpose =
        engine::GeneralPurpose::new(&alphabet::URL_SAFE, general_purpose::NO_PAD);

    let state = CUSTOM_ENGINE.decode(state).unwrap();

    // TODO: test with expired/deleted cookie
    let cookie_state = cookies.get("openid-state").unwrap();
    let cookie_state_b64_sha256 =
        digest::digest(&digest::SHA256, &cookie_state.value().as_bytes());

    if state != cookie_state_b64_sha256.as_ref() {
        // return ExampleResponse::Unauthorized(rocket::response::status::Unauthorized(Some(
        //     "invalid state",
        // )));
        panic!("invalid state");
    }

    let decoded_state = CUSTOM_ENGINE.decode(cookie_state.value()).unwrap();
    let decoded_state: State = serde_json::from_slice(&decoded_state).unwrap();

    let openid_client = &services().globals.openid_client;
    let (key, client) = openid_client.as_ref().unwrap();

    let username;
    match request_token(client, &code).await {
        Ok(Some((_token, userinfo))) => {
            /*
                        let id = uuid::Uuid::new_v4().to_string();

                        let login = userinfo.preferred_username.clone();
                        let email = userinfo.email.clone();
            h
                        let new_user = User {
                            id: userinfo.sub.clone().unwrap_or_default(),
                            login,
                            last_name: userinfo.family_name.clone(),
                            first_name: userinfo.name.clone(),
                            email,
                            activated: userinfo.email_verified,
                            image_url: userinfo.picture.clone().map(|x| x.to_string()),
                            lang_key: Some("en".to_string()),
                            authorities: vec!["ROLE_USER".to_string()], //FIXME: read from token
                        };
                        */

            // user = new_user.login.unwrap();
            username = userinfo.preferred_username.unwrap();
        }
        Ok(None) => {
            // return ExampleResponse::Unauthorized(rocket::response::status::Unauthorized(Some(
            //     "no id_token found",
            // )));
            panic!("no id_token found");
        }
        Err(err) => {
            eprintln!("login error in call: {:?}", err);
            // return ExampleResponse::Unauthorized(rocket::response::status::Unauthorized(Some(
            //     "login error in call",
            // )));
            panic!("login error in call");
        }
    }

    // Create our macaroon
    let mut macaroon = match Macaroon::create(Some("location".into()), &key, username.into()) {
        Ok(macaroon) => macaroon,
        Err(error) => panic!("Error creating macaroon: {:?}", error),
    };

    let something = format!("time < {}", chrono::Utc::now().timestamp() + MAC_VALID_SECS).into();
    macaroon.add_first_party_caveat(something);

    let serialized = macaroon.serialize(macaroon::Format::V2).unwrap();
    let encoded = CUSTOM_ENGINE.encode(serialized);

    let redirect_url =
        Url::parse_with_params(&decoded_state.after_auth, &[("loginToken", encoded)]).unwrap();

    let redirect = axum::response::Redirect::to(&redirect_url.to_string());

    Ok(redirect)
}
