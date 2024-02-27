use crate::{
    service::sso::{templates, Provider, COOKIE_STATE_EXPIRATION_SECS},
    services, Error, Ruma, RumaResponse,
};
use askama::Template;
use axum::{body::Full, response::IntoResponse};
use axum_extra::extract::cookie::{Cookie, SameSite};
use bytes::BytesMut;
use http::StatusCode;
use macaroon::ByteString;
use openidconnect::{reqwest::{http_client, async_http_client}, AuthorizationCode, CsrfToken, TokenResponse};
use ruma::api::{
    client::{error::ErrorKind, session},
    OutgoingResponse,
};
use serde::Deserialize;
use time::macros::format_description;

/// # `GET  /_matrix/client/v3/login/sso/redirect`
///
/// Redirect user to SSO interface. The path argument is optional.
pub async fn get_sso_redirect(
    body: Ruma<session::sso_login::v3::Request>,
) -> axum::response::Response {
    if services().sso.get_all().is_empty() {
        return Error::BadRequest(ErrorKind::NotFound, "SSO has not been configured")
            .into_response();
    }

    return get_sso_fallback_template(body.redirect_url.as_deref().unwrap_or_default())
        .into_response();
}

/// # `GET  /_matrix/client/v3/login/sso/redirect/{idpId}`
///
/// Redirect user to SSO interface.
pub async fn get_sso_redirect_with_provider(
    // State(uiaa_session): State<Option<()>>,
    body: Ruma<session::sso_login_with_provider::v3::Request>,
) -> axum::response::Response {
    if services().sso.get_all().is_empty() {
        return Error::BadRequest(ErrorKind::NotFound, "SSO has not been configured")
            .into_response();
    }

    if body.idp_id.is_empty() {
        return get_sso_fallback_template(body.redirect_url.as_deref().unwrap_or_default())
            .into_response();
    };

    let location = Some(body.idp_id.clone());

    let (url, nonce, cookie) = match services().sso.find_one(&body.idp_id).map(|provider| provider.handle_redirect(body.redirect_url.as_deref().unwrap_or_default())) {
        Ok(fut)=> fut.await,
        Err(e)=> return e.into_response(),
    };


    let cookie = Cookie::build("openid-state", cookie)
        .path("/_conduit/client/sso")
        // .secure(false) //FIXME
        .secure(true)
        .http_only(true)
        .same_site(SameSite::None)
        .max_age(time::Duration::seconds(COOKIE_STATE_EXPIRATION_SECS))
        .finish()
        .to_string();

    let mut res = session::sso_login_with_provider::v3::Response {
        location,
        cookie: Some(cookie),
    }
    .try_into_http_response::<BytesMut>()
    .unwrap();

    *res.status_mut() = StatusCode::FOUND;

    res.map(BytesMut::freeze).map(Full::new).into_response()
}

fn get_sso_fallback_template(redirect_url: &str) -> axum::response::Response {
    let server_name = services().globals.server_name().to_string();
    let metadata = services().sso.inner.iter().map(Into::into).collect();
    let redirect_url = redirect_url.to_string();

    let t = templates::IdpPicker {
        server_name,
        metadata,
        redirect_url,
    };

    t.render()
        .map(|body| {
            ((
                [(
                    http::header::CONTENT_TYPE,
                    http::HeaderValue::from_static(templates::IdpPicker::MIME_TYPE),
                )],
                body,
            ))
                .into_response()
        })
        .expect("woops")
}

#[derive(Deserialize)]
pub struct Callback {
    pub code: AuthorizationCode,
    pub state: CsrfToken,
}

/// # `GET  /_conduit/client/oidc/callback`
///
/// Verify the response received from the identity provider.
/// If everything is fine redirect
pub async fn get_sso_callback(
    cookie: axum::extract::TypedHeader<axum::headers::Cookie>,
    axum::extract::Query(callback): axum::extract::Query<Callback>,
) -> axum::response::Response {
    // TODO

    let Callback { code, state } = callback;

    let Some(cookie) = cookie.get("openid-state") else {
        return Error::BadRequest(
            ErrorKind::MissingToken,
            "Could not retrieve SSO macaroon from cookie",
        )
        .into_response();
    };

    let provider = match Provider::verify_macaroon(cookie.as_bytes(), state)
        .and_then(|macaroon| services().sso.find_one(macaroon.identifier().into()))
    {
        Ok(provider) => provider,
        Err(error) => return error.into_response(),
    };




    let cookie = Cookie::build("openid-state", "")
        .path("/_conduit/client/sso")
        .finish()
        .to_string();

    let user_info = provider.handle_callback(code, nonce);

    // if let Some(verifier) = pkce {
    //     macaroon.add_first_party_caveat(format!("verifier = {}", verifier).into());
    // }

    (TypedHeader(ContentType::text_utf8()), "Hello, World!").into_response()
}
