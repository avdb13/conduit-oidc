use crate::{
    service::sso::{macaroon::Macaroon, templates, COOKIE_STATE_EXPIRATION_SECS},
    services, Error, Ruma,
};
use askama::Template;
use axum::{body::Full, response::IntoResponse};
use axum_extra::extract::cookie::{Cookie, SameSite};
use bytes::BytesMut;
use http::{HeaderValue, StatusCode};
use openidconnect::{
    AuthorizationCode, CsrfToken,
};
use ruma::api::{
    client::{error::ErrorKind, session},
    OutgoingResponse,
};
use serde::Deserialize;

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

    let (url, nonce, cookie) =
        match services().sso.find_one(&body.idp_id).map(|provider| {
            provider.handle_redirect(body.redirect_url.unwrap())
        }) {
            Ok(fut) => fut.await,
            Err(e) => return e.into_response(),
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
    pub verifier: String,
}

pub struct Session {}

/// # `GET  /_conduit/client/oidc/callback`
///
/// Verify the response received from the identity provider.
/// If everything is fine redirect
pub async fn get_sso_callback(
    cookie: axum::extract::TypedHeader<axum::headers::Cookie>,
    axum::extract::Query(callback): axum::extract::Query<Callback>,
) -> axum::response::Response {
    let clear_cookie = Cookie::build("openid-state", "")
        .path("/_conduit/client/sso")
        .finish()
        .to_string();

    let Callback {
        code,
        state,
        verifier,
    } = callback;

    let Some(cookie) = cookie.get("openid-state") else {
        return Error::BadRequest(
            ErrorKind::MissingToken,
            "Could not retrieve SSO macaroon from cookie",
        )
        .into_response();
    };

    let macaroon = match Macaroon::verify(cookie, state.secret()) {
        Ok(macaroon) => macaroon,
        Err(error) => return error.into_response(),
    };

    let provider = match services().sso.find_one(macaroon.idp_id.as_ref()) {
        Ok(provider) => provider,
        Err(error) => return error.into_response(),
    };
    let session = serde_json::to_string(cookie).unwrap();

    let user_info = provider.handle_callback(code, macaroon.nonce).await;

    (
        axum::TypedHeader(axum::headers::Location(
            HeaderValue::from_str(clear_cookie.as_str()).unwrap(),
        )),
        "Hello, World!",
    )
        .into_response()
}
