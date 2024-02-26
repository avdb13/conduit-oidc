use crate::{
    service::sso::{templates, COOKIE_STATE_EXPIRATION_SECS},
    services, Error, Ruma, RumaResponse,
};
use askama::Template;
use axum::{body::Full, response::IntoResponse};
use axum_extra::extract::cookie::{Cookie, SameSite};
use bytes::BytesMut;
use http::StatusCode;
use ruma::api::{
    client::{error::ErrorKind, session},
    OutgoingResponse,
};

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

    return get_sso_fallback_template(body.redirect_url.as_deref().unwrap_or_default()).into_response();
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
        return get_sso_fallback_template(body.redirect_url.as_deref().unwrap_or_default()).into_response();
    };

    let Some(provider) = services().sso.get_provider(&body.idp_id) else {
        return Error::BadRequest(ErrorKind::NotFound, "Unknown identity provider").into_response();
    };

    let (location, cookie) = provider.handle_redirect(body.redirect_url.as_deref().unwrap_or_default()).await;

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
        location: Some(location.to_string()),
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

/// # `GET  /_conduit/client/oidc/callback`
///
/// Verify the response received from the identity provider.
/// If everything is fine redirect
pub async fn get_sso_callback() {}
