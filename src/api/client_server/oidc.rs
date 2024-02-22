use crate::{
    config::Metadata, service::oidc::COOKIE_STATE_EXPIRATION_SECS, services, Error, Result, Ruma,
};
use askama::Template;
use axum::response::IntoResponse;
use axum_extra::extract::cookie::{Cookie, SameSite};
use bytes::BufMut;
use http::{header::COOKIE, HeaderValue, StatusCode};
use ruma::api::{
    client::{error::ErrorKind, session},
    error::IntoHttpError,
    OutgoingResponse,
};

// const SEED_LEN: usize = 32;

/// # `GET  /_matrix/client/v3/login/sso/redirect`
///
/// Redirect user to SSO interface.
///
pub async fn get_sso_redirect(
    body: Ruma<session::sso_login::v3::Request>,
) -> axum::response::Response {
    let server_name = services().globals.server_name().to_string();
    let metadata = services().oidc.get_metadata();
    let redirect_url = body.redirect_url.clone();

    let t = SsoTemplate {
        server_name,
        metadata,
        redirect_url,
    };

    match t.render() {
        Ok(body) => {
            let headers = [(
                http::header::CONTENT_TYPE,
                http::HeaderValue::from_static(SsoTemplate::MIME_TYPE),
            )];
            (headers, body).into_response()
        }
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "woops").into_response(),
    }
}

pub struct SsoResponse {
    pub inner: session::sso_login_with_provider::v3::Response,
    pub cookie: String,
}

impl OutgoingResponse for SsoResponse {
    fn try_into_http_response<T: Default + BufMut>(
        self,
    ) -> Result<http::Response<T>, IntoHttpError> {
        self.inner.try_into_http_response().map(|mut ok| {
            *ok.status_mut() = StatusCode::FOUND;

            match HeaderValue::from_str(self.cookie.as_str()) {
                Ok(value) => {
                    ok.headers_mut().insert(COOKIE, value);

                    Ok(ok)
                }
                Err(e) => Err(IntoHttpError::Header(e)),
            }
        })?
    }
}

/// # `GET  /_matrix/client/v3/login/sso/redirect/{idpId}`
///
/// Redirect user to SSO interface.
pub async fn get_sso_redirect_with_idp_id(
    body: Ruma<session::sso_login_with_provider::v3::Request>,
    // State(uiaa_session): State<Option<()>>,
) -> Result<SsoResponse> {
    // if services().oidc.get_all().len() == 1 {
    // }

    let Ok(provider) = services().oidc.get_provider(&body.idp_id).await else {
        return Err(Error::BadRequest(
            ErrorKind::NotFound,
            "Unknown identity provider",
        ));
    };

    let (location, cookie) = provider.handle_redirect(&body.redirect_url).await;
    let inner = session::sso_login_with_provider::v3::Response {
        location: location.to_string(),
    };

    let cookie = Cookie::build("openid-state", cookie)
        .path("/_conduit/client/oidc")
        .secure(false) //FIXME
        // .secure(true)
        .http_only(true)
        .same_site(SameSite::None)
        .max_age(time::Duration::seconds(COOKIE_STATE_EXPIRATION_SECS))
        .finish()
        .to_string();

    Ok(SsoResponse { inner, cookie })
    // Ok((axum::http::StatusCode::FOUND, [(LOCATION, &body.redirect_url)]).into_response())
}

pub async fn get_sso_return() {}

#[derive(Template)]
#[template(path = "sso_login_idp_picker.html", escape = "none")]
struct SsoTemplate {
    pub server_name: String,
    pub metadata: Vec<Metadata>,
    pub redirect_url: String,
}
