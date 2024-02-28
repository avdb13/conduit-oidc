use std::sync::Arc;

mod session;

use futures_util::future::{self};
use openidconnect::{
    core::{
        CoreAuthenticationFlow, CoreClient, CoreGenderClaim, CoreIdTokenClaims,
        CoreProviderMetadata, CoreUserInfoClaims,
    },
    reqwest::async_http_client,
    AccessTokenHash, AdditionalClaims, AuthUrl, AuthorizationCode, ClientId, ClientSecret,
    CsrfToken, IssuerUrl, Nonce, NonceVerifier, OAuth2TokenResponse, PkceCodeChallenge,
    PkceCodeVerifier, RedirectUrl, Scope, SubjectIdentifier, TokenResponse, TokenUrl,
    UserInfoClaims, UserInfoUrl,
};
use ruma::api::client::{error::ErrorKind, session::get_login_types::v3::IdentityProvider};
use time::{macros::format_description, OffsetDateTime};

use crate::{
    config::{ClientConfig, DiscoveryConfig as Discovery, ProviderConfig},
    services, Config, Error,
};

use self::macaroon::Macaroon;

pub const COOKIE_STATE_EXPIRATION_SECS: i64 = 60 * 60;

pub mod macaroon;
pub mod templates;

pub struct Service {
    pub inner: Vec<Provider>,
}

impl Service {
    pub async fn build(config: &Config) -> Arc<Self> {
        Arc::new(Self {
            inner: future::join_all(config.sso.clone().into_iter().map(Provider::new)).await,
        })
    }

    pub fn find_one(&self, idp_id: impl AsRef<str>) -> Result<Provider, Error> {
        match self.inner.iter().find(|p| p.inner.id == idp_id.as_ref()) {
            Some(provider) => Ok(provider.to_owned()),
            None => Err(Error::BadRequest(
                ErrorKind::NotFound,
                "unknown identity provider",
            )),
        }
    }

    pub fn get_all(&self) -> &[Provider] {
        self.inner.as_slice()
    }
}

#[derive(Clone)]
pub struct Provider {
    pub inner: IdentityProvider,
    pub client: Arc<CoreClient>,
    pub scopes: Vec<String>,
    pub pkce: Option<bool>,
    pub subject_claim: Option<String>,
}

impl Provider {
    pub async fn new(config: ProviderConfig) -> Self {
        let inner = IdentityProvider {
            id: config.id.clone(),
            name: config.name.unwrap_or(config.id),
            icon: config.icon,
            brand: None,
        };

        Self {
            inner,
            client: Provider::create_client(config.discovery, config.issuer, config.client)
                .await
                .unwrap(),
            scopes: config.scopes,
            pkce: config.pkce,
            subject_claim: config.subject_claim,
        }
    }

    async fn create_client(
        discovery: Discovery,
        issuer: url::Url,
        config: ClientConfig,
    ) -> Result<Arc<CoreClient>, Error> {
        let mut base_url = url::Url::try_from(
            services()
                .globals
                .well_known_client()
                .as_deref()
                .unwrap_or(services().globals.server_name().as_str()),
        )
        .expect("server_name should be a valid URL");

        base_url.set_path("_conduit/config/sso/callback");
        let redirect_url = RedirectUrl::from_url(base_url);

        let config = match discovery {
            Discovery::Automatic => {
                let url = issuer.to_string();
                let url = url.strip_suffix("/").unwrap();

                let discovery = CoreProviderMetadata::discover_async(
                    // https://github.com/ramosbugs/openidconnect-rs/issues/77
                    IssuerUrl::new(url.to_owned()).unwrap(),
                    async_http_client,
                )
                .await
                .unwrap();
                // .map_err(|e| Error::BadConfig(&e.to_string()))?;

                CoreClient::from_provider_metadata(
                    discovery,
                    ClientId::new(config.id),
                    config.secret.map(ClientSecret::new),
                )
            }
            Discovery::Manual(endpoints) => CoreClient::new(
                ClientId::new(config.id),
                config.secret.map(ClientSecret::new),
                IssuerUrl::from_url(issuer),
                AuthUrl::from_url(endpoints.auth),
                endpoints.token.map(TokenUrl::from_url),
                endpoints.userinfo.map(UserInfoUrl::from_url),
                Default::default(),
            )
            .set_redirect_uri(redirect_url),
        };

        Ok(Arc::new(config))
    }

    pub async fn handle_redirect(&self, redirect_url: &RedirectUrl) -> (url::Url, String, String) {
        let client = self.client.clone();
        let scopes = self.scopes.iter().map(ToOwned::to_owned).map(Scope::new);

        let mut req = client
            .authorize_url(
                CoreAuthenticationFlow::Implicit(true),
                || CsrfToken::new_random_len(48),
                || Nonce::new_random_len(48),
            )
            .add_scopes(scopes);

        let pkce_verifier = match self.pkce {
            Some(true) => {
                let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
                req = req.set_pkce_challenge(challenge);

                Some(verifier)
            }
            _ => None,
        };

        let (url, csrf, nonce) = req.url();

        let key = services()
            .globals
            .macaroon_key
            .as_deref()
            .expect("macaroon key")
            .to_owned();
        let cookie = Macaroon {
            idp_id: self.inner.id.clone(),
            csrf,
            nonce: nonce.clone(),
            time: OffsetDateTime::now_utc().unix_timestamp(),
            redirect_url: Some(redirect_url.clone()),
            pkce_verifier,
        };
        let cookie = cookie.encode(&key).expect("bad key");

        (url, nonce.secret().to_owned(), cookie)
    }

    pub async fn handle_callback<Claims: AdditionalClaims>(
        &self,
        code: AuthorizationCode,
        nonce: Nonce,
    ) -> Result<(), Error> {
        let resp = self
            .client
            .exchange_code(code)
            .request_async(async_http_client)
            .await
            .unwrap();

        let id_token = resp.id_token().unwrap();
        let claims = id_token
            .claims(&self.client.id_token_verifier(), &nonce)
            .unwrap();

        if let Some(expected) = claims.access_token_hash() {
            let found =
                AccessTokenHash::from_token(resp.access_token(), &id_token.signing_alg().unwrap())
                    .unwrap();

            if &found != expected {
                panic!()
            }
        }

        // match self.client.user_info(
        //     resp.access_token().to_owned(),
        //     self.subject_claim.clone().map(SubjectIdentifier::new),
        // ).map(|req| req.request_async(async_http_client)) {
        //     Err(e) => Ok(claims),
        //     Ok(req) => req.await,
        // }
    }
}
