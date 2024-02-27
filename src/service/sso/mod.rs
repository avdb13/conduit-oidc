use std::sync::Arc;

use futures_util::future::{self};
use macaroon::{Macaroon, Verifier};
use openidconnect::{
    core::{CoreAuthenticationFlow, CoreClient, CoreGenderClaim, CoreProviderMetadata},
    reqwest::async_http_client,
    AccessTokenHash, AdditionalClaims, AuthUrl, AuthorizationCode, ClientId, ClientSecret,
    CsrfToken, IssuerUrl, Nonce, NonceVerifier, OAuth2TokenResponse, PkceCodeChallenge,
    RedirectUrl, Scope, SubjectIdentifier, TokenResponse, TokenUrl, UserInfoClaims, UserInfoUrl,
};
use ruma::api::client::{error::ErrorKind, session::get_login_types::v3::IdentityProvider};
use time::macros::format_description;

use crate::{
    config::{ClientConfig, DiscoveryConfig as Discovery, ProviderConfig},
    services, Config, Error,
};

pub const COOKIE_STATE_EXPIRATION_SECS: i64 = 60 * 60;

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

    pub async fn handle_redirect(&self, redirect_url: &str) -> (url::Url, String, String) {
        let client = self.client.clone();
        let scopes = self.scopes.iter().map(ToOwned::to_owned).map(Scope::new);

        let mut req = client
            .authorize_url(
                CoreAuthenticationFlow::Implicit(true),
                || CsrfToken::new_random_len(36),
                || Nonce::new_random_len(36),
            )
            .add_scopes(scopes);

        let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
        if let Some(true) = self.pkce {
            req = req.set_pkce_challenge(challenge);
        }

        let (url, csrf, nonce) = req.url();

        let cookie = self.generate_macaroon(
            self.inner.id.as_str(),
            csrf.secret(),
            nonce.secret(),
            redirect_url,
            self.pkce.map(|_| verifier.secret().as_str()),
        );

        (url, nonce.secret().to_owned(), cookie)
    }

    pub fn generate_macaroon(
        &self,
        idp_id: &str,
        state: &str,
        nonce: &str,
        redirect_url: &str,
        pkce: Option<&str>,
    ) -> String {
        let key = services().globals.macaroon.unwrap();

        let mut macaroon = Macaroon::create(None, &key, idp_id.into()).unwrap();
        let expires = (time::OffsetDateTime::now_utc()
            + time::Duration::seconds(COOKIE_STATE_EXPIRATION_SECS))
        .to_string();

        let idp_id = self.inner.id.as_str();

        for caveat in [
            format!("idp_id = {idp_id}"),
            format!("state = {state}"),
            format!("nonce = {nonce}"),
            format!("redirect_url = {redirect_url}"),
            format!("time < {expires}"),
        ] {
            macaroon.add_first_party_caveat(caveat.into());
        }

        if let Some(verifier) = pkce {
            macaroon.add_first_party_caveat(format!("verifier = {}", verifier).into());
        }

        macaroon.serialize(macaroon::Format::V2).unwrap()
    }

    pub fn verify_macaroon(cookie: &[u8], state: CsrfToken) -> Result<Macaroon, Error> {
        let mut verifier = Verifier::default();

        let macaroon = Macaroon::deserialize(cookie).map_err(|e| {
            Error::BadRequest(ErrorKind::BadJson, "Could not deserialize SSO macaroon")
        })?;

        verifier.satisfy_exact(format!("state = {}", state.secret()).into());

        // let verification = |s: &ByteString, id: &str| {
        //     s.0.starts_with(format!("{id} =").as_bytes()); // TODO
        // };

        verifier.satisfy_general(|s| s.0.starts_with(b"idp_id ="));
        verifier.satisfy_general(|s| s.0.starts_with(b"nonce ="));
        verifier.satisfy_general(|s| s.0.starts_with(b"redirect_url ="));

        verifier.satisfy_general(|s| {
            let format_desc = format_description!(
                "[year]-[month]-[day] [hour]:[minute]:[second] [offset_hour \
             sign:mandatory]:[offset_minute]:[offset_second]"
            );

            let now = time::OffsetDateTime::now_utc();

            time::OffsetDateTime::parse(std::str::from_utf8(&s.0).unwrap(), format_desc)
                .map(|expires| now < expires)
                .unwrap_or(false)
        });

        let key = services().globals.macaroon.unwrap();

        verifier
            .verify(&macaroon, &key, Default::default())
            .map_err(|e| {
                Error::BadRequest(ErrorKind::Unauthorized, "Macaroon verification failed")
            })?;

        Ok(macaroon)
    }

    pub async fn handle_callback<Claims: AdditionalClaims>(
        &self,
        code: AuthorizationCode,
        nonce: Nonce,
    ) -> Result<UserInfoClaims<Claims, CoreGenderClaim>, Error> {
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

        let Ok(req) = self.client.user_info(
            resp.access_token().to_owned(),
            self.subject_claim.clone().map(SubjectIdentifier::new),
        ) else {
            resp.extra_fields();
            panic!()
        };

        Ok(req.request_async(async_http_client).await.unwrap())
    }
}
