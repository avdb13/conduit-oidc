use std::sync::Arc;

use macaroon::{Macaroon, MacaroonKey};
use openidconnect::{
    core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata},
    reqwest::async_http_client,
    AuthUrl, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce, PkceCodeChallenge, RedirectUrl,
    Scope, TokenUrl, UserInfoUrl,
};
use tokio::sync::OnceCell;

use crate::{
    config::{DiscoveryConfig as Discovery, Metadata, ProviderConfig},
    services, Config, Error,
};

pub const COOKIE_STATE_EXPIRATION_SECS: i64 = 10 * 60;

#[derive(Clone)]
pub struct Client(Arc<CoreClient>);

#[derive(Clone)]
pub struct Provider {
    pub config: ProviderConfig,
    pub client: OnceCell<Client>,
}

impl Provider {
    pub fn new(config: ProviderConfig) -> Self {
        Self {
            config,
            client: OnceCell::new(),
        }
    }

    pub async fn handle_redirect(&self, redirect_url: &str) -> (url::Url, String) {
        let client = self
            .client
            .get_or_try_init(|| async { Client::new(self.config.clone()).await })
            .await
            .map(|c| c.0.clone())
            .unwrap();
        let scopes = self
            .config
            .scopes
            .iter()
            .map(ToOwned::to_owned)
            .map(Scope::new);

        let csrf = CsrfToken::new_random();
        let nonce = Nonce::new_random();
        let tmp = (csrf.clone(), nonce.clone());

        let mut req = client
            .authorize_url(
                CoreAuthenticationFlow::Implicit(true),
                move || csrf,
                move || nonce,
            )
            .add_scopes(scopes);

        let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
        if let Some(true) = self.config.pkce {
            req = req.set_pkce_challenge(challenge);
        }

        let (url, csrf, nonce) = req.url();

        let cookie = self.generate_macaroon(
            csrf.secret(),
            nonce.secret(),
            redirect_url,
            self.config.pkce.map(|_| verifier.secret().as_str()),
        );

        (url, cookie)
    }

    pub fn generate_macaroon(
        &self,
        state: &str,
        nonce: &str,
        redirect_url: &str,
        pkce: Option<&str>,
    ) -> String {
        let key = services()
            .globals
            .macaroon
            .unwrap_or_else(MacaroonKey::generate_random);

        let mut macaroon = Macaroon::create(None, &key, "oidc".into()).unwrap();
        let expires = chrono::Utc::now() + chrono::TimeDelta::seconds(COOKIE_STATE_EXPIRATION_SECS);

        let idp_id = self.config.metadata.id.as_str();

        macaroon.add_first_party_caveat(format!("idp_id = {idp_id}").into());
        macaroon.add_first_party_caveat(format!("state = {state}").into());
        macaroon.add_first_party_caveat(format!("nonce = {nonce}").into());
        macaroon.add_first_party_caveat(format!("redirect_url = {redirect_url}").into());
        macaroon.add_first_party_caveat(format!("time < {expires}").into());

        if let Some(verifier) = pkce {
            macaroon.add_first_party_caveat(format!("verifier = {}", verifier).into());
        }

        macaroon.serialize(macaroon::Format::V2).unwrap()
    }
}

pub struct Service {
    pub inner: Vec<Provider>,
}

impl Service {
    pub async fn build(config: &Config) -> Arc<Self> {
        Arc::new(Self {
            inner: config.oidc.clone().into_iter().map(Provider::new).collect(),
        })
    }

    pub async fn get_provider(&self, idp_id: impl AsRef<str>) -> Result<Provider, ()> {
        let Some(found) = self
            .inner
            .iter()
            .find(|p| p.config.metadata.id == idp_id.as_ref())
            .map(Clone::clone)
        else {
            return Err(());
        };

        // let client = found.client
        //     .get_or_try_init(|| async { Client::new(config.clone()).await })
        //     .await
        //     .unwrap();

        Ok(found)
    }

    pub fn get_all(&self) -> &[Provider] {
        self.inner.as_slice()
    }

    // TODO
    pub fn get_metadata(&self) -> Vec<Metadata> {
        self.inner
            .iter()
            .map(|p| p.config.metadata.clone())
            .collect()
    }

    // pub async fn generate_auth_url<'s, S>(&self, idp_id: String, scopes: S) -> ()
    // where
    //     S: Iterator<Item = &'s str>,
    // {

    //     // TODO: PKCE challenge
    //     if false {
    //         let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();

    //         // return auth_url.set_pkce_challenge(challenge).url()
    //     }

    //     // auth_url.url()
    // }

    // pub async fn exchange_auth_code(&self, auth_code: AuthorizationCode) {
    //     // -> Result<StandardTokenResponse, Error> {
    //     let provider = self.get_client("something").await.unwrap();

    //     let req = provider.exchange_code(auth_code);
    //     if false {
    //         // return req.set_pkce_verifier(pkce_verifier).request(http_client)?
    //     }

    //     let resp = req.request(http_client).unwrap();

    //     let id_token = resp.id_token().unwrap();

    //     let access_token = resp.access_token();

    //     let claims = id_token
    //         .claims(&provider.id_token_verifier(), &Nonce::new("".into()))
    //         .unwrap();

    //     if let Some(hash) = claims.access_token_hash() {
    //         &AccessTokenHash::from_token(access_token, &id_token.signing_alg().unwrap()).unwrap()
    //             == hash;
    //     }

    //     // need `UserInfo` endpoint
    //     // if let Some(subject) = config.subject_claim {
    //     if false {
    //         let req = provider
    //             .user_info(
    //                 access_token.clone(),
    //                 Some(SubjectIdentifier::new("id".to_owned())),
    //             )
    //             .unwrap();
    //         let ok: CoreUserInfoClaims = req.request(http_client).unwrap();
    //     }
    // }
}

impl Client {
    pub async fn new(config: ProviderConfig) -> Result<Self, Error> {
        let mut base_url = url::Url::try_from(
            services()
                .globals
                .well_known_client()
                .as_deref()
                .unwrap_or(services().globals.server_name().as_str()),
        )
        .expect("server_name should be a valid URL");

        base_url.set_path("_conduit/client/oidc/callback");
        let redirect_url = RedirectUrl::from_url(base_url);

        let client = match config.discovery {
            Discovery::Automatic => {
                let url = config.issuer.to_string();
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
                    ClientId::new(config.client.id),
                    config.client.secret.map(ClientSecret::new),
                )
            }
            Discovery::Manual(endpoints) => CoreClient::new(
                ClientId::new(config.client.id),
                config.client.secret.map(ClientSecret::new),
                IssuerUrl::from_url(config.issuer),
                AuthUrl::from_url(endpoints.auth),
                endpoints.token.map(TokenUrl::from_url),
                endpoints.userinfo.map(UserInfoUrl::from_url),
                Default::default(),
            )
            .set_redirect_uri(redirect_url),
        };

        Ok(Self(Arc::new(client)))
    }
}
