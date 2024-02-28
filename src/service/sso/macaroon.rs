use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use openidconnect::{Nonce, PkceCodeVerifier, RedirectUrl, CsrfToken};
use serde::{Deserialize, Serialize};

use crate::Error;

#[derive(Serialize, Deserialize)]
pub struct Macaroon {
    pub idp_id: String,
    pub nonce: Nonce,
    pub csrf: CsrfToken,
    pub redirect_url: Option<RedirectUrl>,
    pub pkce_verifier: Option<PkceCodeVerifier>,
    pub time: i64,
}

impl Macaroon {
    pub fn encode(&self, macaroon: &str) -> Result<String, jsonwebtoken::errors::Error> {
        jsonwebtoken::encode(
            &Header::default(),
            self,
            &EncodingKey::from_secret(macaroon.as_bytes()),
        )
    }

    pub fn verify(token: &str, macaroon: &str) -> Result<Self, Error> {
        let decoded = jsonwebtoken::decode::<Self>(
            token,
            &DecodingKey::from_secret(macaroon.as_bytes()),
            &Validation::new(Algorithm::HS256),
        )
        .map_err(|_| {
            Error::BadRequest(
                ruma::api::client::error::ErrorKind::Unauthorized,
                "macaroon decoding",
            )
        })?;

        Err(Error::BadRequest(
            ruma::api::client::error::ErrorKind::Unauthorized,
            "macaroon invalid",
        ))
    }
}
