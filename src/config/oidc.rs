use ruma::{serde::AsRefStr, OwnedMxcUri};
use serde::Deserialize;

pub type OidcConfig = Vec<ProviderConfig>;

#[derive(Clone, Debug, Deserialize)]
pub struct ProviderConfig  {
    // Must be unique, used to distinguish OPs
    pub id: String,
    pub name: Option<String>,
    pub icon: Option<OwnedMxcUri>,

    // Base URL of the OpenID Provider
    pub issuer: url::Url,
    // Always contains at least "openid"
    // "profile", "email" and "name" are useful to suggest an MXID
    pub scopes: Vec<String>,
    // PKCE provides dynamic client secrets
    // Should be enabled when `ClientAuthMethod` is `None`
    pub pkce: Option<bool>,

    // Allow existent accounts to login with OIDC
    pub allow_existing_users: bool,
    // Invalidate user sessions when the OP session expires
    pub backchannel_logout: bool,
    // Should be enabled when the authorization response does not contain userinfo
    pub userinfo_override: bool,
    // Should be enabled when the authorization response does not contain a unique subject claim
    subject_claim: Option<String>,

    pub client: ClientConfig,
    pub metadata: MetadataConfig,
}

#[derive(Clone, Debug, Deserialize)]
pub enum MetadataConfig {
    // Should be used for OPs supporting the OIDC Discovery endpoint
    Discoverable,
    Manual {
        authorization: Option<url::Url>,
        token: Option<url::Url>,
        userinfo: Option<url::Url>,
        jwk: Option<url::Url>,
    },
}

#[derive(Clone, Debug, Deserialize, AsRefStr)]
pub enum ClientAuthMethod  {
    None,
    // Provide the client combo in the Authorization header
    Basic,
    // Provide the client combo as in the POST request body
    Post,
    // Provide a JWT signed with client secret
    SharedJwt,
    // Provide a JWT signed with our own keypair (OP needs to know the public key)
    PrivateJwt,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ClientConfig {
    pub id: String,
    // Mandatory for the following `ClientAuthMethod`s:
    // [`Basic`,`Post`,`SharedJwt`]
    pub secret: Option<String>,
}
