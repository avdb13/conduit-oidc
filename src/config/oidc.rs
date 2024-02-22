use openidconnect::JsonWebKeyId;
use ruma::{
    api::client::session::get_login_types::v3::{IdentityProvider, IdentityProviderBrand},
    OwnedMxcUri,
};
use serde::Deserialize;

pub type OidcConfig = Vec<ProviderConfig>;

#[derive(Clone, Debug, Deserialize)]
pub struct Metadata {
    // Must be unique, used to distinguish OPs
    #[serde(rename = "idp_id")]
    pub id: String,

    #[serde(rename = "idp_name")]
    pub name: Option<String>,

    #[serde(rename = "idp_icon")]
    pub icon: Option<OwnedMxcUri>,
}

impl Into<IdentityProvider> for Metadata {
    fn into(self) -> IdentityProvider {
        let brand = match IdentityProviderBrand::from(self.id.clone()) {
            IdentityProviderBrand::_Custom(_) => None,
            brand => Some(brand),
        };

        IdentityProvider {
            id: self.id.clone(),
            name: self.name.unwrap_or(self.id),
            icon: self.icon,
            brand,
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct ProviderConfig {
    // Information retrieved while creating the OpenID Application
    pub client: ClientConfig,

    // Information for displaying the OpenID Provider
    #[serde(flatten)]
    pub metadata: Metadata,

    // Foo
    // #[serde(deserialize_with = "crate::utils::deserialize_from_str")]
    pub issuer: url::Url,

    // Always contains "openid" by default
    // "profile", "email" and "name" are useful to suggest an MXID
    pub scopes: Vec<String>,

    // PKCE provides dynamic client secrets
    // Should be enabled when `ClientAuthMethod` is `None`
    pub pkce: Option<bool>,

    // Should be enabled when the authorization response does not contain a unique subject claim
    pub subject_claim: Option<String>,

    // Allow existent accounts to login with OIDC
    #[serde(default)]
    pub allow_existing_users: bool,

    // Invalidate user sessions when the OP session expires
    #[serde(default)]
    pub backchannel_logout: bool,

    // Should be enabled when the authorization response does not contain userinfo
    #[serde(default)]
    pub userinfo_override: bool,

    #[serde(default)]
    pub discovery: DiscoveryConfig,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ClientConfig {
    pub id: String,
    // Mandatory for the following `ClientAuthMethod`s:
    // [`Basic`,`Post`,`SharedJwt`]
    pub secret: Option<String>,

    pub auth_method: AuthMethod,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Endpoints {
    pub auth: url::Url,
    pub token: Option<url::Url>,
    pub userinfo: Option<url::Url>,
    pub jwk: Option<url::Url>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DiscoveryConfig {
    // Should be used for OPs supporting the OIDC Discovery endpoint
    #[default]
    Automatic,
    Manual(Endpoints),
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthMethod {
    None,
    // Provide the client combo in the Authorization header
    Basic,
    // Provide the client combo as in the POST request body
    Post,
    // Provide a JWT signed with client secret
    SharedJwt,
    // Provide a JWT signed with a private key (OP needs to know the public key)
    PrivateJwt,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Algorithm {
    Rsa,
    EdDsa,
}

#[derive(Clone, Debug, Deserialize)]
pub struct PrivateSigningKey {
    pub kind: Algorithm,
    pub path: String,
    pub kid: Option<JsonWebKeyId>,
}
