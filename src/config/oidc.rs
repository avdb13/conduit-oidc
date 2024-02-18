use serde::Deserialize;

#[derive(Clone, Debug, Deserialize)]
pub struct ProviderConfig  {
    pub id: String,
    pub name: String,
    pub icon: Option<String>,

    pub scopes: Vec<String>,
    pub issuer: url::Url,
    pub redirect_url: url::Url,

    // pub discover: bool, ???
    pub backchannel_logout: bool,

    pub client: ClientConfig,
    pub endpoint: EndpointConfig,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ClientConfig {
    pub id: String,
    pub secret: String,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct EndpointConfig {
    pub authorization: Option<url::Url>,
    pub token: Option<url::Url>,
    pub userinfo: Option<url::Url>,
}
