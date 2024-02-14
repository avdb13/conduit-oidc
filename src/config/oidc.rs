use serde::Deserialize;

#[derive(Clone, Debug, Deserialize)]
pub struct ProviderConfig  {
    id: String,
    name: String,
    icon: Option<String>,

    client: ClientConfig,
    scopes: Vec<String>,

    endpoint: EndpointConfig,

    discover_url: Option<url::Url>,
    backchannel_logout: bool,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ClientConfig {
    id: String,
    secret: String,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct EndpointConfig {
    authorization: Option<url::Url>,
    token: Option<url::Url>,
    userinfo: Option<url::Url>,
}
