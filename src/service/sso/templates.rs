use askama::Template;
use ruma::{
    api::client::search::search_events::v3::UserProfile, OwnedMxcUri, OwnedServerName, OwnedUserId,
};

use super::Provider;

#[derive(Template)]
#[template(path = "auth_confirmation.html", escape = "none")]
pub struct AuthConfirmation {
    description: String,
    redirect_url: url::Url,
    idp_name: String,
}

pub struct Metadata {
    id: String,
    name: Option<String>,
    icon: Option<OwnedMxcUri>,
}

impl From<&Provider> for Metadata {
    fn from(value: &Provider) -> Self {
        Self {
            id: value.config.id.clone(),
            name: value.config.name.clone(),
            icon: value.config.icon.clone(),
        }
    }
}

#[derive(Template)]
#[template(path = "auth_failure.html", escape = "none")]
pub struct AuthFailure {
    server_name: OwnedServerName,
}
#[derive(Template)]
#[template(path = "auth_success.html", escape = "none")]
pub struct AuthSuccess {}

#[derive(Template)]
#[template(path = "deactivated.html", escape = "none")]
pub struct Deactivated {}

#[derive(Template)]
#[template(path = "idp_picker.html", escape = "none")]
pub struct IdpPicker {
    pub server_name: String,
    pub metadata: Vec<Metadata>,
    pub redirect_url: String,
}

#[derive(Template)]
#[template(path = "registration.html", escape = "none")]
pub struct Registration {
    pub server_name: OwnedServerName,
    pub idp: Metadata,
    pub user: Attributes,
}

pub struct Attributes {
    pub localpart: String,
    pub displayname: Option<String>,
    pub avatar_url: Option<String>,
    pub emails: Vec<String>,
}

#[derive(Template)]
#[template(path = "redirect_confirm.html", escape = "none")]
pub struct RedirectConfirm {
    pub user_id: OwnedUserId,
    pub user_profile: UserProfile,
    pub display_url: url::Url,
    pub redirect_url: url::Url,
}
