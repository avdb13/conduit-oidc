use askama::Template;
use ruma::{OwnedUserId, api::client::search::search_events::v3::UserProfile, OwnedServerName};

use crate::config::Metadata;

#[derive(Template)]
#[template(path = "auth_confirmation.html", escape = "none")]
pub struct AuthConfirmationTemplate {
    description: String,
    redirect_url: url::Url,
    idp_name: String,
}

#[derive(Template)]
#[template(path = "auth_failure.html", escape = "none")]
pub struct AuthFailureTemplate {
    server_name: OwnedServerName,
}
#[derive(Template)]
#[template(path = "auth_success.html", escape = "none")]
pub struct AuthSuccessTemplate {}

#[derive(Template)]
#[template(path = "deactivated.html", escape = "none")]
pub struct DeactivatedTemplate {}

#[derive(Template)]
#[template(path = "idp_picker.html", escape = "none")]
pub struct IdpPickerTemplate {
    pub server_name: String,
    pub metadata: Vec<Metadata>,
    pub redirect_url: String,
}

#[derive(Template)]
#[template(path = "registration.html", escape = "none")]
pub struct RegistrationTemplate {
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
pub struct RedirectConfirmTemplate  {
    pub user_id: OwnedUserId,
    pub user_profile: UserProfile,
    pub display_url: url::Url,
    pub redirect_url: url::Url,
}
