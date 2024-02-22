use super::{DEVICE_ID_LENGTH, TOKEN_LENGTH};
use crate::{services, utils, Error, Result, Ruma};
use base64::{alphabet, engine, engine::general_purpose};
// use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use macaroon::Verifier;
use ruma::{
    api::client::{
        error::ErrorKind,
        session::{get_login_types, login, logout, logout_all},
        uiaa::UserIdentifier,
    },
    events::GlobalAccountDataEventType,
    push, UserId,
};
use serde::Deserialize;
use tracing::{debug, error, info, warn};

#[derive(Debug, Deserialize)]
struct Claims {
    sub: String,
    //exp: usize,
}

#[tracing::instrument]
fn verifier_callback(v: &macaroon::ByteString) -> bool {
    use std::num::ParseIntError;

    let result: Result<bool, String> = (|| {
        if v.0.starts_with(b"time < ") {
            let v2 = std::str::from_utf8(&v.0).map_err(|e| e.to_string())?;
            let v3 = v2.trim_start_matches("time < ");
            let v4: i64 = v3.parse().map_err(|e: ParseIntError| e.to_string())?;
            let now = chrono::Utc::now().timestamp();
            if now < v4 {
                debug!("macaroon is not expired yet");
                Ok(true)
            } else {
                debug!(
                    "macaroon expired, v4={} , now={}, v4-now={}",
                    v4,
                    now,
                    v4 - now
                );
                Ok(false)
            }
        } else {
            Ok(false)
        }
    })();

    match result {
        Ok(r) => r,
        Err(e) => {
            error!("verifier_callback: {:?}", e);
            false
        }
    }
}

#[test]
fn test_verifier_callback() {
    use macaroon::ByteString;

    let now = chrono::Utc::now().timestamp();

    assert!(verifier_callback(&ByteString(
        format!("time < {}", now + 10).as_bytes().to_vec()
    )));
    assert!(!verifier_callback(&ByteString(
        format!("time < {}", now - 10).as_bytes().to_vec()
    )));
}

/// # `GET /_matrix/client/r0/login`
///
/// Get the supported login types of this server. One of these should be used as the `type` field
/// when logging in.
pub async fn get_login_types_route(
    _body: Ruma<get_login_types::v3::Request>,
) -> Result<get_login_types::v3::Response> {
    let identity_providers = services()
        .oidc
        .get_metadata()
        .clone()
        .into_iter()
        .map(Into::into)
        .collect();

    Ok(get_login_types::v3::Response::new(vec![
        get_login_types::v3::LoginType::Password(Default::default()),
        get_login_types::v3::LoginType::ApplicationService(Default::default()),
        get_login_types::v3::LoginType::Sso(get_login_types::v3::SsoLoginType {
            identity_providers,
        }),
    ]))
}

/// # `POST /_matrix/client/r0/login`
///
/// Authenticates the user and returns an access token it can use in subsequent requests.
///
/// - The user needs to authenticate using their password (or if enabled using a json web token)
/// - If `device_id` is known: invalidates old access token of that device
/// - If `device_id` is unknown: creates a new device
/// - Returns access token that is associated with the user and device
///
/// Note: You can use [`GET /_matrix/client/r0/login`](fn.get_supported_versions_route.html) to see
/// supported login types.
pub async fn login_route(body: Ruma<login::v3::Request>) -> Result<login::v3::Response> {
    // To allow deprecated login methods
    #![allow(deprecated)]
    // Validate login method
    // TODO: Other login methods
    let user_id = match &body.login_info {
        login::v3::LoginInfo::Password(login::v3::Password {
            identifier,
            password,
            user,
            address: _,
            medium: _,
        }) => {
            let user_id = if let Some(UserIdentifier::UserIdOrLocalpart(user_id)) = identifier {
                UserId::parse_with_server_name(
                    user_id.to_lowercase(),
                    services().globals.server_name(),
                )
            } else if let Some(user) = user {
                UserId::parse(user)
            } else {
                warn!("Bad login type: {:?}", &body.login_info);
                return Err(Error::BadRequest(ErrorKind::Forbidden, "Bad login type."));
            }
            .map_err(|_| Error::BadRequest(ErrorKind::InvalidUsername, "Username is invalid."))?;

            let hash = services()
                .users
                .password_hash(&user_id)?
                .ok_or(Error::BadRequest(
                    ErrorKind::Forbidden,
                    "Wrong username or password.",
                ))?;

            if hash.is_empty() {
                return Err(Error::BadRequest(
                    ErrorKind::UserDeactivated,
                    "The user has been deactivated",
                ));
            }

            let hash_matches = argon2::verify_encoded(&hash, password.as_bytes()).unwrap_or(false);

            if !hash_matches {
                return Err(Error::BadRequest(
                    ErrorKind::Forbidden,
                    "Wrong username or password.",
                ));
            }

            user_id
        }
        login::v3::LoginInfo::Token(login::v3::Token { token }) => {
            const CUSTOM_ENGINE: engine::GeneralPurpose =
                engine::GeneralPurpose::new(&alphabet::URL_SAFE, general_purpose::NO_PAD);

            if let Some(jwt_decoding_key) = services().globals.jwt_decoding_key() {
                let token = jsonwebtoken::decode::<Claims>(
                    token,
                    jwt_decoding_key,
                    &jsonwebtoken::Validation::default(),
                )
                .map_err(|_| Error::BadRequest(ErrorKind::InvalidUsername, "Token is invalid."))?;
                let username = token.claims.sub.to_lowercase();
                UserId::parse_with_server_name(username, services().globals.server_name()).map_err(
                    |_| Error::BadRequest(ErrorKind::InvalidUsername, "Username is invalid."),
                )?
            } else if macaroon::Macaroon::deserialize(&CUSTOM_ENGINE.decode(token).unwrap()) // TODO
                .is_ok()
            {
                println!("TOKEN! {}", token);

                let macaroon =
                    macaroon::Macaroon::deserialize(&CUSTOM_ENGINE.decode(token).unwrap()).unwrap();

                let v1 = macaroon.identifier();
                let user_id = std::str::from_utf8(&v1.0).unwrap();
                println!("identifier: {}", user_id);

                println!("location: {:?}", macaroon.location());
                println!("sig: {:?}", macaroon.signature());

                let mut verifier = Verifier::default();
                verifier.satisfy_general(verifier_callback);

                // let openid_client = &services().globals.openid_client;
                // let (key, _client) = openid_client.as_ref().unwrap();

                // match verifier.verify(&macaroon, &key, Default::default()) {
                //     Ok(()) => println!("Macaroon verified!"),
                //     Err(error) => println!("Error validating macaroon: {:?}", error),
                // }

                let user_id =
                    UserId::parse_with_server_name(user_id, services().globals.server_name())
                        .map_err(|_| {
                            Error::BadRequest(ErrorKind::InvalidUsername, "Username is invalid.")
                        })?;

                println!("user_id: {}", user_id);

                if !services().users.exists(&user_id)? {
                    let random_password = crate::utils::random_string(TOKEN_LENGTH);
                    services().users.create(&user_id, Some(&random_password))?;
                    services().account_data.update(
                        None,
                        &user_id,
                        GlobalAccountDataEventType::PushRules.to_string().into(),
                        &serde_json::to_value(ruma::events::push_rules::PushRulesEvent {
                            content: ruma::events::push_rules::PushRulesEventContent {
                                global: push::Ruleset::server_default(&user_id),
                            },
                        })
                        .expect("to json always works"),
                    )?;
                }

                user_id
            } else {
                return Err(Error::BadRequest(
                    ErrorKind::Unknown,
                    "Token login is not supported (server has no jwt decoding key).",
                ));
            }
        }
        login::v3::LoginInfo::ApplicationService(login::v3::ApplicationService {
            identifier,
            user,
        }) => {
            if !body.from_appservice {
                return Err(Error::BadRequest(
                    ErrorKind::Forbidden,
                    "Forbidden login type.",
                ));
            };
            if let Some(UserIdentifier::UserIdOrLocalpart(user_id)) = identifier {
                UserId::parse_with_server_name(
                    user_id.to_lowercase(),
                    services().globals.server_name(),
                )
            } else if let Some(user) = user {
                UserId::parse(user)
            } else {
                warn!("Bad login type: {:?}", &body.login_info);
                return Err(Error::BadRequest(ErrorKind::Forbidden, "Bad login type."));
            }
            .map_err(|_| Error::BadRequest(ErrorKind::InvalidUsername, "Username is invalid."))?
        }
        _ => {
            warn!("Unsupported or unknown login type: {:?}", &body.login_info);
            return Err(Error::BadRequest(
                ErrorKind::Unknown,
                "Unsupported login type.",
            ));
        }
    };

    // Generate new device id if the user didn't specify one
    let device_id = body
        .device_id
        .clone()
        .unwrap_or_else(|| utils::random_string(DEVICE_ID_LENGTH).into());

    // Generate a new token for the device
    let token = utils::random_string(TOKEN_LENGTH);

    // Determine if device_id was provided and exists in the db for this user
    let device_exists = body.device_id.as_ref().map_or(false, |device_id| {
        services()
            .users
            .all_device_ids(&user_id)
            .any(|x| x.as_ref().map_or(false, |v| v == device_id))
    });

    if device_exists {
        services().users.set_token(&user_id, &device_id, &token)?;
    } else {
        services().users.create_device(
            &user_id,
            &device_id,
            &token,
            body.initial_device_display_name.clone(),
        )?;
    }

    info!("{} logged in", user_id);

    // Homeservers are still required to send the `home_server` field
    #[allow(deprecated)]
    Ok(login::v3::Response {
        user_id,
        access_token: token,
        home_server: Some(services().globals.server_name().to_owned()),
        device_id,
        well_known: None,
        refresh_token: None,
        expires_in: None,
    })
}

/// # `POST /_matrix/client/r0/logout`
///
/// Log out the current device.
///
/// - Invalidates access token
/// - Deletes device metadata (device id, device display name, last seen ip, last seen ts)
/// - Forgets to-device events
/// - Triggers device list updates
pub async fn logout_route(body: Ruma<logout::v3::Request>) -> Result<logout::v3::Response> {
    let sender_user = body.sender_user.as_ref().expect("user is authenticated");
    let sender_device = body.sender_device.as_ref().expect("user is authenticated");

    services().users.remove_device(sender_user, sender_device)?;

    Ok(logout::v3::Response::new())
}

/// # `POST /_matrix/client/r0/logout/all`
///
/// Log out all devices of this user.
///
/// - Invalidates all access tokens
/// - Deletes all device metadata (device id, device display name, last seen ip, last seen ts)
/// - Forgets all to-device events
/// - Triggers device list updates
///
/// Note: This is equivalent to calling [`GET /_matrix/client/r0/logout`](fn.logout_route.html)
/// from each device of this user.
pub async fn logout_all_route(
    body: Ruma<logout_all::v3::Request>,
) -> Result<logout_all::v3::Response> {
    let sender_user = body.sender_user.as_ref().expect("user is authenticated");

    for device_id in services().users.all_device_ids(sender_user).flatten() {
        services().users.remove_device(sender_user, &device_id)?;
    }

    Ok(logout_all::v3::Response::new())
}
