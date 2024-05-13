use sqlx::{Pool, Sqlite};

use crate::models::users::User;
use crate::responses;
use crate::utils;

pub async fn register_user(
    registration_info: responses::auth_responses::RegistrationRequest,
    db: &Pool<Sqlite>,
) -> Result<(User, String), sqlx::Error> {
    let password = utils::tools::generate_password(16);
    let password_hash = utils::tools::hash_password(password.as_bytes()).unwrap();

    let user = User {
        id: 0,
        username: registration_info.username,
        password_hash,
        last_seen: None,
        since: None,
        role: "user".to_string(),
    };

    let new_user = user.create(db).await.expect("Failed to create user");

    Ok((new_user, password))
}

pub async fn login_user(
    login_info: responses::auth_responses::LoginRequest,
    db: &Pool<Sqlite>,
    jwt_key: &[u8],
) -> Result<String, jsonwebtoken::errors::Error> {
    let username = &login_info.username;
    let password = &login_info.password;

    let user_opt = User::find_by_username(db, username).await;
    match user_opt {
        Ok(user) => {
            let password_hash = &user.password_hash;
            let password_verification =
                utils::tools::verify_password(password_hash, password.as_bytes());
            eprintln!("Password verification: {:?}", password_verification);
            if password_verification.is_err() || !password_verification.unwrap() {
                return Err(jsonwebtoken::errors::Error::from(
                    jsonwebtoken::errors::ErrorKind::InvalidToken,
                ));
            }

            match utils::tools::generate_token(
                &user.id,
                utils::tools::calculate_expiration(),
                jwt_key,
            ) {
                Ok(token) => {
                    if let Err(e) = user.update_last_seen(db).await {
                        eprintln!("Failed to update last seen: {}", e);
                    }

                    Ok(token)
                }
                Err(err) => {
                    eprintln!("Error generating token: {:?}", err);
                    Err(jsonwebtoken::errors::Error::from(
                        jsonwebtoken::errors::ErrorKind::InvalidToken,
                    ))
                }
            }
        }
        Err(_) => Err(jsonwebtoken::errors::Error::from(
            jsonwebtoken::errors::ErrorKind::InvalidToken,
        )),
    }

    // let user = match user_opt {
    //     Some(user) => user,
    //     None => {
    //         return Err(jsonwebtoken::errors::Error::from(
    //             jsonwebtoken::errors::ErrorKind::InvalidToken,
    //         ))
    //     }
    // };
}
