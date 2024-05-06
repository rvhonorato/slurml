use actix_web::HttpRequest;
use actix_web::{get, post, web, HttpResponse, Responder};
use sqlx::{Pool, Sqlite};

use crate::config::Config;
use crate::models::User;
use crate::responses;
use crate::utils;

#[get("/")]
pub async fn index() -> impl Responder {
    HttpResponse::Ok().json(responses::Message {
        message: "Ping!".to_string(),
    })
}

#[post("/login")]
pub async fn login(
    login_info: web::Json<responses::LoginRequest>,
    db: web::Data<Pool<Sqlite>>,
    config: web::Data<Config>,
) -> impl Responder {
    // Recieves a json with username and password
    let username = &login_info.username;
    let password = &login_info.password;

    let user_opt = match User::find_by_username(&db, username).await {
        Ok(user) => user,
        Err(_) => {
            return HttpResponse::InternalServerError().json(responses::ErrorResponse {
                error: "Failed to find user".to_string(),
            })
        }
    };

    let user = match user_opt {
        Some(user) => user,
        None => {
            return HttpResponse::Unauthorized().json(responses::ErrorResponse {
                error: "Invalid username or password".to_string(),
            })
        }
    };

    let password_hash = &user.password_hash;
    let password_verification = utils::verify_password(password_hash, password.as_bytes());
    if password_verification.is_err() || !password_verification.unwrap() {
        return HttpResponse::Unauthorized().json(responses::ErrorResponse {
            error: "Invalid username or password".to_string(),
        });
    }

    let token = match utils::generate_token(
        &user.id,
        utils::calculate_expiration(),
        config.jwt_key.as_bytes(),
    ) {
        Ok(token) => token,
        Err(_) => {
            return HttpResponse::InternalServerError().json(responses::ErrorResponse {
                error: "Failed to generate token".to_string(),
            })
        }
    };
    // }
    if let Err(e) = user.update_last_seen(&db).await {
        eprintln!("Failed to update last seen: {}", e);
    }

    HttpResponse::Ok().json(responses::Token { token })
}

#[post["/upload"]]
pub async fn upload(
    req: HttpRequest,
    config: web::Data<Config>,
    db: web::Data<Pool<Sqlite>>,
) -> impl Responder {
    match utils::validate_user(req, config.jwt_key.as_ref(), &db).await {
        Ok(valid) if !valid => {
            return HttpResponse::Unauthorized().json(responses::ErrorResponse {
                error: "Token is not valid".to_string(),
            });
        }
        Err(err) => {
            return HttpResponse::InternalServerError().json(responses::ErrorResponse {
                error: err.to_string(),
            });
        }
        _ => {}
    }

    HttpResponse::Ok().json(responses::Message {
        message: "Upload successful".to_string(),
    })
}
