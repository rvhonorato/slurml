use actix_web::HttpRequest;
use actix_web::{get, post, web, HttpResponse, Responder};
use sqlx::{Pool, Sqlite};

use crate::auth_service;
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
    match auth_service::login_user(login_info.into_inner(), &db, config.jwt_key.as_bytes()).await {
        Ok(token) => HttpResponse::Ok().json(responses::Token { token }),
        Err(err) => HttpResponse::InternalServerError().json(responses::ErrorResponse {
            error: err.to_string(),
        }),
    }
}

#[post("/inspect")]
pub async fn inspect(
    req: HttpRequest,
    config: web::Data<Config>,
    db: web::Data<Pool<Sqlite>>,
) -> impl Responder {
    match utils::validate_user(req, config.jwt_key.as_ref(), &db).await {
        Ok(user) => {
            // Obfuscate the password hash
            let user = User {
                password_hash: "********".to_string(),
                ..user
            };

            HttpResponse::Ok().json(user)
        }
        Err(err) => HttpResponse::InternalServerError().json(responses::ErrorResponse {
            error: err.to_string(),
        }),
    }
}

#[post("/register")]
pub async fn register(
    registration_info: web::Json<responses::RegistrationRequest>,
    req: HttpRequest,
    db: web::Data<Pool<Sqlite>>,
    config: web::Data<Config>,
) -> impl Responder {
    // Only admins can register, check if the user is an admin
    match utils::validate_user(req, config.jwt_key.as_ref(), &db).await {
        Ok(user) => {
            if !user.is_admin() {
                return HttpResponse::Unauthorized().json(responses::ErrorResponse {
                    error: "only Admins can add users".to_string(),
                });
            }
        }
        Err(_) => {
            return HttpResponse::InternalServerError().json(responses::ErrorResponse {
                error: "Something went wrong".to_string(),
            })
        }
    };

    let (user, password) =
        match auth_service::register_user(registration_info.into_inner(), &db).await {
            Ok(user_password_tuple) => user_password_tuple,
            Err(_) => {
                return HttpResponse::InternalServerError().json(responses::ErrorResponse {
                    error: "Failed to create user".to_string(),
                })
            }
        };

    HttpResponse::Ok().json(responses::LoginRequest {
        username: user.username,
        password,
    })
}
