use actix_web::HttpRequest;
use actix_web::{get, post, web, HttpResponse, Responder};
use sqlx::{Pool, Sqlite};

use crate::models::users::User;
use crate::responses;
use crate::services;
use crate::utils;

#[get("/")]
pub async fn index() -> impl Responder {
    HttpResponse::Ok().json(responses::auth_responses::Message {
        message: "Ping!".to_string(),
    })
}

#[post("/login")]
pub async fn login(
    login_info: web::Json<responses::auth_responses::LoginRequest>,
    db: web::Data<Pool<Sqlite>>,
    config: web::Data<utils::config::Config>,
) -> impl Responder {
    match services::auth_service::login_user(
        login_info.into_inner(),
        &db,
        config.jwt_key.as_bytes(),
    )
    .await
    {
        Ok(token) => HttpResponse::Ok().json(responses::auth_responses::Token { token }),
        Err(err) => {
            HttpResponse::InternalServerError().json(responses::auth_responses::ErrorResponse {
                error: err.to_string(),
            })
        }
    }
}

#[post("/inspect")]
pub async fn inspect(
    req: HttpRequest,
    config: web::Data<utils::config::Config>,
    db: web::Data<Pool<Sqlite>>,
) -> impl Responder {
    match utils::tools::validate_user(req, config.jwt_key.as_ref(), &db).await {
        Ok(user) => {
            // Obfuscate the password hash
            let user = User {
                password_hash: "********".to_string(),
                ..user
            };

            HttpResponse::Ok().json(user)
        }
        Err(err) => {
            HttpResponse::InternalServerError().json(responses::auth_responses::ErrorResponse {
                error: err.to_string(),
            })
        }
    }
}

#[post("/register")]
pub async fn register(
    registration_info: web::Json<responses::auth_responses::RegistrationRequest>,
    req: HttpRequest,
    db: web::Data<Pool<Sqlite>>,
    config: web::Data<utils::config::Config>,
) -> impl Responder {
    // Only admins can register, check if the user is an admin
    match utils::tools::validate_user(req, config.jwt_key.as_ref(), &db).await {
        Ok(user) => {
            if !user.is_admin() {
                return HttpResponse::Unauthorized().json(
                    responses::auth_responses::ErrorResponse {
                        error: "only Admins can add users".to_string(),
                    },
                );
            }
        }
        Err(_) => {
            return HttpResponse::InternalServerError().json(
                responses::auth_responses::ErrorResponse {
                    error: "Something went wrong".to_string(),
                },
            )
        }
    };

    let (user, password) =
        match services::auth_service::register_user(registration_info.into_inner(), &db).await {
            Ok(user_password_tuple) => user_password_tuple,
            Err(_) => {
                return HttpResponse::InternalServerError().json(
                    responses::auth_responses::ErrorResponse {
                        error: "Failed to create user".to_string(),
                    },
                )
            }
        };

    HttpResponse::Ok().json(responses::auth_responses::LoginRequest {
        username: user.username,
        password,
    })
}
