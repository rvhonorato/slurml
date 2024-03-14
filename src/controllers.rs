use crate::auth;
use actix_web::{get, post, web, HttpResponse, Responder};
use serde::{Deserialize, Serialize};
use sqlx::{Pool, Sqlite};

use crate::config::Config;

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenRequest {
    pub username: String,
    pub password: String,
}

#[post("/token")]
pub async fn token(
    req: web::Json<TokenRequest>,
    config: web::Data<Config>,
    db: web::Data<Pool<Sqlite>>,
) -> impl Responder {
    let token = auth::generate_token(&req.username, &req.password, &config.jwt_key, &db).await;

    match token {
        Ok(token) => HttpResponse::Ok().body(token.to_string()),
        Err(_) => HttpResponse::BadRequest().body("Failed to generate token".to_string()),
    }
}

#[get("/")]
pub async fn index() -> impl Responder {
    HttpResponse::Ok().body("Hello, world!")
}
