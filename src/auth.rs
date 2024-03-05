use actix_web::HttpResponse;
use chrono::Duration;
use chrono::Utc;
use jsonwebtoken::EncodingKey;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, Header, TokenData, Validation};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::env;

use crate::config::Config;

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    passphrase: String,
    exp: usize, // Expiration time
}

pub fn generate_jwt(
    passphrase: &str,
    config: actix_web::web::Data<Config>,
) -> Result<HttpResponse, HttpResponse> {
    if passphrase != config.secret_pass {
        return Err(HttpResponse::Forbidden().json(json!({"error": "wrong password"})));
    }

    let expiration_time = Utc::now()
        .checked_add_signed(Duration::hours(1))
        .expect("valid timestamp")
        .timestamp();

    let claims = Claims {
        passphrase: passphrase.to_owned(),
        exp: expiration_time as usize,
    };
    let secret = &config.jwt_key;
    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_ref()),
    )
    .map_err(|_| HttpResponse::InternalServerError())?;

    Ok(HttpResponse::Ok().json(json!({"token": token})))
}

fn validate_token(token: &str) -> Result<TokenData<Claims>, &'static str> {
    let secret = env::var("JWTKEY").expect("JWTKEY must be set");
    decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_ref()),
        &Validation::new(Algorithm::HS256),
    )
    .map_err(|_| "Couldn't validate token")
}
