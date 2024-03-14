use actix_web::HttpResponse;
use actix_web::{web, Responder};
use chrono::Duration;
use chrono::Utc;
use jsonwebtoken::EncodingKey;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, Header, TokenData, Validation};
use rand::{distributions::Alphanumeric, Rng};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::SqlitePool;
use std::env;

use crate::config::Config;

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    passphrase: String,
    exp: usize, // Expiration time
}

// pub fn generate_jwt(
//     passphrase: &str,
//     config: actix_web::web::Data<Config>,
// ) -> Result<HttpResponse, HttpResponse> {
//     if passphrase != config.secret_pass {
//         return Err(HttpResponse::Forbidden().json(json!({"error": "wrong password"})));
//     }

//     let expiration_time = Utc::now()
//         .checked_add_signed(Duration::hours(1))
//         .expect("valid timestamp")
//         .timestamp();

//     let claims = Claims {
//         passphrase: passphrase.to_owned(),
//         exp: expiration_time as usize,
//     };
//     let secret = &config.jwt_key;
//     let token = encode(
//         &Header::default(),
//         &claims,
//         &EncodingKey::from_secret(secret.as_ref()),
//     )
//     .map_err(|_| HttpResponse::InternalServerError())?;

//     Ok(HttpResponse::Ok().json(json!({ "token": token })))
// }

// fn validate_token(token: &str) -> Result<TokenData<Claims>, &'static str> {
//     let secret = env::var("JWTKEY").expect("JWTKEY must be set");
//     decode::<Claims>(
//         token,
//         &DecodingKey::from_secret(secret.as_ref()),
//         &Validation::new(Algorithm::HS256),
//     )
//     .map_err(|_| "Couldn't validate token")
// }

// async fn my_handler(pool: web::Data<SqlitePool>) -> impl Responder {
//     // Perform a query
//     let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM your_table")
//         .fetch_one(&**pool)
//         .await
//         .expect("Failed to execute query.");

//     format!("Number of rows in your_table: {}", row.0)
// }

pub fn generate_credentials(db_path: &str) {
    let username = generate_username();
    let password = generate_password(42);
    println!("Username: {}", username);
    println!("Password: {}", password);
}

fn generate_username() -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(10) // Username length
        .map(char::from)
        .collect()
}

fn generate_password(length: usize) -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(length)
        .map(char::from)
        .collect()
}
