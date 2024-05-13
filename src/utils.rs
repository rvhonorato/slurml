use actix_web::http::header;
use actix_web::HttpRequest;
use rand::{distributions::Alphanumeric, Rng};
use sqlx::{Pool, Sqlite};

use std::time::{SystemTime, UNIX_EPOCH};

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Argon2, PasswordHash, PasswordVerifier,
};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

use crate::models::User;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    sub: i32, // Subject (user id)
    exp: u64, // Expiration time
}

pub fn generate_password(n: usize) -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(n)
        .map(char::from)
        .collect()
}

// Helper function to calculate expiration for token
pub fn calculate_expiration() -> u64 {
    let now = SystemTime::now();
    let since_the_epoch = now.duration_since(UNIX_EPOCH).unwrap_or_default();
    since_the_epoch.as_secs() + 31_536_000 // 1 year
}

pub fn hash_password(password: &[u8]) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);

    match Argon2::default().hash_password(password, &salt) {
        Ok(password_hash) => Ok(password_hash.to_string()),
        Err(e) => Err(e),
    }
}

pub fn verify_password(
    hashed_password: &str,
    password: &[u8],
) -> Result<bool, argon2::password_hash::Error> {
    let parsed_hash = PasswordHash::new(hashed_password)?;

    Ok(Argon2::default()
        .verify_password(password, &parsed_hash)
        .is_ok())
}

pub fn generate_token(
    user_id: &i32,
    exp: u64,
    jwt_key: &[u8],
) -> Result<String, jsonwebtoken::errors::Error> {
    let claims = Claims {
        sub: user_id.to_owned(),
        exp,
    };
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(jwt_key),
    )
}

pub async fn validate_token(
    token: &str,
    jwt_key: &[u8],
    pool: &sqlx::Pool<sqlx::Sqlite>,
) -> Result<User, jsonwebtoken::errors::Error> {
    println!("Validating token: {}", token);
    let validation = Validation::default();
    match decode::<Claims>(token, &DecodingKey::from_secret(jwt_key), &validation) {
        Ok(decoded_token) => {
            let user = User::find_by_id(pool, decoded_token.claims.sub)
                .await
                .unwrap();

            // Check if the User is not empty
            if user.is_empty() {
                println!("User is empty!?");
                return Err(jsonwebtoken::errors::ErrorKind::InvalidIssuer.into());
            }
            Ok(user)
        }
        Err(e) => Err(e),
    }
}

pub async fn validate_user(
    req: HttpRequest,
    jwt_key: &[u8],
    db: &Pool<Sqlite>,
) -> Result<User, jsonwebtoken::errors::Error> {
    match req.headers().get(header::AUTHORIZATION) {
        Some(header_values) => match header_values.to_str() {
            Ok(auth_str) => {
                if auth_str.starts_with("Bearer ") {
                    let token = auth_str.trim_start_matches("Bearer ");
                    match validate_token(token, jwt_key, db).await {
                        Ok(user) => Ok(user),
                        Err(err) => Err(err),
                    }
                } else {
                    Err(jsonwebtoken::errors::Error::from(
                        jsonwebtoken::errors::ErrorKind::InvalidToken,
                    ))
                }
            }
            Err(_) => Err(jsonwebtoken::errors::Error::from(
                jsonwebtoken::errors::ErrorKind::InvalidToken,
            )),
        },
        None => Err(jsonwebtoken::errors::Error::from(
            jsonwebtoken::errors::ErrorKind::InvalidToken,
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_expiration() {
        let expiration = calculate_expiration();
        assert!(expiration > 0);
    }

    #[test]
    fn test_hash_password() {
        let password = "password";
        let hashed_password = hash_password(password.as_bytes()).unwrap();
        assert_ne!(hashed_password, password);
    }

    #[test]
    fn test_verify_password() {
        let password = "password".as_bytes();
        let hashed_password = hash_password(password).unwrap();
        assert!(verify_password(&hashed_password, password).unwrap());
    }

    #[test]
    fn test_generate_token() {
        let user_id = 1;
        let exp = calculate_expiration();
        let jwt_key = b"secret_key";
        let token = generate_token(&user_id, exp, jwt_key).unwrap();
        assert!(!token.is_empty());
    }

    #[test]
    fn test_generate_password() {
        let password = generate_password(8);
        assert_eq!(password.len(), 8);
    }
}
