use crate::auth;
use actix_web::{post, web, Responder};
use serde::{Deserialize, Serialize};

use crate::config::Config;

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenRequest {
    pub pass: String,
}

// #[post("/token")]
// pub async fn generate_token(
//     req_body: web::Json<TokenRequest>,
//     config: web::Data<Config>,
// ) -> impl Responder {
//     match auth::generate_jwt(&req_body.pass, config) {
//         Ok(token) => token,
//         Err(e) => e,
//     }
// }
