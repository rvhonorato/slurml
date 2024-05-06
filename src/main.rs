use crate::config::Config;

use env_logger::Env;

mod auth;
mod auth_controller;
mod config;
mod db;
mod models;
mod responses;
mod slurml;
mod utils;

use actix_web::middleware::Logger;
use actix_web::{web, App, HttpServer};
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(Env::default().default_filter_or("info"));

    // Load the configuration
    let config = Config::new().expect("Failed to load configuration");

    // Initialize the database
    let db = db::init_db().await;

    // load TLS keys
    // openssl req -x509 -newkey rsa:4096 -nodes -keyout key.pem -out cert.pem -days 365 -subj '/CN=localhost'
    let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
    builder
        .set_private_key_file("key.pem", SslFiletype::PEM)
        .unwrap();
    builder.set_certificate_chain_file("cert.pem").unwrap();

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(config.clone()))
            .app_data(web::Data::new(db.clone()))
            .wrap(Logger::default())
            .wrap(Logger::new("%a %{User-Agent}i"))
            .service(auth_controller::index)
            .service(auth_controller::login)
            .service(auth_controller::upload)
    })
    // .workers(4)
    .bind_openssl(("127.0.0.1", 8080), builder)?
    .run()
    .await
}
