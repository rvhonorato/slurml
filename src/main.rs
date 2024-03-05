use crate::config::Config;
use actix_web::middleware::Logger;
use actix_web::{web, App, HttpServer};
use env_logger::Env;
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};

mod auth;
mod config;
mod controllers;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // load the configuration
    let config = Config::new().expect("Failed to load configuration");

    // make the logger
    env_logger::init_from_env(Env::default().default_filter_or("info"));

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
            .wrap(Logger::default())
            .wrap(Logger::new("%a %{User-Agent}i"))
            .service(controllers::generate_token)
    })
    // .workers(4)
    .bind_openssl(("127.0.0.1", 8080), builder)?
    .run()
    .await
}
