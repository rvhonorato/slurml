use actix_web::middleware::Logger;
use actix_web::{web, App, HttpServer};
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};
use sqlx::{Pool, Sqlite};

use crate::config;
use crate::controllers;

pub async fn run(db: Pool<Sqlite>, config: config::Config) -> std::io::Result<()> {
    // Initialize the database

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
            .service(controllers::token)
            .service(controllers::index)
    })
    // .workers(4)
    .bind_openssl(("127.0.0.1", 8080), builder)?
    .run()
    .await
}
