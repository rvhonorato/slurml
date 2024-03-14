use crate::config::Config;

use env_logger::Env;

mod auth;
mod config;
mod controllers;
mod db;
mod slurml;
mod utils;

use clap::{Arg, SubCommand};

#[tokio::main]
async fn main() {
    env_logger::init_from_env(Env::default().default_filter_or("info"));

    let db = db::init_db().await;

    let config = Config::new().expect("Failed to load configuration");

    let matches = clap::App::new("slurml")
        .version("1.0")
        .author("Your Name <your_email@example.com>")
        .about("Manages usernames and passwords")
        .subcommand(
            SubCommand::with_name("gen-credentials").about("Generate a username and password"),
        )
        .subcommand(
            SubCommand::with_name("auth")
                .about("Authenticate a username and password")
                .arg(Arg::with_name("username").required(true))
                .arg(Arg::with_name("password").required(true)),
        )
        .subcommand(
            SubCommand::with_name("delete-user")
                .about("Delete a user")
                .arg(Arg::with_name("username").required(true)),
        )
        .subcommand(SubCommand::with_name("run").about("Run SLURML"))
        .get_matches();

    // =======================================================================================
    if matches.subcommand_matches("gen-credentials").is_some() {
        auth::generate_credentials(db.clone()).await;
    } else if matches.subcommand_matches("run").is_some() {
        let _ = slurml::run(db, config).await;
    }
    // =======================================================================================
    else if let Some(matches) = matches.subcommand_matches("auth") {
        let username = matches.value_of("username").unwrap();
        let password = matches.value_of("password").unwrap();
        let authenticated = auth::authenticate_user(&db, username, password)
            .await
            .expect("Failed to authenticate user");
        println!("Authenticated: {}", authenticated);
    }
    // =======================================================================================
    else if let Some(matches) = matches.subcommand_matches("delete-user") {
        let username = matches.value_of("username").unwrap();
        let deleted = auth::delete_user(db, username)
            .await
            .expect("Failed to delete user");
        println!("Deleted: {}", deleted);
    }
    // =======================================================================================
    else {
        println!("No subcommand specified");
    }
}
