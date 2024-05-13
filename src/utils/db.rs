use sqlx::sqlite::SqlitePool;
use sqlx::{migrate::MigrateDatabase, Sqlite};

use crate::utils;

use crate::models::users::User;

const DB_URL: &str = "sqlite://sqlite.db";

pub async fn init_db() -> sqlx::Pool<sqlx::Sqlite> {
    if !Sqlite::database_exists(DB_URL).await.unwrap_or(false) {
        match Sqlite::create_database(DB_URL).await {
            Ok(_) => println!("Create db success"),
            Err(error) => panic!("error: {}", error),
        }
    }
    let db = SqlitePool::connect(DB_URL).await.unwrap();

    let _ = sqlx::query(
        "CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        last_seen TEXT,
        since TEXT,
        role TEXT
    );",
    )
    .execute(&db)
    .await
    .expect("Failed to create table");

    // Add a new admin user
    let user = User {
        id: 0,
        username: "admin".to_string(),
        password_hash: utils::tools::hash_password("admin".as_bytes()).unwrap(),
        last_seen: None,
        since: None,
        role: "admin".to_string(),
    };

    match user.create(&db).await {
        Ok(_) => println!("Admin user created"),
        Err(_) => println!("Admin user already exists"),
    }

    db
}
