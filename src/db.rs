use sqlx::sqlite::SqlitePool;
use sqlx::{migrate::MigrateDatabase, Sqlite};

use crate::utils;

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
        since TEXT
    );",
    )
    .execute(&db)
    .await
    .expect("Failed to create table");

    if let Some(password) = add_admin(&db).await {
        println!("Admin password: {}", password);
    } else {
        println!("Admin user already exists");
    }

    db
}

async fn add_admin(db: &sqlx::Pool<sqlx::Sqlite>) -> Option<String> {
    let admin_result = sqlx::query("SELECT * FROM users WHERE username = 'admin'")
        .fetch_optional(db)
        .await
        .unwrap();

    let _password = utils::generate_password(42);
    let password = "admin".to_string();
    let password_hash = utils::hash_password(password.as_bytes()).unwrap();

    if admin_result.is_none() {
        let _ = sqlx::query("INSERT INTO users (username, password_hash) VALUES ('admin', $1)")
            .bind(&password_hash)
            .execute(db)
            .await
            .unwrap();
        Some(password)
    } else {
        None
    }
}
