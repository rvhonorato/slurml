use sqlx::sqlite::SqlitePool;
use sqlx::{migrate::MigrateDatabase, Sqlite};

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
        password_hash TEXT NOT NULL
    );",
    )
    .execute(&db)
    .await
    .unwrap();

    db
}
