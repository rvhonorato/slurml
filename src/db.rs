use sqlx::sqlite::SqlitePoolOptions;
use sqlx::{Pool, Sqlite};

pub async fn init_db(db_path: &str) -> Result<Pool<Sqlite>, sqlx::Error> {
    let pool = SqlitePoolOptions::new()
        .connect(db_path)
        .await
        .expect("Failed to create pool.");

    // Execute a SQL command to create the table if it doesn't exist
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS user_accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL
        )",
    )
    .execute(&pool)
    .await?;

    Ok(pool)
}
