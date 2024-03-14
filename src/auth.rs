use bcrypt::{hash, verify, DEFAULT_COST};
use jsonwebtoken::{encode, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use sqlx::{Pool, Sqlite};

use crate::utils;

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    passphrase: String,
    exp: usize, // Expiration time
}

/// Asynchronously generates and inserts new user credentials into the database.
///
/// This function generates a unique username and password, hashes the password,
/// and then inserts these credentials into a users table within the specified SQLite database.
/// The function prints the generated username and password to the console.
///
/// # Parameters
/// - `pool`: A `Pool<Sqlite>` connection pool from which a database connection can be acquired.
///
/// # Panics
/// Panics if the insertion into the database fails.
///
/// # Examples
/// ```
/// use sqlx::sqlite::SqlitePoolOptions;
///
/// #[tokio::main]
/// async fn main() {
///     let pool = SqlitePoolOptions::new()
///         .connect("sqlite::memory:").await.unwrap();
///
///     generate_credentials(pool).await;
/// }
/// ```
///
/// Note: Ensure the database is properly set up with a `users` table that includes
/// `username` and `password_hash` columns before calling this function.
pub async fn generate_credentials(pool: Pool<Sqlite>) {
    let username = utils::generate_username();
    let password = utils::generate_password();
    let password_hash = hash(&password, DEFAULT_COST).unwrap();

    let _ = sqlx::query("INSERT INTO users (username, password_hash) VALUES (?, ?)")
        .bind(&username)
        .bind(&password_hash)
        .execute(&pool)
        .await
        .expect("Failed to insert into database");

    println!("Username: {}", username);
    println!("Password: {}", password);
}

/// Asynchronously deletes a user with the specified username from the database.
///
/// This function performs a deletion operation on the `users` table, targeting the row
/// where the `username` matches the given username. It returns the number of rows affected
/// by the deletion operation, which is typically 1 for successful deletions or 0 if the
/// username does not exist in the database.
///
/// # Parameters
/// - `pool`: A `Pool<Sqlite>` representing the database connection pool.
/// - `username`: A string slice reference (`&str`) representing the username of the user to delete.
///
/// # Returns
/// A `Result<u64, sqlx::Error>` indicating the number of rows affected by the deletion operation,
/// or an error if the operation fails.
///
/// # Examples
/// ```
/// use sqlx::sqlite::SqlitePoolOptions;
///
/// #[tokio::main]
/// async fn main() -> Result<(), sqlx::Error> {
///     let pool = SqlitePoolOptions::new()
///         .connect("sqlite::memory:").await?;
///
///     let username = "user123";
///     let result = delete_user(pool, username).await?;
///     println!("Deleted {} user(s)", result);
///
///     Ok(())
/// }
/// ```
///
/// Note: This function does not verify the existence of the user before attempting deletion.
/// It's the caller's responsibility to handle cases where the username may not exist.
pub async fn delete_user(pool: Pool<Sqlite>, username: &str) -> Result<u64, sqlx::Error> {
    let result = sqlx::query("DELETE FROM users WHERE username = ?")
        .bind(username)
        .execute(&pool)
        .await?;

    Ok(result.rows_affected())
}

/// Asynchronously authenticates a user by verifying their username and password against the database.
///
/// This function queries the database for the password hash associated with the given username,
/// then uses bcrypt to verify the provided password against the stored hash. It returns `true`
/// if the authentication is successful (i.e., if the password matches the hash), and `false` otherwise.
///
/// # Parameters
/// - `pool`: A reference to a `Pool<Sqlite>` representing the database connection pool.
/// - `username`: A string slice (`&str`) representing the username of the user attempting to authenticate.
/// - `password`: A string slice (`&str`) representing the password provided by the user for authentication.
///
/// # Returns
/// A `Result<bool, sqlx::Error>` indicating the success or failure of the authentication.
/// On success, returns `Ok(true)` if the user is authenticated successfully, or `Ok(false)` if not.
/// On failure, returns an error, which could be due to database access issues or bcrypt verification failures.
///
/// # Examples
/// ```
/// use sqlx::sqlite::SqlitePoolOptions;
///
/// #[tokio::main]
/// async fn main() -> Result<(), sqlx::Error> {
///     let pool = SqlitePoolOptions::new()
///         .connect("sqlite::memory:").await?;
///
///     let username = "user123";
///     let password = "password";
///     let authenticated = authenticate_user(&pool, username, password).await?;
///     println!("Authenticated: {}", authenticated);
///
///     Ok(())
/// }
/// ```
///
/// Note: This function relies on bcrypt for password verification. Ensure that the `password_hash`
/// in the database is correctly generated using bcrypt for compatibility.
pub async fn authenticate_user(
    pool: &Pool<Sqlite>,
    username: &str,
    password: &str,
) -> Result<bool, sqlx::Error> {
    // let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");

    let row = sqlx::query("SELECT password_hash FROM users WHERE username = ?")
        .bind(username)
        .fetch_one(pool)
        .await?;

    let password_hash: String = row.try_get("password_hash")?;

    match verify(password, &password_hash) {
        Ok(matches) => Ok(matches),
        Err(_) => Err(sqlx::Error::RowNotFound), // or handle bcrypt error differently
    }
}

/// Asynchronously generates a JWT token for the given username and password.
pub async fn generate_token(
    username: &str,
    password: &str,
    jwt_key: &str,
    pool: &Pool<Sqlite>,
) -> Result<String, sqlx::Error> {
    let authenticated = authenticate_user(pool, username, password).await?;

    if authenticated {
        let expiration_time = 3600; // 1 hour
        let claims = Claims {
            passphrase: username.to_string(),
            exp: expiration_time,
        };

        // Convert the jwt_key from a string slice (&str) to a byte slice (&[u8]),
        // then create an EncodingKey
        let encoding_key = EncodingKey::from_secret(jwt_key.as_ref());

        let token = encode(&Header::default(), &claims, &encoding_key)
            .map_err(|_| sqlx::Error::Protocol("Encode error".to_string()))?;

        Ok(token)
    } else {
        Err(sqlx::Error::RowNotFound)
    }
}
