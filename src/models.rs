use serde::Serialize;

#[derive(Debug, sqlx::FromRow, Serialize)]
pub struct User {
    pub id: i32,
    pub username: String,
    pub password_hash: String,
    pub last_seen: Option<String>,
    pub since: Option<String>,
    pub role: String,
}

impl User {
    pub async fn create(&self, pool: &sqlx::Pool<sqlx::Sqlite>) -> Result<User, sqlx::Error> {
        let user = sqlx::query_as::<_, User>(
            "INSERT INTO users (username, password_hash, role, last_seen, since) VALUES ($1, $2, $3, datetime('now'), datetime('now')) RETURNING *",
        )
        .bind(&self.username)
        .bind(&self.password_hash)
        .bind(&self.role)
        .fetch_one(pool)
        .await?;

        Ok(user)
    }

    pub async fn find_by_id(pool: &sqlx::Pool<sqlx::Sqlite>, id: i32) -> Result<User, sqlx::Error> {
        let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = $1")
            .bind(id)
            .fetch_one(pool)
            .await?;

        Ok(user)
    }

    pub async fn find_by_username(
        pool: &sqlx::Pool<sqlx::Sqlite>,
        username: &str,
    ) -> Result<User, sqlx::Error> {
        let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE username = $1")
            .bind(username)
            .fetch_one(pool)
            .await?;

        Ok(user)
    }

    pub fn is_empty(&self) -> bool {
        self.id == 0 && self.username.is_empty() && self.password_hash.is_empty()
    }

    pub fn is_admin(&self) -> bool {
        self.role == "admin"
    }

    pub async fn update_last_seen(
        &self,
        pool: &sqlx::Pool<sqlx::Sqlite>,
    ) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE users SET last_seen = datetime('now') WHERE id = $1")
            .bind(self.id)
            .execute(pool)
            .await?;
        Ok(())
    }
}
