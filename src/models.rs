#[derive(Debug, sqlx::FromRow)]
pub struct User {
    pub id: i32,
    pub username: String,
    pub password_hash: String,
    pub last_seen: Option<String>,
    pub since: Option<String>,
}

impl User {
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
    ) -> Result<Option<User>, sqlx::Error> {
        let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE username = $1")
            .bind(username)
            .fetch_optional(pool)
            .await?;
        Ok(user)
    }

    pub fn is_empty(&self) -> bool {
        self.id == 0 && self.username.is_empty() && self.password_hash.is_empty()
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
