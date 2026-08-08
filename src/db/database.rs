use sqlx::{SqlitePool, Error};

pub struct Database {
    pool: SqlitePool,
}

impl Database {
    pub async fn new(path: &str) -> Result<Self, Error> {
        let pool = SqlitePool::connect(&format!("sqlite://{path}?mode=rwc")).await?;
        sqlx::query("CREATE TABLE IF NOT EXISTS topics (id INTEGER PRIMARY KEY, name TEXT)")
            .execute(&pool)
            .await?;
        Ok(Self { pool })
    }

    pub async fn add_topic(&self, name: &str) -> Result<i64, Error> {
        let r = sqlx::query("INSERT INTO topics (name) VALUES (?)")
            .bind(name)
            .execute(&self.pool)
            .await?;
        Ok(r.last_insert_rowid())
    }

    pub async fn get_topics(&self) -> Result<Vec<(i64, String)>, Error> {
        sqlx::query_as("SELECT id, name FROM topics")
            .fetch_all(&self.pool)
            .await
    }
}