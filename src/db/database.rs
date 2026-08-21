// ================================================================
// Database
//
// © 2026 WhaleHook. All rights reserved.
//
// Minimal SQLite database used exclusively for testing the
// crawler's data flow.
//
// The current schema stores crawler topics only and is not
// intended to represent the final database architecture.
// ================================================================

use sqlx::{Error, SqlitePool};

pub struct Database {
    pool: SqlitePool,
}

impl Database {
    pub async fn new(path: &str) -> Result<Self, Error> {
        let pool =
            SqlitePool::connect(&format!("sqlite://{path}?mode=rwc")).await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS topics (
                id INTEGER PRIMARY KEY,
                name TEXT
            )"
        )
        .execute(&pool)
        .await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS last_modified (
                url TEXT PRIMARY KEY,
                last_modified TEXT
            )"
        )
        .execute(&pool)
        .await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS recent_cve (
                cve_id TEXT PRIMARY KEY,
                last_modified TEXT NOT NULL,
                data TEXT NOT NULL
            )"
        )
        .execute(&pool)
        .await?;

        Ok(Self { pool })
    }

    pub async fn add_topic(&self, name: &str) -> Result<i64, Error> {
        let r = sqlx::query(
            "INSERT INTO topics (name) VALUES (?)"
        )
        .bind(name)
        .execute(&self.pool)
        .await?;

        Ok(r.last_insert_rowid())
    }

    pub async fn get_topics(&self) -> Result<Vec<(i64, String)>, Error> {
        sqlx::query_as(
            "SELECT id, name FROM topics"
        )
        .fetch_all(&self.pool)
        .await
    }

    pub async fn get_last_modified(
        &self,
        url: &str,
    ) -> Result<Option<String>, Error> {
        let result = sqlx::query_as::<_, (String,)>(
            "SELECT last_modified
             FROM last_modified
             WHERE url = ?"
        )
        .bind(url)
        .fetch_optional(&self.pool)
        .await?;

        Ok(result.map(|(last_modified,)| last_modified))
    }

    pub async fn set_last_modified(
        &self,
        url: &str,
        last_modified: &str,
    ) -> Result<(), Error> {
        sqlx::query(
            "INSERT INTO last_modified (url, last_modified)
             VALUES (?, ?)
             ON CONFLICT(url) DO UPDATE SET
                 last_modified = excluded.last_modified"
        )
        .bind(url)
        .bind(last_modified)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn post_recent_cve(
        &self,
        cve_id: &str,
        last_modified: &str,
        data: &str,
    ) -> Result<(), Error> {
        sqlx::query(
            "INSERT INTO recent_cve (
                cve_id,
                last_modified,
                data
            )
            VALUES (?, ?, ?)
            ON CONFLICT(cve_id) DO UPDATE SET
                last_modified = excluded.last_modified,
                data = excluded.data"
        )
        .bind(cve_id)
        .bind(last_modified)
        .bind(data)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn get_recent_cve(&self) -> Result<Vec<serde_json::Value>, Error> {
        let cves = sqlx::query_scalar::<_, String>(
            "SELECT data
             FROM recent_cve
             ORDER BY last_modified DESC"
        )
        .fetch_all(&self.pool)
        .await?;

        let cves = cves
            .into_iter()
            .map(|data| {serde_json::from_str::<serde_json::Value>(&data)})
            .collect::<Result<Vec<_>, _>>()
            .map_err(|err| Error::Decode(Box::new(err)))?;

        Ok(cves)
    }
}