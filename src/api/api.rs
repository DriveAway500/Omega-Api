// ================================================================
// API Routes
//
// © 2026 WhaleHook. All rights reserved.
//
// Minimal API routes used exclusively for testing the crawler's
// data flow.
//
// The current API exposes topic creation and retrieval only.
// ================================================================

use axum::{extract::State, routing::{get}, Json, Router};
use axum::http::StatusCode;
use std::sync::Arc;
use crate::Database;

pub fn routes(db: Arc<Database>) -> Router {
    Router::new()
        .route("/health", get(health_check))
        .route("/topics", get(get_topics).post(add_topic))
        .route("/last_modified/{*url}", get(get_last_modified).post(set_last_modified))
        .with_state(db)
}

async fn health_check() -> StatusCode{
    StatusCode::OK
}

async fn add_topic(State(db): State<Arc<Database>>, body: String) -> Json<i64> {
    let id = db.add_topic(&body).await.unwrap();
    Json(id)
}

async fn get_topics(
    State(db): State<Arc<Database>>) -> Json<Vec<(i64, String)>> {
    Json(db.get_topics().await.unwrap())
}

async fn get_last_modified(
    State(db): State<Arc<Database>>, 
    axum::extract::Path(url): axum::extract::Path<String>) -> Json<Option<String>> {
    let last_modified = db.get_last_modified(&url).await.unwrap();
    Json(last_modified)
}

async fn set_last_modified(
    State(db): State<Arc<Database>>,
    axum::extract::Path(url): axum::extract::Path<String>,
    body: String,) -> StatusCode {
    db.set_last_modified(&url, &body).await.unwrap();
    StatusCode::NO_CONTENT
}