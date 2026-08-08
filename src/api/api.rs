// ================================================================
// Omega Crawler API Routes
//
// © 2026 WhaleHook. All rights reserved.
//
// Minimal API routes used exclusively for testing the crawler's
// data flow.
//
// The current API exposes topic creation and retrieval only.
// ================================================================

use axum::{extract::State, routing::{get}, Json, Router};
use std::sync::Arc;
use crate::Database;

pub fn routes(db: Arc<Database>) -> Router {
    Router::new()
        .route("/topics", get(get_topics).post(add_topic))
        .with_state(db)
}

async fn add_topic(State(db): State<Arc<Database>>, body: String) -> Json<i64> {
    let id = db.add_topic(&body).await.unwrap();
    Json(id)
}

async fn get_topics(State(db): State<Arc<Database>>) -> Json<Vec<(i64, String)>> {
    Json(db.get_topics().await.unwrap())
}