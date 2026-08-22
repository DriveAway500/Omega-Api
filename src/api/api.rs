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

use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, Path, State},
    routing::{get, post},
    Json, Router,
};
use axum::http::StatusCode;
use serde_json::Value;
use std::sync::Arc;

use crate::Database;

pub fn routes(db: Arc<Database>) -> Router {
    Router::new()
        .route("/health", get(health_check))
        .route("/topics", get(get_topics).post(add_topic))
        .route("/last_modified/{*url}", get(get_last_modified).post(set_last_modified))
        .route("/recent_cve", post(post_recent_cve))
        .route("/recent_cve_feed", get(get_recent_cve))
        .layer(DefaultBodyLimit::max(50 * 1024 * 1024))
        .with_state(db)
}

async fn health_check() -> StatusCode {
    StatusCode::OK
}

async fn add_topic(
    State(db): State<Arc<Database>>,
    body: String,
) -> Json<i64> {
    let id = db.add_topic(&body).await.unwrap();
    Json(id)
}

async fn get_topics(
    State(db): State<Arc<Database>>,
) -> Json<Vec<(i64, String)>> {
    Json(db.get_topics().await.unwrap())
}

async fn get_last_modified(
    State(db): State<Arc<Database>>,
    Path(url): Path<String>,
) -> Json<Option<String>> {
    let last_modified = db.get_last_modified(&url).await.unwrap();
    Json(last_modified)
}

async fn set_last_modified(
    State(db): State<Arc<Database>>,
    Path(url): Path<String>,
    body: String) -> StatusCode {
    db.set_last_modified(&url, &body).await.unwrap();
    StatusCode::NO_CONTENT
}

async fn post_recent_cve(
    State(db): State<Arc<Database>>,
    body: Bytes,
) -> Result<StatusCode, StatusCode> {

    let feed: Value = serde_json::from_slice(&body)
        .map_err(|err| {
            println!("err: {:?}", err);
            StatusCode::BAD_REQUEST
        })?;

    let vulnerabilities = feed
        .get("vulnerabilities")
        .and_then(Value::as_array)
        .ok_or(StatusCode::BAD_REQUEST)?;

    for vulnerability in vulnerabilities {

        let cve = vulnerability
            .get("cve")
            .ok_or(StatusCode::BAD_REQUEST)?;

        let cve_id = cve
            .get("id")
            .and_then(Value::as_str)
            .ok_or(StatusCode::BAD_REQUEST)?;

        let last_modified = cve
            .get("lastModified")
            .and_then(Value::as_str)
            .ok_or(StatusCode::BAD_REQUEST)?;

        println!("last_modified: {:?}", last_modified);

        let data = serde_json::to_string(cve)
            .map_err(|err| {
                println!("err: {:?}", err);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

        db.post_recent_cve(
            cve_id,
            last_modified,
            &data,
        )
        .await
        .map_err(|err| {
            println!("err: {:?}", err);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    }

    Ok(StatusCode::NO_CONTENT)
}

async fn get_recent_cve(
    State(db): State<Arc<Database>>,
) -> Result<Json<Vec<serde_json::Value>>, StatusCode> {
    let cves = db
        .get_recent_cve()
        .await
        .map_err(|err| {
            println!("err: {:?}", err);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok(Json(cves))
}