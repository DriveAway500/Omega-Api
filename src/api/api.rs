use axum::{extract::State, routing::{get}, Json, Router};
use std::sync::Arc;
use crate::Database; // ajuste o path conforme seu projeto

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