mod db;
mod api;
use api::routes;
use db::Database;

use std::sync::Arc;

#[tokio::main]
async fn main() {
    let db = Arc::new(Database::new("test.db").await.unwrap());
    let app = routes(db);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
