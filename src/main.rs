// ================================================================
// Omega Crawler API
//
// © 2026 WhaleHook. All rights reserved.
//
// Minimal application entry point used to test the crawler's
// database and API data flow.
//
// Testing
// -------
// Start the application:
//
//     cargo run
//
// Add a topic:
//
//     curl -X POST localhost:3000/topics -d "rust"
//
// Retrieve all topics:
//
//     curl localhost:3000/topics
//
// The database is created automatically as `omega.db`.
//
// This application is currently intended only for development
// and crawler flow testing. The API and database architecture
// may change as the project evolves.
// ================================================================


mod db;
mod api;
use api::routes;
use db::Database;

use std::sync::Arc;

#[tokio::main]
async fn main() {
    let db = Arc::new(Database::new("omega.db").await.unwrap());
    let app = routes(db);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
