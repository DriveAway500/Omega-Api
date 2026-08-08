mod db;
use db::Database;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
let db = Database::new("omega.db").await?;
db.add_topic("rust").await?;
let topics = db.get_topics().await?;
for (id, name) in topics {
    println!("Topic {}: {}", id, name);
}
Ok(())
}
