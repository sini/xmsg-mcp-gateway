#[allow(dead_code)]
fn task(connection: rusqlite::Connection) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        {
            let transaction = connection.unchecked_transaction().unwrap();
            transaction.commit().unwrap();
        }
        std::future::ready(()).await;
    })
}

fn main() {}
