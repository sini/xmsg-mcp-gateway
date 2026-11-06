use xmsg_mcp_gateway::{auth::{Verifier, VerifierConfig}, grants::Store};
async fn authorize(store: &Store, config: VerifierConfig, token: &str) {
    let verifier = Verifier::from_config(config).unwrap();
    let identity = verifier.verify(token).await.unwrap();
    let _ = store.authorize(&identity);
}
fn main() {}
