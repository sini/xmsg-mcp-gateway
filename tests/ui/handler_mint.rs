#![allow(dead_code)]
mod grants {
    pub use xmsg_mcp_gateway::grants::exact_audience;
}
#[path = "../../src/auth.rs"]
mod auth;
mod handler {
    fn mint() {
        let _ = super::auth::VerifiedIdentity {
            service: "gateway".into(), issuer: "https://issuer.example/".into(),
            resource: "https://gateway.example/mcp".into(), subject: "owner".into(),
            hosted_client: "hosted-client".into(), expires_at: u64::MAX,
        };
    }
}
fn main() {}
