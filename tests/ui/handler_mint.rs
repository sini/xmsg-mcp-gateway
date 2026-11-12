#![allow(dead_code)]
#[allow(unused_imports)]
mod grants {
    pub use xmsg_mcp_gateway::grants::{exact_audience, Authorization, Binding};
}
mod outbound {pub use xmsg_mcp_gateway::outbound::Policy;}
mod auth {
    mod identity {include!("../../src/auth/identity.rs");}
    pub use identity::VerifiedIdentity;
}
mod handler {
    fn mint() {
        let _ = super::auth::VerifiedIdentity {
            service: "gateway".into(), issuer: "https://issuer.example/".into(),
            resource: "https://gateway.example/mcp".into(), subject: "owner".into(),
            hosted_client: "hosted-client".into(), expires_at: u64::MAX,
        audience: "https://gateway.example/mcp".into(),
        token_family:None,admission:None,admission_policy:None,
        };
    }
}
fn main() {}
pub use xmsg_mcp_gateway::webhook;
