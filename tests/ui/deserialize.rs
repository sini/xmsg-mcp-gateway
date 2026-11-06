use xmsg_mcp_gateway::auth::VerifiedIdentity;
fn main() {
    let _: VerifiedIdentity = serde_json::from_str("{}").unwrap();
}
