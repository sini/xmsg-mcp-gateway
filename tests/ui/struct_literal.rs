use xmsg_mcp_gateway::auth::VerifiedIdentity;
fn main() {
    let _ = VerifiedIdentity {
        service: "gateway".into(), issuer: "https://issuer.example/".into(),
        resource: "https://gateway.example/mcp".into(), subject: "owner".into(),
        hosted_client: "hosted-client".into(), expires_at: u64::MAX,
        token_family:None,admission:None,admission_policy:None,
    audience: "https://gateway.example/mcp".into(),
    };
}
