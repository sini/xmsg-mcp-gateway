use xmsg_mcp_gateway::outbound::RequestId;

fn main() {
    let rpc_id = serde_json::json!(42);
    let _: RequestId = rpc_id.into();
}
