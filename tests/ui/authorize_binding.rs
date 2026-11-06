use xmsg_mcp_gateway::grants::{Binding, Store};
fn authorize(store: &Store, binding: &Binding) { let _ = store.authorize(binding); }
fn main() {}
