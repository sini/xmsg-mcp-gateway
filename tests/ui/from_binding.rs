use xmsg_mcp_gateway::{auth::VerifiedIdentity, grants::Binding};
fn convert(binding: Binding) -> VerifiedIdentity { binding.into() }
fn main() {}
