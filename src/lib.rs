#![forbid(unsafe_code)]

pub mod auth;
mod deadline;
pub mod grants;
mod reads;
pub mod serving;
mod session;
pub mod xmsg_config;

pub mod custody;
pub mod outbound;
mod outbound_lease;
pub use outbound_lease::OperationLease;

pub mod event_store;

#[cfg(test)]
extern crate self as xmsg_mcp_gateway;
#[cfg(test)]
#[allow(dead_code)]
#[path = "../tests/common/provider.rs"]
mod provider_fixture;

pub mod webhook;

pub mod events;
mod event_cursor;
