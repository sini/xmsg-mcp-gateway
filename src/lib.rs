#![forbid(unsafe_code)]

mod attachment_store;
mod attachments;
pub mod auth;
pub mod broker;
mod deadline;
mod dispatch_outcome;
mod event_diagnostic;
pub mod grants;
mod reads;
pub mod serving;
mod session;
pub mod xmsg_config;

pub mod custody;
pub mod outbound;
mod outbound_lease;
pub mod retirement;
pub use outbound_lease::OperationLease;

pub mod event_store;

#[cfg(test)]
extern crate self as xmsg_mcp_gateway;
#[cfg(test)]
#[allow(dead_code)]
#[path = "../tests/common/provider.rs"]
mod provider_fixture;

pub mod webhook;

mod event_cursor;
mod event_dispatch;
pub mod events;
#[cfg(test)]
mod events_test_support;
mod recovery;

mod event_replay;

mod event_status;

#[cfg(test)]
use provider_fixture as provider;
#[cfg(test)]
#[allow(dead_code)]
#[path = "../tests/common/event_callback.rs"]
mod event_callback_fixture;
#[cfg(test)]
#[path = "../tests/common/outbound_observer.rs"]
mod event_observer_fixture;

#[cfg(test)]
mod event_observability_tests;

#[cfg(test)]
mod event_renewal_status_tests;
