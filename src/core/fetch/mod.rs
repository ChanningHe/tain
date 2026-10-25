//! HTTP fetch layer: client, concurrency budget, verifying sink, Range-segmented
//! downloads, the stall watchdog, and retry backoff.

pub mod budget;
pub mod client;
mod guard;
pub mod retry;
pub mod segmented;
pub mod sink;
pub mod watchdog;
