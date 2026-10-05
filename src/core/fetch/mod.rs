//! HTTP fetch layer: client, concurrency budget, verifying sink, Range-segmented
//! downloads, and the stall watchdog.

pub mod budget;
pub mod client;
pub mod segmented;
pub mod sink;
pub mod watchdog;
