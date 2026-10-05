//! Format-agnostic core: download engine, generation manifest, atomic publish,
//! GC, scrub, and the backend trait boundary. A new backend must not require
//! changes here.

pub mod backend;
#[cfg(unix)]
pub mod daemon;
pub mod engine;
pub mod fetch;
pub mod staging;
pub mod store;
pub mod types;
