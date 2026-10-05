//! Tain — repository mirror sync framework.
//!
//! `core` owns downloading, manifests, publish, GC and scheduling; `backends`
//! only describe what to fetch and publish and never write the published tree.

pub mod backends;
pub mod cli;
pub mod config;
pub mod core;
pub mod exit;
pub mod observe;
