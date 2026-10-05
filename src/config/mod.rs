//! Configuration model and sources.
//!
//! *Resolved* types (`Config`, `MirrorConfig`, …) have every field concrete;
//! *partial* types (`PartialGlobal`, `PartialMirror`, `MirrorDefaults`, …) are
//! what TOML/env sources produce before `inherit → build` resolves them.

pub mod display;
pub mod env;
pub mod load;
pub mod mirrors_list;
pub mod model;
pub mod toml;

pub use model::*;
