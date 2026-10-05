//! Per-mirror state under `<target>/<mirror>/.tain/`: run lock, `state.json`,
//! and the generation manifest used by GC.

pub mod lock;
pub mod manifest;
pub mod state;

use std::path::{Path, PathBuf};

/// Internal state directory under each mirror root; web servers should hide it.
pub const STATE_DIR: &str = ".tain";

/// Return the mirror's `.tain/` directory, creating it if missing.
///
/// # Errors
///
/// Any `create_dir_all` failure.
pub fn ensure_state_dir(mirror_root: &Path) -> std::io::Result<PathBuf> {
    let dir = mirror_root.join(STATE_DIR);
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}
