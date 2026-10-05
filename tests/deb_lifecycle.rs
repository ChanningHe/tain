//! Thin wrapper running `tests/e2e/deb-lifecycle.sh` (apt install/upgrade/purge
//! in a Debian container). Needs docker, cargo-deb (auto-installed), and network
//! to pull the image; run with `cargo test -- --ignored deb_lifecycle`.

use std::path::PathBuf;
use std::process::Command;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn script_path() -> PathBuf {
    repo_root().join("tests/e2e/deb-lifecycle.sh")
}

fn docker_available() -> bool {
    let has_bin = Command::new("docker")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !has_bin {
        return false;
    }
    Command::new("docker")
        .arg("info")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[test]
#[ignore = "requires docker daemon + cargo-deb; opt-in via `cargo test -- --ignored`"]
fn deb_lifecycle_install_upgrade_purge() {
    assert!(
        script_path().exists(),
        "e2e script missing at {}",
        script_path().display()
    );

    if !docker_available() {
        eprintln!(
            "skipped: docker daemon not reachable — run this test on a machine with docker \
             or invoke tests/e2e/deb-lifecycle.sh <deb-path> from a Debian VM directly"
        );
        return;
    }

    let status = Command::new("bash")
        .arg(script_path())
        .env(
            "TAIN_E2E_IMAGE",
            std::env::var("TAIN_E2E_IMAGE").unwrap_or_else(|_| "debian:trixie-slim".to_string()),
        )
        .current_dir(repo_root())
        .status()
        .expect("failed to spawn tests/e2e/deb-lifecycle.sh");

    assert!(
        status.success(),
        "deb-lifecycle.sh exited with {:?} — see stderr above for the failing assertion",
        status.code(),
    );
}
