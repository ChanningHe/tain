//! Upstream-controlled strings that end up in error messages must be escaped
//! and bounded, so a hostile Release cannot forge log lines or flood stderr.

use std::path::Path;
use std::process::{Command, Output};

mod common;
use common::{StaticServer, SyntheticRepo, TempDir};

const REAL_DATE_LINE: &str = "Date: Sat, 03 Feb 2024 09:15:38 UTC\n";
const FORGED_LINE: &str = "2026-10-25T00:00:00Z ERROR tain: injected line";
/// Generous ceiling for one log line carrying a quoted upstream value.
const MAX_LOG_LINE: usize = 2048;

/// Replace the `Date:` field of both root files with `date_field`.
fn set_date_field(repo_root: &Path, suite: &str, date_field: &str) {
    for name in ["Release", "InRelease"] {
        let path = repo_root.join("dists").join(suite).join(name);
        let body = std::fs::read_to_string(&path).unwrap();
        assert!(body.contains(REAL_DATE_LINE), "fixture Date line moved");
        std::fs::write(&path, body.replace(REAL_DATE_LINE, date_field)).unwrap();
    }
}

async fn sync_once(serve: &Path, target: &Path) -> Output {
    let server = StaticServer::spawn(serve.to_path_buf()).await;
    let config = target.join("tain.toml");
    std::fs::write(
        &config,
        format!(
            "[global]\ntarget = {:?}\n\n[[mirror]]\nname = \"m\"\nurl = \"{}\"\n\
             suites = [\"bookworm\"]\ncomponents = [\"main\"]\narchitectures = [\"amd64\"]\n",
            target.join("data").display().to_string(),
            server.base_url()
        ),
    )
    .unwrap();
    let out = tokio::task::spawn_blocking(move || {
        Command::new(env!("CARGO_BIN_EXE_tain"))
            .arg("--config")
            .arg(&config)
            .arg("sync")
            .env_clear()
            .output()
            .expect("spawn tain")
    })
    .await
    .unwrap();
    drop(server);
    out
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hostile_release_date_cannot_forge_log_lines() {
    // Arrange: an ANSI escape plus a continuation line shaped like a log record.
    let serve = TempDir::new("untrusted-forge-serve");
    let target = TempDir::new("untrusted-forge-target");
    SyntheticRepo::new(serve.path().to_path_buf(), "bookworm")
        .add_package("hello", b"hello deb".to_vec())
        .write();
    set_date_field(
        serve.path(),
        "bookworm",
        &format!("Date: \x1b[31mFAKE\x1b[0m\n {FORGED_LINE}\n"),
    );

    // Act
    let out = sync_once(serve.path(), target.path()).await;

    // Assert
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "a bad Date must fail the sync");
    assert!(stderr.contains("FAKE"), "error not logged: {stderr}");
    assert!(
        !stderr.contains('\x1b'),
        "raw ESC reached the log: {stderr:?}"
    );
    assert!(
        !stderr.lines().any(|l| l.starts_with(FORGED_LINE)),
        "forged log line: {stderr}"
    );
    assert!(
        stderr.lines().all(|l| l.len() <= MAX_LOG_LINE),
        "overlong log line: {stderr}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oversized_release_date_is_truncated_in_logs() {
    // Arrange
    let serve = TempDir::new("untrusted-flood-serve");
    let target = TempDir::new("untrusted-flood-target");
    SyntheticRepo::new(serve.path().to_path_buf(), "bookworm")
        .add_package("hello", b"hello deb".to_vec())
        .write();
    let huge = "A".repeat(4 * 1024 * 1024);
    set_date_field(serve.path(), "bookworm", &format!("Date: {huge}\n"));

    // Act
    let out = sync_once(serve.path(), target.path()).await;

    // Assert
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "a bad Date must fail the sync");
    assert!(
        stderr.contains("4194304 bytes"),
        "truncated value should state its length: {}",
        &stderr[..stderr.len().min(4096)]
    );
    assert!(
        stderr.lines().all(|l| l.len() <= MAX_LOG_LINE),
        "overlong log line ({} bytes of stderr)",
        stderr.len()
    );
}
