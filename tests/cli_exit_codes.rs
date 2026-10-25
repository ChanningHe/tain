//! Exit-code contract of the real binary for config-level failures. Every
//! case here fails before any network access.

use std::path::Path;
use std::process::{Command, Output};

mod common;
use common::TempDir;

const MIRROR: &str = r#"
[[mirror]]
name = "debian"
url = "http://127.0.0.1:1/debian"
suites = ["bookworm"]
components = ["main"]
architectures = ["amd64"]
"#;

fn write_config(dir: &TempDir, body: &str) -> std::path::PathBuf {
    let target = dir.path().join("target");
    let path = dir.path().join("tain.toml");
    let text = format!("[global]\ntarget = \"{}\"\n{body}", target.display());
    std::fs::write(&path, text).unwrap();
    path
}

fn tain(config: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_tain"))
        .env_clear()
        .arg("--config")
        .arg(config)
        .args(args)
        .output()
        .expect("spawn tain")
}

fn tain_with_env(config: &Path, env: &[(&str, &str)], args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_tain"))
        .env_clear()
        .envs(env.iter().copied())
        .arg("--config")
        .arg(config)
        .args(args)
        .output()
        .expect("spawn tain")
}

fn assert_exit(out: &Output, code: i32, needle: &str) {
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(code), "stderr:\n{stderr}");
    assert!(
        stderr.contains(needle),
        "missing `{needle}` in stderr:\n{stderr}"
    );
}

#[test]
fn check_accepts_valid_config() {
    let dir = TempDir::new("cli-ok");
    let cfg = write_config(&dir, MIRROR);
    let out = tain(&cfg, &["check"]);
    assert_eq!(out.status.code(), Some(0), "{out:?}");
}

#[test]
fn check_rejects_dists_mirror_without_components() {
    let dir = TempDir::new("cli-nocomp");
    let body = MIRROR.replace("components = [\"main\"]\n", "");
    let cfg = write_config(&dir, &body);
    assert_exit(&tain(&cfg, &["check"]), 2, "at least one component");
}

#[test]
fn check_rejects_unsafe_suite_path() {
    let dir = TempDir::new("cli-suite");
    let body = MIRROR.replace("[\"bookworm\"]", "[\"../../../etc\"]");
    let cfg = write_config(&dir, &body);
    assert_exit(&tain(&cfg, &["check"]), 2, "unsafe path");
}

#[test]
fn check_rejects_escaping_mirror_path() {
    let dir = TempDir::new("cli-path");
    let body = format!("{MIRROR}path = \"../escape\"\n");
    let cfg = write_config(&dir, &body);
    assert_exit(&tain(&cfg, &["check"]), 2, "must not contain `..`");
}

#[test]
fn check_rejects_schedule_without_next_occurrence() {
    let dir = TempDir::new("cli-cron");
    let cfg = write_config(&dir, &format!("schedule = \"0 0 30 2 *\"\n{MIRROR}"));
    assert_exit(&tain(&cfg, &["check"]), 2, "0 0 30 2 *");
}

#[test]
fn check_rejects_unparsable_schedule() {
    let dir = TempDir::new("cli-cron-bad");
    let cfg = write_config(&dir, &format!("schedule = \"not cron\"\n{MIRROR}"));
    assert_exit(&tain(&cfg, &["check"]), 2, "not cron");
}

#[cfg(unix)]
#[test]
fn daemon_rejects_schedule_without_next_occurrence() {
    let dir = TempDir::new("cli-daemon-cron");
    let cfg = write_config(&dir, &format!("schedule = \"0 0 30 2 *\"\n{MIRROR}"));
    assert_exit(
        &tain(&cfg, &["daemon", "--no-initial-sync"]),
        2,
        "0 0 30 2 *",
    );
}

#[test]
fn sync_unknown_mirror_is_config_error() {
    let dir = TempDir::new("cli-unknown-sync");
    let cfg = write_config(&dir, MIRROR);
    assert_exit(&tain(&cfg, &["sync", "--mirror", "debain"]), 2, "debain");
}

#[test]
fn verify_unknown_mirror_is_config_error() {
    let dir = TempDir::new("cli-unknown-verify");
    let cfg = write_config(&dir, MIRROR);
    assert_exit(&tain(&cfg, &["verify", "--mirror", "debain"]), 2, "debain");
}

#[test]
fn commands_reject_config_without_mirrors() {
    let dir = TempDir::new("cli-empty");
    let cfg = write_config(&dir, "schedule = \"0 * * * *\"\n");
    for args in [
        &["sync"][..],
        &["status"],
        &["verify"],
        &["daemon", "--no-initial-sync"],
    ] {
        assert_exit(&tain(&cfg, args), 2, "no mirrors");
    }
    // `check` still prints the (empty) resolved config.
    assert_eq!(tain(&cfg, &["check"]).status.code(), Some(0));
}

#[test]
fn empty_target_is_config_error() {
    let dir = TempDir::new("cli-target");
    let path = dir.path().join("tain.toml");
    std::fs::write(&path, format!("[global]\ntarget = \"\"\n{MIRROR}")).unwrap();
    assert_exit(&tain(&path, &["check"]), 2, "target");
}

#[test]
fn empty_tain_target_env_is_config_error() {
    let dir = TempDir::new("cli-target-env");
    let cfg = write_config(&dir, MIRROR);
    let out = Command::new(env!("CARGO_BIN_EXE_tain"))
        .env_clear()
        .env("TAIN_TARGET", "")
        .arg("--config")
        .arg(&cfg)
        .arg("check")
        .output()
        .unwrap();
    assert_exit(&out, 2, "target");
}

#[test]
fn invalid_log_level_names_the_value() {
    let dir = TempDir::new("cli-loglevel");
    let cfg = write_config(&dir, &format!("log_level = \"lou[d\"\n{MIRROR}"));
    let out = tain(&cfg, &["check"]);
    assert_exit(&out, 2, "config error: invalid log level `lou[d`");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(stderr.matches("invalid log level").count(), 1, "{stderr}");
}

/// A bare word EnvFilter would read as a target name used to silence every
/// log line and still run the command.
#[test]
fn misspelled_env_log_level_is_a_config_error() {
    let dir = TempDir::new("cli-loglevel-env");
    let cfg = write_config(&dir, MIRROR);
    for bad in ["nonsense", "bogus!!"] {
        let out = tain_with_env(&cfg, &[("TAIN_LOG_LEVEL", bad)], &["sync", "--dry-run"]);
        assert_exit(&out, 2, &format!("invalid log level `{bad}`"));
    }
}

#[test]
fn segments_per_file_out_of_range_is_a_config_error() {
    let dir = TempDir::new("cli-segments");
    let cfg = write_config(&dir, &format!("segments_per_file = 0\n{MIRROR}"));
    assert_exit(&tain(&cfg, &["check"]), 2, "between 1 and 8, got 0");
    let cfg = write_config(&dir, MIRROR);
    let out = tain_with_env(&cfg, &[("TAIN_SEGMENTS", "9")], &["check"]);
    assert_exit(&out, 2, "between 1 and 8, got 9");
}

#[test]
fn warning_is_accepted_as_log_level() {
    let dir = TempDir::new("cli-loglevel-warning");
    let cfg = write_config(&dir, &format!("log_level = \"warning\"\n{MIRROR}"));
    let out = tain(&cfg, &["check"]);
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    let out = tain_with_env(&cfg, &[("TAIN_LOG_LEVEL", "warning")], &["check"]);
    assert_eq!(out.status.code(), Some(0), "{out:?}");
}
