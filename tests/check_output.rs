//! `tain check` prints every setting, defaults included, as valid TOML.

use std::process::Command;

mod common;
use common::TempDir;

const MINIMAL: &str = r#"
[[mirror]]
name = "debian"
url = "http://127.0.0.1:1/debian"
suites = ["bookworm"]
components = ["main"]
architectures = ["amd64"]
"#;

fn check(body: &str) -> String {
    let dir = TempDir::new("check-output");
    let path = dir.path().join("tain.toml");
    std::fs::write(&path, body).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_tain"))
        .env_clear()
        .arg("--config")
        .arg(&path)
        .arg("check")
        .output()
        .expect("spawn tain");
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    stdout
}

#[test]
fn unset_settings_are_shown_with_their_default() {
    let out = check(MINIMAL);
    for line in [
        "log_level = \"info\"\n",
        "# bind_address = (unset)\n",
        "# schedule = (unset)\n",
        "# keyring = (unset)\n",
    ] {
        assert!(out.contains(line), "missing `{line}`:\n{out}");
    }
}

#[test]
fn set_settings_replace_the_unset_markers() {
    let out = check(&format!(
        "[global]\nbind_address = \"192.0.2.1\"\nschedule = \"0 3 * * *\"\nlog_level = \"debug\"\n\
         {MINIMAL}[mirror.verify]\nkeyring = \"/etc/k.gpg\"\n"
    ));
    assert!(!out.contains("(unset)"), "{out}");
    for line in [
        "bind_address = \"192.0.2.1\"\n",
        "schedule = \"0 3 * * *\"\n",
        "log_level = \"debug\"\n",
        "keyring = \"/etc/k.gpg\"\n",
    ] {
        assert!(out.contains(line), "missing `{line}`:\n{out}");
    }
}

#[test]
fn check_output_is_accepted_by_check() {
    let first = check(MINIMAL);
    assert_eq!(check(&first), first);
}
