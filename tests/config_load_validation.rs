//! Load-time validation through the real binary: every value that would
//! only fail mid-sync must be rejected by `tain check` with exit code 2.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

mod common;
use common::TempDir;

const URL: &str = "http://127.0.0.1:1/debian";

/// One mirror; `extra` lines go inside the `[[mirror]]` block.
fn mirror(name: &str, suites: &str, components: &str, extra: &str) -> String {
    format!(
        "[[mirror]]\nname = \"{name}\"\nurl = \"{URL}\"\nsuites = {suites}\n\
         components = {components}\narchitectures = [\"amd64\"]\n{extra}\n"
    )
}

fn default_mirror(extra: &str) -> String {
    mirror("debian", r#"["bookworm"]"#, r#"["main"]"#, extra)
}

fn write_config(dir: &TempDir, global: &str, body: &str) -> PathBuf {
    let target = dir.path().join("target");
    let path = dir.path().join("tain.toml");
    let text = format!(
        "[global]\ntarget = \"{}\"\n{global}\n{body}",
        target.display()
    );
    std::fs::write(&path, text).unwrap();
    path
}

fn run(config: Option<&Path>, env: &[(&str, &str)], args: &[&str]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_tain"));
    cmd.env_clear().envs(env.iter().copied());
    if let Some(config) = config {
        cmd.arg("--config").arg(config);
    }
    cmd.args(args).output().expect("spawn tain")
}

fn check(dir_prefix: &str, global: &str, body: &str) -> Output {
    let dir = TempDir::new(dir_prefix);
    let cfg = write_config(&dir, global, body);
    run(Some(&cfg), &[], &["check"])
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[track_caller]
fn assert_config_error(out: &Output, needle: &str) {
    let err = stderr(out);
    assert_eq!(out.status.code(), Some(2), "stderr:\n{err}");
    assert!(err.contains(needle), "missing `{needle}` in stderr:\n{err}");
}

#[track_caller]
fn assert_ok(out: &Output) {
    assert_eq!(out.status.code(), Some(0), "stderr:\n{}", stderr(out));
}

#[test]
fn check_rejects_mirror_name_longer_than_a_file_name() {
    let name = "a".repeat(300);
    let out = check(
        "cv-name",
        "",
        &mirror(&name, r#"["bookworm"]"#, r#"["main"]"#, ""),
    );
    assert_config_error(&out, "255");
}

#[test]
fn check_accepts_mirror_name_at_the_file_name_limit() {
    let name = "a".repeat(255);
    let out = check(
        "cv-name-ok",
        "",
        &mirror(&name, r#"["bookworm"]"#, r#"["main"]"#, ""),
    );
    assert_ok(&out);
}

#[test]
fn check_rejects_path_component_longer_than_a_file_name() {
    let path = format!("mirrors/{}", "p".repeat(256));
    let out = check(
        "cv-path",
        "",
        &default_mirror(&format!("path = \"{path}\"")),
    );
    assert_config_error(&out, "255");
}

#[test]
fn check_rejects_user_agent_with_control_characters() {
    let out = check("cv-ua", r#"user_agent = "a\u0001b""#, &default_mirror(""));
    assert_config_error(&out, "user_agent");
}

#[test]
fn sync_rejects_user_agent_from_env_before_any_network_access() {
    let dir = TempDir::new("cv-ua-env");
    let cfg = write_config(&dir, "", &default_mirror(""));
    let out = run(Some(&cfg), &[("TAIN_USER_AGENT", "a\u{1}b")], &["sync"]);
    assert_config_error(&out, "TAIN_USER_AGENT");
}

#[test]
fn check_rejects_relative_keyring() {
    let out = check(
        "cv-key-rel",
        "",
        &default_mirror("[mirror.verify]\npgp = \"required\"\nkeyring = \"keys/debian.gpg\""),
    );
    assert_config_error(&out, "absolute");
}

#[test]
fn check_rejects_keyring_with_control_characters() {
    let out = check(
        "cv-key-ctl",
        "",
        &default_mirror(
            "[mirror.verify]\npgp = \"if-present\"\nkeyring = \"/etc/key\\u0007ring.gpg\"",
        ),
    );
    assert_config_error(&out, "keyring");
    assert!(!stderr(&out).contains('\u{7}'), "raw BEL in stderr");
}

#[test]
fn check_rejects_suite_nested_inside_another_suite() {
    for suites in [
        r#"["bookworm", "bookworm/updates"]"#,
        r#"["bookworm/updates", "bookworm"]"#,
    ] {
        let out = check(
            "cv-nested",
            "",
            &mirror("debian", suites, r#"["main"]"#, ""),
        );
        assert_config_error(&out, "bookworm/updates");
        assert_config_error(&out, "inside suite");
    }
}

#[test]
fn check_rejects_nesting_even_among_prefix_sharing_siblings() {
    let out = check(
        "cv-siblings",
        "",
        &mirror(
            "debian",
            r#"["stable", "stable-updates", "stable/updates"]"#,
            r#"["main"]"#,
            "",
        ),
    );
    // `stable/updates` lies inside `stable`; `stable-updates` does not.
    assert_config_error(&out, "\"stable/updates\" lies inside suite \"stable\"");
}

#[test]
fn check_accepts_sibling_suites_sharing_a_name_prefix() {
    let out = check(
        "cv-siblings-ok",
        "",
        &mirror(
            "debian",
            r#"["bookworm", "bookworm-updates", "bookworm-backports"]"#,
            r#"["main"]"#,
            "",
        ),
    );
    assert_ok(&out);
}

#[test]
fn check_rejects_url_query_without_echoing_it() {
    for url in [
        "http://127.0.0.1:1/debian?token=s3cr3t-value",
        "http://127.0.0.1:1/debian#s3cr3t-value",
    ] {
        let body = default_mirror("").replace(URL, url);
        let out = check("cv-query", "", &body);
        assert_config_error(&out, "query");
        assert!(!stderr(&out).contains("s3cr3t"), "{}", stderr(&out));
    }
}

#[test]
fn check_accepts_url_with_empty_query_marker() {
    let body = default_mirror("").replace(URL, "http://127.0.0.1:1/debian?");
    assert_ok(&check("cv-query-empty", "", &body));
}

#[test]
fn check_rejects_apt_values_outside_the_apt_character_set() {
    let cases = [
        (r#"["bookworm"]"#, r#"["main#x"]"#, "components"),
        (r#"["bookworm"]"#, r#"["con trib"]"#, "components"),
        (r#"["bookworm"]"#, r#"["non/free"]"#, "components"),
        (r#"["bookworm"]"#, r#"["main?"]"#, "components"),
        (r#"["bookworm"]"#, r#"[""]"#, "components"),
        (r#"["book worm"]"#, r#"["main"]"#, "suites"),
        (r#"["bookworm%2f"]"#, r#"["main"]"#, "suites"),
    ];
    for (suites, components, field) in cases {
        let out = check("cv-charset", "", &mirror("d", suites, components, ""));
        assert_config_error(&out, field);
    }
    let body =
        mirror("d", r#"["bookworm"]"#, r#"["main"]"#, "").replace(r#"["amd64"]"#, r#"["amd 64"]"#);
    assert_config_error(&check("cv-charset-arch", "", &body), "architectures");
    let body = mirror("d", r#"["bookworm"]"#, r#"["main"]"#, "")
        .replace(r#"["amd64"]"#, r#"["linux/amd64"]"#);
    assert_config_error(&check("cv-charset-arch", "", &body), "architectures");
}

#[test]
fn check_accepts_real_world_suite_component_and_architecture_names() {
    let mirrors = [
        // Debian, Debian security (old and new layout), Ubuntu.
        mirror(
            "debian",
            r#"["bookworm", "bookworm-updates", "bookworm-backports", "trixie-proposed-updates", "sid", "rc-buggy"]"#,
            r#"["main", "contrib", "non-free", "non-free-firmware"]"#,
            "",
        ),
        mirror(
            "debian-security",
            r#"["stretch/updates"]"#,
            r#"["main"]"#,
            "",
        ),
        mirror(
            "ubuntu",
            r#"["noble", "noble-updates", "noble-security", "noble-proposed"]"#,
            r#"["main", "restricted", "universe", "multiverse"]"#,
            "",
        ),
        // Proxmox, Docker, NodeSource, PostgreSQL, Kali.
        mirror("pve", r#"["bookworm"]"#, r#"["pve-no-subscription"]"#, ""),
        mirror("docker", r#"["bookworm"]"#, r#"["stable"]"#, ""),
        mirror("nodesource", r#"["nodistro"]"#, r#"["main"]"#, ""),
        mirror("pgdg", r#"["bookworm-pgdg"]"#, r#"["main", "14"]"#, ""),
        mirror("kali", r#"["kali-rolling"]"#, r#"["main", "non-free"]"#, ""),
        mirror("tilde", r#"["v1.0~rc1+deb12"]"#, r#"["main_x"]"#, ""),
    ];
    let body = mirrors
        .iter()
        .enumerate()
        .map(|(i, m)| m.replace(&format!("url = \"{URL}\""), &format!("url = \"{URL}{i}\"")))
        .collect::<String>()
        .replace(
            r#"architectures = ["amd64"]"#,
            r#"architectures = ["amd64", "arm64", "armhf", "i386", "ppc64el", "s390x", "hurd-i386"]"#,
        );
    assert_ok(&check("cv-real", "", &body));
}

#[test]
fn unknown_tain_variable_warns_with_the_closest_known_name() {
    let dir = TempDir::new("cv-unknown-env");
    let cfg = write_config(&dir, "", &default_mirror(""));
    let out = run(Some(&cfg), &[("TAIN_PARALEL", "4")], &["check"]);
    assert_ok(&out);
    let err = stderr(&out);
    assert!(err.contains("TAIN_PARALEL"), "{err}");
    assert!(err.contains("TAIN_PARALLEL"), "{err}");
    assert_eq!(err.matches("TAIN_PARALEL").count(), 1, "{err}");
}

#[test]
fn known_tain_variables_do_not_warn() {
    let dir = TempDir::new("cv-known-env");
    let cfg = write_config(&dir, "", &default_mirror(""));
    let out = run(
        Some(&cfg),
        &[("TAIN_PARALLEL", "4"), ("TAIN_LOG_FORMAT", "text")],
        &["check"],
    );
    assert_ok(&out);
    assert!(!stderr(&out).contains("WARN"), "{}", stderr(&out));
}

#[test]
fn empty_tain_config_is_treated_as_unset() {
    let dir = TempDir::new("cv-empty-config");
    let target = dir.path().join("target");
    let out = run(
        None,
        &[
            ("TAIN_CONFIG", ""),
            ("TAIN_URL", URL),
            ("TAIN_DISTS", "bookworm|main|amd64"),
            ("TAIN_TARGET", target.to_str().unwrap()),
        ],
        &["check"],
    );
    assert_ok(&out);
    assert!(!stderr(&out).contains("--config"), "{}", stderr(&out));
}

#[test]
fn derived_mirror_name_fits_in_a_file_name() {
    let dir = TempDir::new("cv-derived");
    let target = dir.path().join("target");
    let long_url = format!("http://127.0.0.1:1/{}", "seg/".repeat(100));
    for dists in [
        "bookworm|main|amd64",
        "bookworm|main|amd64;trixie|main|amd64",
    ] {
        let out = run(
            None,
            &[
                ("TAIN_URL", &long_url),
                ("TAIN_DISTS", dists),
                ("TAIN_TARGET", target.to_str().unwrap()),
            ],
            &["check"],
        );
        assert_ok(&out);
        let stdout = String::from_utf8_lossy(&out.stdout);
        let names: Vec<&str> = stdout
            .lines()
            .filter_map(|l| l.strip_prefix("name = \""))
            .map(|l| l.trim_end_matches('"'))
            .collect();
        assert!(!names.is_empty(), "{stdout}");
        for name in names {
            assert!(name.len() <= 255, "{} bytes: {name}", name.len());
            assert!(name.starts_with("127.0.0.1-seg-seg"), "{name}");
        }
    }
}

#[test]
fn non_unicode_tain_config_is_a_config_error() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    let out = Command::new(env!("CARGO_BIN_EXE_tain"))
        .env_clear()
        .env(
            "TAIN_CONFIG",
            OsStr::from_bytes(b"/etc/tain/\xffconfig.toml"),
        )
        .env("TAIN_URL", URL)
        .env("TAIN_DISTS", "bookworm|main|amd64")
        .arg("check")
        .output()
        .expect("spawn tain");
    assert_config_error(&out, "TAIN_CONFIG");
}

#[test]
fn check_rejects_bad_scheme_without_echoing_credentials_or_query() {
    let body =
        default_mirror("").replace(URL, "ftp://user:pw-s3cr3t@127.0.0.1:1/debian?tok=s3cr3t");
    let out = check("cv-scheme", "", &body);
    assert_config_error(&out, "\"ftp\"");
    assert!(!stderr(&out).contains("s3cr3t"), "{}", stderr(&out));
}

#[test]
fn service_link_variables_do_not_warn() {
    let dir = TempDir::new("cv-links");
    let cfg = write_config(&dir, "", &default_mirror(""));
    let out = run(
        Some(&cfg),
        &[
            ("TAIN_PORT", "tcp://10.0.0.1:80"),
            ("TAIN_PORT_80_TCP_PORT", "80"),
            ("TAIN_SERVICE_HOST", "10.0.0.1"),
        ],
        &["check"],
    );
    assert_ok(&out);
    assert!(!stderr(&out).contains("WARN"), "{}", stderr(&out));
}

#[test]
fn check_rejects_suite_part_too_long_for_its_files() {
    let suite = format!("[\"bookworm/{}\"]", "x".repeat(200));
    let out = check("cv-long-suite", "", &mirror("d", &suite, r#"["main"]"#, ""));
    assert_config_error(&out, "longer than");
}

#[test]
fn segments_error_names_the_toml_key() {
    let out = check("cv-seg", "segments_per_file = 9", &default_mirror(""));
    assert_config_error(&out, "global.segments_per_file");
}

#[test]
fn dry_run_help_matches_what_dry_run_does() {
    let out = run(None, &[], &["sync", "--help"]);
    assert_ok(&out);
    let help = String::from_utf8_lossy(&out.stdout);
    assert!(help.contains("no pool files"), "{help}");
    assert!(!help.contains("without downloading"), "{help}");
}
