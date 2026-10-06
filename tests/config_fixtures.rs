//! Acceptance tests for the documented config example and `mirrors.list`
//! importer syntax. Fixtures mirror the docs: fix code or docs, not fixtures.

use std::collections::HashMap;
use std::path::PathBuf;

use tain::config::env::ProcessEnv;
use tain::config::load::{LoadOptions, load};
use tain::config::mirrors_list;
use tain::config::model::{BackendOptions, I18nSelection, PgpMode};
use tain::config::toml as toml_source;
use tain::config::{display, env as env_mod};

const CONFIG_EXAMPLE_TOML: &str = include_str!("fixtures/config_example.toml");
const SAMPLE_MIRRORS_LIST: &str = include_str!("fixtures/old_readme_mirrors.list");

fn env_map(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect()
}

// ---------- documented TOML example ----------

#[test]
fn config_example_toml_parses() {
    let cfg = toml_source::parse(CONFIG_EXAMPLE_TOML).expect("config example must parse");
    assert_eq!(cfg.global.parallel, 16);
    assert_eq!(cfg.global.schedule.as_deref(), Some("0 2,8,14,20 * * *"));
    assert_eq!(cfg.global.log.level.as_deref(), Some("info"));
    assert_eq!(cfg.mirrors.len(), 2, "debian + proxmox");

    // debian: per-mirror pgp = required beats defaults.pgp = off
    let debian = cfg.mirrors.iter().find(|m| m.name == "debian").unwrap();
    assert_eq!(debian.verify.pgp, PgpMode::Required);
    assert!(debian.gc.enabled, "gc inherited from [defaults]");
    match &debian.backend_options {
        BackendOptions::Apt(a) => {
            assert_eq!(a.suites.len(), 3);
            assert_eq!(a.architectures, vec!["amd64", "arm64"]);
            assert_eq!(
                a.indexes.i18n,
                I18nSelection::Only(vec!["en".into(), "zh".into()])
            );
        }
    }

    // proxmox: architectures inherited from defaults
    let proxmox = cfg.mirrors.iter().find(|m| m.name == "proxmox").unwrap();
    match &proxmox.backend_options {
        BackendOptions::Apt(a) => assert_eq!(a.architectures, vec!["amd64"]),
    }
}

#[test]
fn config_example_toml_check_output_stable() {
    // `tain check` must show every documented field for every mirror.
    let cfg = toml_source::parse(CONFIG_EXAMPLE_TOML).unwrap();
    let out = display::format_config(&cfg);
    for line in [
        "[global]",
        "target = \"/data\"",
        "parallel = 16",
        "schedule = \"0 2,8,14,20 * * *\"",
        "[global.retry]",
        "count = 3",
        "index_rounds = 5",
        "log_level = \"info\"",
        // debian mirror
        "name = \"debian\"",
        "backend = \"apt\"",
        "url = \"https://deb.debian.org/debian\"",
        "suites = [\"bookworm\", \"bookworm-updates\", \"bookworm-backports\"]",
        "architectures = [\"amd64\", \"arm64\"]",
        "i18n = [\"en\", \"zh\"]",
        "pgp = \"required\"",
        "keyring = \"/usr/share/keyrings/debian-archive-keyring.gpg\"",
        "enabled = true",
        "grace_period = \"72h\"",
        // proxmox mirror
        "name = \"proxmox\"",
        "components = [\"pve-no-subscription\"]",
    ] {
        assert!(
            out.contains(line),
            "check output missing `{line}`. Full output:\n{out}"
        );
    }
}

#[test]
fn config_example_toml_check_output_round_trips() {
    // `tain check` output is valid input and re-renders byte-identically.
    let cfg = toml_source::parse(CONFIG_EXAMPLE_TOML).unwrap();
    let out = display::format_config(&cfg);
    assert!(
        !out.contains("packages ="),
        "`packages` is not a config key:\n{out}"
    );
    let reparsed = toml_source::parse(&out)
        .unwrap_or_else(|e| panic!("check output rejected as input: {e}\n---\n{out}"));
    assert_eq!(display::format_config(&reparsed), out);
}

// ---------- sample apt-mirror `mirrors.list` entries ----------

#[test]
fn sample_mirrors_list_parses_end_to_end() {
    let entries = mirrors_list::parse(SAMPLE_MIRRORS_LIST)
        .expect("every sample mirrors.list syntax must still parse");
    let debs = entries
        .iter()
        .filter(|e| matches!(e, mirrors_list::Entry::Deb(_)))
        .count();
    let paths = entries
        .iter()
        .filter(|e| matches!(e, mirrors_list::Entry::MirrorPath { .. }))
        .count();
    assert_eq!(debs, 9);
    assert_eq!(paths, 2);
}

#[test]
fn sample_bracket_arch_syntax_parsed() {
    let text = "deb [ arch=amd64,arm64 ] https://download.docker.com/linux/ubuntu/ noble stable";
    let entry = mirrors_list::parse_line(1, text).unwrap().unwrap();
    match entry {
        mirrors_list::Entry::Deb(d) => {
            assert_eq!(
                d.arch_override.as_deref(),
                Some(&["amd64".to_owned(), "arm64".to_owned()][..])
            );
        }
        _ => panic!("expected Deb entry"),
    }
}

#[test]
fn sample_mirror_path_maps_local_dir() {
    let entries = mirrors_list::parse(SAMPLE_MIRRORS_LIST).unwrap();
    let out = mirrors_list::to_toml(&entries);
    assert!(
        out.contains("path = \"docker-ubuntu\""),
        "expected docker-ubuntu path override in:\n{out}"
    );
    assert!(
        out.contains("path = \"debian\""),
        "expected debian path override in:\n{out}"
    );
}

#[test]
fn generated_toml_from_sample_mirrors_list_is_loadable() {
    // The documented migration path: import output must parse as config.
    let entries = mirrors_list::parse(SAMPLE_MIRRORS_LIST).unwrap();
    let gen_toml = mirrors_list::to_toml(&entries);
    let cfg = toml_source::parse(&gen_toml)
        .unwrap_or_else(|e| panic!("generated TOML rejected: {e}\n---\n{gen_toml}"));
    assert!(
        !cfg.mirrors.is_empty(),
        "at least one mirror should have survived"
    );
}

// ---------- legacy env-variable syntax (rejected at runtime) ----------

#[test]
fn old_env_variables_only_produce_warnings_not_config() {
    // Legacy names are never honored, only reported as warnings.
    let e = env_map(&[
        ("APTSYNC_URL", "http://download.proxmox.com/debian/pve"),
        ("APTSYNC_DISTS", "bookworm|pve-no-subscription|amd64|"),
        ("APTSYNC_UNLINK", "1"),
        ("CRON", "20 23,6,12,20 * * *"),
        ("TO", "/data"),
    ]);
    let opts = LoadOptions {
        cli_config: None,
        env: &e,
        default_config_path: None,
    };
    let err = load(opts).unwrap_err();
    assert!(matches!(err, tain::config::load::LoadError::NoSource));

    let warns = env_mod::detect_legacy(&e);
    let names: Vec<_> = warns.iter().map(|w| w.legacy).collect();
    assert!(names.contains(&"APTSYNC_URL"));
    assert!(names.contains(&"APTSYNC_DISTS"));
    assert!(names.contains(&"APTSYNC_UNLINK"));
    assert!(names.contains(&"CRON"));
    assert!(names.contains(&"TO"));
}

#[test]
fn old_tain_dists_semicolon_colon_syntax_variance() {
    // aptsync used `:` as group separator; `TAIN_DISTS` uses `;` or newline.
    let modern = env_mod::parse_dists("bookworm|main|amd64;bullseye|main|amd64").unwrap();
    assert_eq!(modern.len(), 2);

    let modern_nl = env_mod::parse_dists("bookworm|main|amd64\nbullseye|main|amd64").unwrap();
    assert_eq!(modern_nl.len(), 2);

    // `:` yields one invalid group: an error, not silent acceptance.
    assert!(env_mod::parse_dists("bookworm|main|amd64:bullseye|main|amd64").is_err());
}

// ---------- ProcessEnv smoke ----------

#[test]
fn process_env_reads_current_process() {
    let p = ProcessEnv;
    let _: &dyn env_mod::EnvSource = &p;
    let has_path = std::env::var("PATH").is_ok();
    assert_eq!(
        <ProcessEnv as env_mod::EnvSource>::get(&p, "PATH").is_some(),
        has_path
    );
}

// Keeps the `PathBuf` import used.
#[allow(dead_code)]
fn _touch(_: PathBuf) {}
