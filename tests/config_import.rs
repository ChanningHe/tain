//! `tain import mirrors-list` through the real binary: apt's tokenizing and
//! option rules, warnings, and the promise that the printed TOML always
//! passes `tain check`.

use std::path::Path;
use std::process::{Command, Output};

use tain::config::model::MAX_FILE_NAME_BYTES;

mod common;
use common::TempDir;

const FINGERPRINT_V4: &str = "0123456789ABCDEF0123456789ABCDEF01234567";
const FINGERPRINT_V5: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

struct Imported {
    status: Option<i32>,
    toml: String,
    stderr: String,
}

fn tain(args: &[&str], path: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_tain"))
        .env_clear()
        .args(args)
        .arg(path)
        .output()
        .expect("spawn tain")
}

fn import(dir: &TempDir, list: &str) -> Imported {
    let path = dir.path().join("mirror.list");
    std::fs::write(&path, list).unwrap();
    let out = tain(&["import", "mirrors-list"], &path);
    Imported {
        status: out.status.code(),
        toml: String::from_utf8(out.stdout).unwrap(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

/// Import, then run `tain check` on the result; both must succeed.
fn import_and_check(dir: &TempDir, list: &str) -> Imported {
    let imported = import(dir, list);
    assert_eq!(
        imported.status,
        Some(0),
        "import failed:\n{}",
        imported.stderr
    );
    let cfg = dir.path().join("tain.toml");
    std::fs::write(&cfg, &imported.toml).unwrap();
    let out = tain(&["check", "--config"], &cfg);
    assert_eq!(
        out.status.code(),
        Some(0),
        "`tain check` rejects the import:\n{}\n---\n{}",
        String::from_utf8_lossy(&out.stderr),
        imported.toml
    );
    imported
}

fn values_of<'a>(toml: &'a str, key: &str) -> Vec<&'a str> {
    let prefix = format!("{key} = ");
    toml.lines()
        .filter_map(|l| l.strip_prefix(prefix.as_str()))
        .collect()
}

fn unquote(v: &str) -> &str {
    v.trim_matches('"')
}

fn mirror_count(toml: &str) -> usize {
    toml.matches("[[mirror]]").count()
}

#[cfg(feature = "pgp")]
#[test]
fn same_url_with_different_keyrings_warns_about_duplicate_pool() {
    let dir = TempDir::new("import-keyrings");
    let got = import_and_check(
        &dir,
        "deb [signed-by=/a.gpg] http://deb.debian.org/debian bookworm main\n\
         deb [signed-by=/b.gpg] http://deb.debian.org/debian bookworm-updates main\n",
    );
    assert_eq!(mirror_count(&got.toml), 2, "{}", got.toml);
    for needle in ["deb.debian.org-debian", "deb.debian.org-debian-2", "pool"] {
        assert!(got.stderr.contains(needle), "{needle}:\n{}", got.stderr);
    }
    let comment = "# mirrors `deb.debian.org-debian`, `deb.debian.org-debian-2` use the same URL";
    assert_eq!(got.toml.matches(comment).count(), 2, "{}", got.toml);
}

#[test]
fn single_mirror_per_url_produces_no_duplicate_warning() {
    let dir = TempDir::new("import-one-group");
    let got = import_and_check(
        &dir,
        "deb http://x/debian bookworm main\n\
         deb http://x/debian trixie main\n",
    );
    assert!(!got.stderr.contains("pool"), "{}", got.stderr);
}

#[test]
fn nested_suites_of_one_url_become_separate_mirrors() {
    let dir = TempDir::new("import-nested");
    let got = import_and_check(
        &dir,
        "deb http://x/debian stable main\n\
         deb http://x/debian stable/updates main\n\
         deb http://x/debian stable/updates/extra main\n",
    );
    assert_eq!(mirror_count(&got.toml), 3, "{}", got.toml);
    assert_eq!(
        values_of(&got.toml, "suites"),
        vec![
            "[\"stable\"]",
            "[\"stable/updates\"]",
            "[\"stable/updates/extra\"]"
        ]
    );
    assert!(got.stderr.contains("use the same URL"), "{}", got.stderr);
}

#[test]
fn only_ascii_whitespace_separates_tokens() {
    let dir = TempDir::new("import-unicode-space");
    let got = import_and_check(
        &dir,
        "deb http://x.org/d bookworm main\u{3000}contrib\n\
         deb http://y.org/d bookworm main\u{85}contrib\n\
         deb http://z.org/d\x0bbookworm main\n\
         deb\thttp://w.org/d\x0cbookworm main\r\n",
    );
    assert!(!got.toml.contains("\"contrib\""), "{}", got.toml);
    assert!(got.toml.contains("# Not converted"), "{}", got.toml);
    let urls = values_of(&got.toml, "url");
    assert_eq!(
        urls,
        vec!["\"http://z.org/d\"", "\"http://w.org/d\""],
        "{}",
        got.toml
    );
    assert!(
        got.stderr.contains("line 1 not converted"),
        "{}",
        got.stderr
    );
}

/// A `signed-by` that is not one keyring file must not turn into a mirror
/// that skips signature checks: the line is not converted.
#[cfg(feature = "pgp")]
#[test]
fn signed_by_that_is_not_one_keyring_file_skips_the_line() {
    let dir = TempDir::new("import-bad-signed-by");
    for (value, reason) in [
        (FINGERPRINT_V4.to_owned(), "fingerprints"),
        (FINGERPRINT_V5.to_owned(), "fingerprints"),
        (format!("{FINGERPRINT_V4},/k.gpg"), "fingerprints"),
        (format!("{FINGERPRINT_V4}!"), "fingerprints"),
        ("/a.gpg,/b.gpg".to_owned(), "several keyrings"),
        ("keys.gpg".to_owned(), "absolute"),
        ("./k.gpg".to_owned(), "absolute"),
    ] {
        let got = import_and_check(
            &dir,
            &format!(
                "deb [signed-by={value}] http://x bookworm main\n\
                 deb http://y bookworm main\n"
            ),
        );
        assert_eq!(
            values_of(&got.toml, "url"),
            vec!["\"http://y/\""],
            "{value}"
        );
        assert!(
            got.toml
                .contains(&format!("# line 1: deb [signed-by={value}] http://x")),
            "{}",
            got.toml
        );
        assert!(
            got.stderr.contains("line 1 not converted"),
            "{}",
            got.stderr
        );
        assert!(got.stderr.contains(reason), "{value}: {}", got.stderr);
    }
}

#[cfg(feature = "pgp")]
#[test]
fn absolute_keyring_path_is_applied() {
    let dir = TempDir::new("import-abs-keyring");
    let got = import_and_check(&dir, "deb [signed-by=/etc/k.gpg] http://x bookworm main\n");
    assert_eq!(values_of(&got.toml, "keyring"), vec!["\"/etc/k.gpg\""]);
    assert_eq!(values_of(&got.toml, "pgp"), vec!["\"required\""]);
    assert!(got.stderr.is_empty(), "{}", got.stderr);
}

#[cfg(not(feature = "pgp"))]
#[test]
fn signed_by_without_pgp_support_skips_the_line_with_a_warning() {
    let dir = TempDir::new("import-no-pgp");
    let got = import_and_check(&dir, "deb [signed-by=/etc/k.gpg] http://x bookworm main\n");
    assert_eq!(mirror_count(&got.toml), 0, "{}", got.toml);
    assert!(
        got.stderr.contains("line 1 not converted"),
        "{}",
        got.stderr
    );
    assert!(got.stderr.contains("OpenPGP"), "{}", got.stderr);
}

#[test]
fn options_that_do_not_affect_the_mirror_are_ignored_with_a_warning() {
    let dir = TempDir::new("import-ignored-options");
    let got = import_and_check(
        &dir,
        "deb [target=Contents-deb lang=de check-valid-until=no] http://a bookworm main\n\
         deb [target+=Contents-udeb lang-=fr arch=amd64 pdiffs=no] http://b bookworm main\n\
         deb [trusted=yes by-hash=force] http://c bookworm main\n",
    );
    assert_eq!(mirror_count(&got.toml), 3, "{}", got.toml);
    for line in 1..=3 {
        let needle = format!("line {line}: options ignored");
        assert!(got.stderr.contains(&needle), "{needle}:\n{}", got.stderr);
        assert!(got.toml.contains(&format!("# {needle}")), "{}", got.toml);
    }
    assert!(
        got.stderr.contains("check-valid-until=no"),
        "{}",
        got.stderr
    );
}

#[test]
fn options_tain_cannot_honour_skip_only_their_line() {
    let dir = TempDir::new("import-unsupported-options");
    let got = import_and_check(
        &dir,
        "deb [snapshot=20240101T000000Z] http://a bookworm main\n\
         deb [inrelease-path=x/InRelease] http://b bookworm main\n\
         deb [tenderloin=yes] http://c bookworm main\n\
         deb [arch+=arm64] http://d bookworm main\n\
         deb [signed-by+=/k.gpg] http://e bookworm main\n\
         deb http://f bookworm main\n",
    );
    assert_eq!(
        values_of(&got.toml, "url"),
        vec!["\"http://f/\""],
        "{}",
        got.toml
    );
    for (line, needle) in [
        (1, "snapshot="),
        (2, "inrelease-path="),
        (3, "tenderloin="),
        (4, "arch="),
        (5, "signed-by+="),
    ] {
        let prefix = format!("line {line} not converted");
        assert!(got.stderr.contains(&prefix), "{prefix}:\n{}", got.stderr);
        assert!(got.stderr.contains(needle), "{needle}:\n{}", got.stderr);
    }
}

#[test]
fn arch_edits_that_remove_every_architecture_skip_the_line() {
    let dir = TempDir::new("import-arch-empty");
    let got = import_and_check(
        &dir,
        "deb [arch=amd64 arch-=amd64] http://x/a bookworm main\n\
         deb-arm64 [arch-=arm64] http://x/b bookworm main\n\
         deb [arch=arm64] http://x/c bookworm main\n",
    );
    assert_eq!(
        values_of(&got.toml, "url"),
        vec!["\"http://x/c\""],
        "{}",
        got.toml
    );
    assert!(!got.toml.contains("[defaults]"), "{}", got.toml);
    for line in [1, 2] {
        let needle = format!("line {line} not converted");
        assert!(got.stderr.contains(&needle), "{needle}:\n{}", got.stderr);
    }
}

/// apt would check these lines against its trusted keyring; tain cannot,
/// so it says so instead of guessing a keyring.
#[test]
fn mirrors_without_signed_by_are_marked_unverified() {
    let dir = TempDir::new("import-unverified");
    let got = import_and_check(
        &dir,
        "deb http://x/a bookworm main\n\
         deb http://x/b bookworm main\n",
    );
    assert_eq!(
        got.toml.matches("# Signatures are not verified").count(),
        2,
        "{}",
        got.toml
    );
    assert!(values_of(&got.toml, "keyring").is_empty(), "{}", got.toml);
    let summary: Vec<&str> = got
        .stderr
        .lines()
        .filter(|l| l.contains("do not verify signatures"))
        .collect();
    assert_eq!(summary.len(), 1, "{}", got.stderr);
    assert!(summary[0].contains("`x-a`, `x-b`"), "{}", summary[0]);
}

#[cfg(feature = "pgp")]
#[test]
fn signed_mirrors_carry_no_unverified_note() {
    let dir = TempDir::new("import-verified");
    let got = import_and_check(
        &dir,
        "deb [signed-by=/etc/k.gpg] http://x/a bookworm main\n",
    );
    assert!(!got.toml.contains("not verified"), "{}", got.toml);
    assert!(!got.stderr.contains("verify signatures"), "{}", got.stderr);
}

#[test]
fn arch_edits_next_to_an_arch_list_are_applied() {
    let dir = TempDir::new("import-arch-edits");
    let got = import_and_check(
        &dir,
        "deb [arch=amd64,i386 arch+=arm64 arch-=i386] http://x bookworm main\n",
    );
    assert_eq!(
        values_of(&got.toml, "architectures"),
        vec!["[\"amd64\", \"arm64\"]"],
        "{}",
        got.toml
    );
}

#[test]
fn malformed_options_fail_the_import() {
    let dir = TempDir::new("import-malformed-options");
    for line in [
        "deb [arch] http://x bookworm main\n",
        "deb [=x] http://x bookworm main\n",
        "deb [arch=] http://x bookworm main\n",
        "deb [arch=amd64 http://x bookworm main\n",
    ] {
        let got = import(&dir, line);
        assert_eq!(got.status, Some(2), "{line}{}", got.stderr);
    }
}

#[test]
fn invalid_component_is_dropped_and_the_line_kept() {
    let dir = TempDir::new("import-drop-component");
    let got = import_and_check(
        &dir,
        "deb http://x/debian bookworm main main/debian-installer contrib\n",
    );
    assert_eq!(
        values_of(&got.toml, "components"),
        vec!["[\"main\", \"contrib\"]"],
        "{}",
        got.toml
    );
    let needle = "line 1: component `main/debian-installer` dropped";
    assert!(got.stderr.contains(needle), "{}", got.stderr);
    assert!(got.stderr.contains("debian_installer"), "{}", got.stderr);
    assert!(got.toml.contains(&format!("# {needle}")), "{}", got.toml);
}

#[test]
fn ipv6_url_is_not_mistaken_for_options() {
    let dir = TempDir::new("import-ipv6");
    let got = import_and_check(&dir, "deb http://[2001:db8::1]:8080/debian bookworm main\n");
    assert_eq!(
        values_of(&got.toml, "url"),
        vec!["\"http://[2001:db8::1]:8080/debian\""],
        "{}",
        got.toml
    );
}

#[test]
fn long_url_path_yields_names_within_the_file_name_limit() {
    let dir = TempDir::new("import-long-name");
    let long = "p".repeat(300);
    let got = import_and_check(
        &dir,
        &format!(
            "deb http://x.example/{long}a bookworm main\n\
             deb http://x.example/{long}b bookworm main\n\
             deb https://x.example/{long}a bookworm main\n"
        ),
    );
    let names: Vec<&str> = values_of(&got.toml, "name")
        .into_iter()
        .map(unquote)
        .collect();
    assert_eq!(names.len(), 3, "{}", got.toml);
    for n in &names {
        assert!(n.len() <= MAX_FILE_NAME_BYTES, "{} bytes: {n}", n.len());
        assert!(!n.ends_with('-'), "{n}");
    }
    assert_ne!(names[0], names[1]);
    assert_ne!(names[1], names[2]);
    assert_ne!(names[0], names[2]);
}

/// A URL query or fragment is never sent upstream, so such lines are not
/// converted rather than silently changed.
#[test]
fn url_with_query_or_fragment_is_not_converted() {
    let dir = TempDir::new("import-query");
    let got = import_and_check(
        &dir,
        "deb http://x/a?token=1 bookworm main\n\
         deb http://x/b#frag bookworm main\n\
         deb http://x/c bookworm main\n",
    );
    assert_eq!(
        values_of(&got.toml, "url"),
        vec!["\"http://x/c\""],
        "{}",
        got.toml
    );
    assert!(
        got.stderr.contains("line 1 not converted"),
        "{}",
        got.stderr
    );
    assert!(
        got.stderr.contains("line 2 not converted"),
        "{}",
        got.stderr
    );
}

#[test]
fn names_outside_the_apt_character_set_are_not_converted() {
    let dir = TempDir::new("import-charset");
    let got = import_and_check(
        &dir,
        "deb http://x/a bookworm main#x\n\
         deb [arch=am%64] http://x/b bookworm main\n\
         deb http://x/c book?worm main\n\
         deb http://x/d stable/updates main contrib non-free-firmware\n",
    );
    assert_eq!(
        values_of(&got.toml, "url"),
        vec!["\"http://x/d\""],
        "{}",
        got.toml
    );
}

fn property_corpus() -> Vec<String> {
    let long = "seg/".repeat(80);
    let urls = [
        "http://deb.debian.org/debian".to_owned(),
        "http://deb.debian.org/debian/".to_owned(),
        format!("http://h.example/{long}"),
        format!("https://h.example/{long}x"),
        "http://u@h.example/x?q=1".to_owned(),
        "http://h.example/\u{1}c".to_owned(),
        "http://[::1]:8080/d".to_owned(),
    ];
    let options = [
        String::new(),
        format!("[signed-by={FINGERPRINT_V4}] "),
        format!("[signed-by={FINGERPRINT_V5},/k.gpg] "),
        "[signed-by=/etc/k.gpg arch=amd64,arm64] ".to_owned(),
        "[signed-by=/etc/j.gpg arch+=i386 trusted=yes] ".to_owned(),
        "[signed-by=rel.gpg target+=x lang-=y] ".to_owned(),
        "[snapshot=now arch=amd64 arch-=amd64] ".to_owned(),
    ];
    let tails = [
        "bookworm main",
        "stable main contrib",
        "stable/updates main",
        "stable/updates/x main main/debian-installer",
        "./",
        "bookworm ma#in",
    ];
    let mut lines = vec!["mirror_path http://h.example/ h".to_owned()];
    for (i, url) in urls.iter().enumerate() {
        for (j, opt) in options.iter().enumerate() {
            for k in 0..3 {
                let tail = tails[(i + j + k) % tails.len()];
                lines.push(format!("deb {opt}{url} {tail}"));
                lines.push(format!("deb-src {opt}{url} {tail}"));
            }
        }
    }
    lines
}

/// Every combination of awkward inputs converts into a config `tain check`
/// accepts, with names, keyrings and URLs inside the limits it enforces.
#[test]
fn import_output_always_passes_check() {
    let dir = TempDir::new("import-property");
    let mut list = property_corpus().join("\n");
    list.push('\n');
    let got = import_and_check(&dir, &list);
    assert!(mirror_count(&got.toml) > 5, "{}", got.toml);
    for name in values_of(&got.toml, "name") {
        assert!(unquote(name).len() <= MAX_FILE_NAME_BYTES, "{name}");
    }
    for keyring in values_of(&got.toml, "keyring") {
        assert!(unquote(keyring).starts_with('/'), "{keyring}");
        assert!(!keyring.contains(','), "{keyring}");
    }
    for url in values_of(&got.toml, "url") {
        assert!(!url.contains('?') && !url.contains('#'), "{url}");
    }
    assert!(!got.toml.chars().any(|c| c.is_control() && c != '\n'));
}

/// A line with `signed-by` either becomes a mirror that requires signatures
/// or is not converted; never a mirror that skips the check.
#[test]
fn signed_lines_never_become_unverified_mirrors() {
    let dir = TempDir::new("import-signed-property");
    for line in property_corpus()
        .iter()
        .filter(|l| l.contains("signed-by="))
    {
        let got = import_and_check(&dir, &format!("{line}\n"));
        let mirrors = mirror_count(&got.toml);
        if cfg!(feature = "pgp") && mirrors > 0 {
            assert_eq!(values_of(&got.toml, "pgp"), vec!["\"required\""], "{line}");
            assert_eq!(values_of(&got.toml, "keyring").len(), 1, "{line}");
        } else {
            assert_eq!(mirrors, 0, "{line}\n{}", got.toml);
            assert!(got.stderr.contains("not converted"), "{line}");
        }
    }
}
