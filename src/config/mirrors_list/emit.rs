//! TOML emission for `tain import mirrors-list`: group lines into mirrors,
//! name them, apply `mirror_path`, and comment out what tain cannot mirror.
//! Invariant: the output always passes `tain check`.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use url::Url;

use super::mirror_paths::{self, canonical};
use super::{DebEntry, DebKind, Entry};
use crate::backends::apt::unsafe_suite_reason;
use crate::config::env::derive_name_from_url;
use crate::config::model::{has_control_chars, is_flat_suite, normalize_mirror_path};

/// Default architecture for lines that declare none (also `[defaults]`).
const DEFAULT_ARCH: &str = "amd64";

/// Used when a URL slug is not a usable directory name.
const FALLBACK_NAME: &str = "mirror";

/// Why a line cannot be converted, or `None` if it can.
#[must_use]
pub fn skip_reason(d: &DebEntry) -> Option<&'static str> {
    if is_flat_suite(&d.suite) {
        Some("flat repositories are not supported yet")
    } else if !matches!(d.url.scheme(), "http" | "https") {
        Some("only http and https URLs are supported")
    } else if d.components.is_empty() {
        Some("a dists-style suite needs at least one component")
    } else if std::iter::once(&d.suite)
        .chain(&d.components)
        .chain(d.arch_override.iter().flatten())
        .any(|s| has_control_chars(s))
    {
        Some("a suite, component or architecture contains control characters")
    } else if unsafe_suite_reason(&d.url, &d.suite).is_some() {
        Some("the suite does not stay inside the mirror")
    } else {
        None
    }
}

/// Lines that `to_toml` emits only as comments, with the reason.
pub fn skipped_entries(entries: &[Entry]) -> impl Iterator<Item = (&DebEntry, &'static str)> {
    entries.iter().filter_map(|e| match e {
        Entry::Deb(d) => skip_reason(d).map(|r| (d, r)),
        Entry::MirrorPath { .. } => None,
    })
}

/// One output `[[mirror]]`: every line for one URL + keyring.
#[derive(Debug)]
struct Group {
    url: Url,
    keyring: Option<PathBuf>,
    /// Earliest source line, for output order.
    first_line: usize,
    arch: BTreeSet<String>,
    /// A binary line without `[arch=]`, which implies `DEFAULT_ARCH`.
    any_arch_unset: bool,
    include_source: bool,
    suites: Vec<String>,
    components: Vec<String>,
}

impl Group {
    fn new(d: &DebEntry) -> Self {
        Self {
            url: canonical(&d.url),
            keyring: d.keyring.clone(),
            first_line: d.line,
            arch: BTreeSet::new(),
            any_arch_unset: false,
            include_source: false,
            suites: Vec::new(),
            components: Vec::new(),
        }
    }

    fn add(&mut self, d: &DebEntry) {
        self.first_line = self.first_line.min(d.line);
        push_unique(&mut self.suites, &d.suite);
        for c in &d.components {
            push_unique(&mut self.components, c);
        }
        match (d.kind, &d.arch_override) {
            // Sources are arch-independent; `[arch=]` on deb-src is irrelevant.
            (DebKind::Source, _) => self.include_source = true,
            (DebKind::Binary, Some(archs)) => self.arch.extend(archs.iter().cloned()),
            (DebKind::Binary, None) => self.any_arch_unset = true,
        }
    }

    /// Explicit architectures, or `None` to inherit `[defaults]`.
    fn architectures(&self) -> Option<Vec<String>> {
        if self.arch.is_empty() {
            return None;
        }
        let mut arch = self.arch.clone();
        if self.any_arch_unset {
            arch.insert(DEFAULT_ARCH.to_owned());
        }
        Some(arch.into_iter().collect())
    }
}

fn push_unique(v: &mut Vec<String>, s: &str) {
    if !v.iter().any(|x| x == s) {
        v.push(s.to_owned());
    }
}

/// Group lines by URL + keyring, unioning architectures: tain mirrors the
/// suites × components × arches product, and two mirrors of one URL would
/// only fight over the same tree. `deb-src` joins the binary group of its
/// URL (same keyring preferred), whatever its options say.
fn group_lines(debs: &[&DebEntry]) -> Vec<Group> {
    let mut groups: Vec<Group> = Vec::new();
    let binaries = debs.iter().filter(|d| d.kind == DebKind::Binary);
    let sources = debs.iter().filter(|d| d.kind == DebKind::Source);
    for d in binaries.chain(sources) {
        let url = canonical(&d.url);
        let exact = groups
            .iter()
            .position(|g| g.url == url && g.keyring == d.keyring);
        let idx = match d.kind {
            DebKind::Binary => exact,
            DebKind::Source => exact.or_else(|| groups.iter().position(|g| g.url == url)),
        };
        let group = match idx {
            Some(i) => &mut groups[i],
            None => {
                groups.push(Group::new(d));
                groups.last_mut().expect("just pushed")
            }
        };
        group.add(d);
    }
    groups.sort_by_key(|g| g.first_line);
    groups
}

/// Unique names from the URL slug: a taken name gets the first free `-2`,
/// `-3`, … suffix, checked against every name generated so far.
fn group_names(groups: &[Group]) -> Vec<String> {
    let mut used: BTreeSet<String> = BTreeSet::new();
    groups
        .iter()
        .map(|g| {
            let slug = derive_name_from_url(&g.url);
            // The name doubles as the default path, so it must be one.
            let base = if normalize_mirror_path(Path::new(&slug)).is_ok() {
                slug
            } else {
                FALLBACK_NAME.to_owned()
            };
            let name = std::iter::once(base.clone())
                .chain((2..).map(|n| format!("{base}-{n}")))
                .find(|n| !used.contains(n))
                .expect("unbounded candidates");
            used.insert(name.clone());
            name
        })
        .collect()
}

/// Converted TOML plus one warning per line that was not (fully) applied.
#[derive(Debug)]
pub struct Conversion {
    pub toml: String,
    pub warnings: Vec<String>,
}

/// [`convert`] without the warnings.
#[must_use]
pub fn to_toml(entries: &[Entry]) -> String {
    convert(entries).toml
}

/// Emit TOML: one `[[mirror]]` per URL + keyring (see `group_lines`), with
/// `mirror_path` applied only where it yields a valid, unshared directory.
/// Anything not applied is both a TOML comment and a warning.
#[must_use]
pub fn convert(entries: &[Entry]) -> Conversion {
    let debs: Vec<&DebEntry> = entries
        .iter()
        .filter_map(|e| match e {
            // `write_skipped_block` keeps unsupported lines as comments.
            Entry::Deb(d) if skip_reason(d).is_none() => Some(d),
            _ => None,
        })
        .collect();
    let has_mirror_paths = entries
        .iter()
        .any(|e| matches!(e, Entry::MirrorPath { .. }));

    let groups = group_lines(&debs);
    let names = group_names(&groups);
    let urls: Vec<&Url> = groups.iter().map(|g| &g.url).collect();
    let paths = mirror_paths::resolve(entries, &urls, &names);

    let mut warnings: Vec<String> = skipped_entries(entries)
        .map(|(d, reason)| format!("line {} not converted: {reason}", d.line))
        .collect();
    warnings.extend(paths.unused.iter().cloned());
    warnings.extend(
        paths
            .per_mirror
            .iter()
            .filter_map(|p| p.as_ref().and_then(|r| r.as_ref().err()).cloned()),
    );

    let any_no_arch = groups.iter().any(|g| g.architectures().is_none());
    let mut out = String::new();
    out.push_str("# Generated by `tain import mirrors-list` — review before use.\n");
    out.push_str("# See docs/configuration.md in the tain repository for the full schema.\n\n");
    out.push_str("[global]\n");
    if has_mirror_paths {
        out.push_str("# mirror_path lines had no direct TOML equivalent; the paths were\n");
        out.push_str("# applied to matching mirrors below where possible.\n");
    }
    for msg in &paths.unused {
        writeln!(out, "# {}", comment_safe(msg)).unwrap();
    }
    out.push('\n');
    if any_no_arch {
        out.push_str("# One or more `deb` lines in the source file did not declare\n");
        out.push_str("# `[arch=...]`; amd64 is used as a safe default. Adjust as needed.\n");
        out.push_str("[defaults]\n");
        out.push_str("architectures = [\"amd64\"]\n\n");
    }

    for ((g, name), path) in groups.iter().zip(&names).zip(paths.per_mirror) {
        write_mirror(&mut out, g, name, path);
    }

    write_skipped_block(&mut out, entries);
    Conversion {
        toml: out,
        warnings,
    }
}

fn write_mirror(out: &mut String, g: &Group, name: &str, path: Option<Result<PathBuf, String>>) {
    writeln!(out, "[[mirror]]").unwrap();
    writeln!(out, "name = {}", toml_string(name)).unwrap();
    writeln!(out, "url = {}", toml_string(g.url.as_str())).unwrap();
    match path {
        Some(Ok(p)) => writeln!(out, "path = {}", toml_string(&p.to_string_lossy())).unwrap(),
        Some(Err(msg)) => writeln!(out, "# {}", comment_safe(&msg)).unwrap(),
        None => {}
    }
    writeln!(out, "suites = {}", toml_string_list(&g.suites)).unwrap();
    writeln!(out, "components = {}", toml_string_list(&g.components)).unwrap();
    if let Some(arch) = g.architectures() {
        writeln!(out, "architectures = {}", toml_string_list(&arch)).unwrap();
    }
    if g.include_source {
        writeln!(out, "[mirror.indexes]").unwrap();
        writeln!(out, "sources = true").unwrap();
    }
    if let Some(kr) = &g.keyring {
        let kr = kr.to_string_lossy();
        if cfg!(feature = "pgp") {
            writeln!(out, "[mirror.verify]").unwrap();
            writeln!(out, "pgp = \"required\"").unwrap();
            writeln!(out, "keyring = {}", toml_string(&kr)).unwrap();
        } else {
            writeln!(
                out,
                "# signed-by=`{}` not applied: this tain build has no OpenPGP support",
                comment_safe(&kr)
            )
            .unwrap();
        }
    }
    out.push('\n');
}

fn write_skipped_block(out: &mut String, entries: &[Entry]) {
    let mut by_reason: BTreeMap<&str, Vec<&DebEntry>> = BTreeMap::new();
    for (d, reason) in skipped_entries(entries) {
        by_reason.entry(reason).or_default().push(d);
    }
    for (reason, lines) in by_reason {
        writeln!(out, "# Not converted: {reason}.").unwrap();
        for d in lines {
            writeln!(out, "# line {}: {}", d.line, comment_safe(&d.source)).unwrap();
        }
    }
}

/// TOML comments may not contain control characters other than tab.
fn comment_safe(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() && c != '\t' { '?' } else { c })
        .collect()
}

/// TOML basic string; every control character is escaped.
fn toml_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => write!(out, "\\u{:04X}", u32::from(c)).unwrap(),
            _ => out.push(c),
        }
    }
    out.push('"');
    out
}

fn toml_string_list(v: &[String]) -> String {
    let items: Vec<String> = v.iter().map(|s| toml_string(s)).collect();
    format!("[{}]", items.join(", "))
}

#[cfg(test)]
mod tests {
    use super::super::parse;
    use super::*;
    use crate::config::Config;
    use crate::config::load::{LoadOptions, load};
    use crate::config::model::{AptOptions, BackendOptions, MirrorConfig};
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn parse_ok(s: &str) -> Vec<Entry> {
        parse(s).unwrap()
    }

    /// Convert, then load the result exactly as `tain check` would.
    fn import(text: &str) -> (String, Config) {
        static N: AtomicUsize = AtomicUsize::new(0);
        let out = to_toml(&parse_ok(text));
        let path = std::env::temp_dir().join(format!(
            "tain-import-{}-{}.toml",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&path, &out).unwrap();
        let env: HashMap<String, String> = HashMap::new();
        let res = load(LoadOptions {
            cli_config: Some(&path),
            env: &env,
            default_config_path: None,
        });
        std::fs::remove_file(&path).unwrap();
        let (cfg, _) = res.unwrap_or_else(|e| panic!("`check` rejects import: {e}\n---\n{out}"));
        (out, cfg)
    }

    fn apt(m: &MirrorConfig) -> &AptOptions {
        match &m.backend_options {
            BackendOptions::Apt(a) => a,
        }
    }

    #[test]
    fn merges_same_url_arch_keyring_into_one_mirror() {
        let text = "deb http://deb.debian.org/debian bookworm main contrib\n\
                    deb http://deb.debian.org/debian bookworm-updates main\n";
        let (out, _) = import(text);
        assert_eq!(out.matches("[[mirror]]").count(), 1);
        assert!(out.contains("suites = [\"bookworm\", \"bookworm-updates\"]"));
        assert!(out.contains("components = [\"main\", \"contrib\"]"));
    }

    #[test]
    fn different_url_separate_mirrors() {
        let text = "deb http://a.example bookworm main\n\
                    deb http://b.example bookworm main\n";
        let (_, cfg) = import(text);
        assert_eq!(cfg.mirrors.len(), 2);
    }

    #[test]
    fn deb_and_debsrc_merge_and_enable_sources() {
        let text = "deb http://x bookworm main\n\
                    deb-src http://x bookworm main\n";
        let (out, cfg) = import(text);
        assert_eq!(cfg.mirrors.len(), 1);
        assert!(out.contains("[mirror.indexes]\nsources = true"), "{out}");
    }

    #[test]
    fn flat_suite_detection_follows_apt_rules() {
        for s in ["./", ".", "stable/", "repo/./"] {
            assert!(is_flat_suite(s), "{s}");
        }
        for s in ["bookworm", "stable/updates"] {
            assert!(!is_flat_suite(s), "{s}");
        }
    }

    #[test]
    fn import_comments_out_flat_lines() {
        let lines = [
            "deb https://example.com/repo ./",
            "deb https://example.com/repo .",
            "deb [arch=amd64] https://example.com/apt stable/",
            "deb https://example.com/apt repo/./",
        ];
        let (out, cfg) = import(&lines.join("\n"));
        assert!(cfg.mirrors.is_empty(), "{out}");
        assert!(
            out.contains("# Not converted: flat repositories are not supported yet.\n"),
            "{out}"
        );
        for (idx, line) in lines.iter().enumerate() {
            let commented = format!("# line {}: {line}\n", idx + 1);
            assert!(out.contains(&commented), "missing `{commented}`:\n{out}");
        }
    }

    #[test]
    fn import_with_flat_line_keeps_other_mirrors_loadable() {
        let text = "deb http://deb.debian.org/debian bookworm main\n\
                    deb https://example.com/repo ./\n\
                    deb https://example.com/repo bookworm main\n";
        let entries = parse_ok(text);
        let skipped: Vec<usize> = skipped_entries(&entries).map(|(d, _)| d.line).collect();
        assert_eq!(skipped, vec![2]);
        let (out, cfg) = import(text);
        assert!(
            out.contains("# line 2: deb https://example.com/repo ./\n"),
            "{out}"
        );
        assert_eq!(cfg.mirrors.len(), 2);
        for m in &cfg.mirrors {
            assert_eq!(apt(m).suites, vec!["bookworm".to_owned()]);
        }
    }

    #[test]
    fn unsupported_lines_are_commented_with_their_reason() {
        let text = "deb ftp://ftp.example/debian bookworm main\n\
                    deb file:///srv/debian bookworm main\n\
                    deb http://x/debian ../../etc main\n\
                    deb http://x/debian bookworm\n\
                    deb http://x/debian trixie main\n";
        let (out, cfg) = import(text);
        assert_eq!(cfg.mirrors.len(), 1, "{out}");
        assert_eq!(apt(&cfg.mirrors[0]).suites, vec!["trixie"]);
        for needle in [
            "# Not converted: only http and https URLs are supported.\n\
             # line 1: deb ftp://ftp.example/debian bookworm main\n\
             # line 2: deb file:///srv/debian bookworm main\n",
            "# Not converted: the suite does not stay inside the mirror.\n\
             # line 3: deb http://x/debian ../../etc main\n",
            "# Not converted: a dists-style suite needs at least one component.\n\
             # line 4: deb http://x/debian bookworm\n",
        ] {
            assert!(out.contains(needle), "missing:\n{needle}\n---\n{out}");
        }
    }

    #[cfg(feature = "pgp")]
    #[test]
    fn keyring_emits_verify_block_with_required_pgp() {
        let (out, cfg) = import("deb [signed-by=/etc/keys.gpg] http://x bookworm main\n");
        assert!(
            out.contains("[mirror.verify]\npgp = \"required\"\nkeyring = \"/etc/keys.gpg\""),
            "{out}"
        );
        assert_eq!(
            cfg.mirrors[0].verify.pgp,
            crate::config::model::PgpMode::Required
        );
    }

    #[cfg(not(feature = "pgp"))]
    #[test]
    fn keyring_is_a_comment_without_pgp_feature() {
        let (out, _) = import("deb [signed-by=/etc/keys.gpg] http://x bookworm main\n");
        assert!(!out.contains("[mirror.verify]"), "{out}");
        assert!(out.contains("no OpenPGP support"), "{out}");
    }

    #[test]
    fn same_url_arch_lines_and_deb_src_merge_into_one_mirror() {
        let text = "mirror_path http://x/debian debian\n\
                    deb [arch=amd64] http://x/debian bookworm main\n\
                    deb [arch=arm64] http://x/debian bookworm-updates main contrib\n\
                    deb-src [arch=amd64] http://x/debian bookworm main\n";
        let (out, cfg) = import(text);
        assert_eq!(cfg.mirrors.len(), 1, "{out}");
        let m = &cfg.mirrors[0];
        assert_eq!(m.path, PathBuf::from("debian"));
        let a = apt(m);
        assert_eq!(a.architectures, vec!["amd64", "arm64"]);
        assert_eq!(a.suites, vec!["bookworm", "bookworm-updates"]);
        assert_eq!(a.components, vec!["main", "contrib"]);
        assert!(a.indexes.sources);
    }

    #[test]
    fn deb_src_before_binary_line_still_merges() {
        let text = "deb-src http://x bookworm main\n\
                    deb [arch=arm64 signed-by=/k.gpg] http://x bookworm main\n";
        let (out, cfg) = import(text);
        assert_eq!(cfg.mirrors.len(), 1, "{out}");
        assert!(apt(&cfg.mirrors[0]).indexes.sources);
    }

    #[test]
    fn line_without_arch_adds_default_arch_to_union() {
        let text = "deb http://x bookworm main\n\
                    deb [arch=arm64] http://x bookworm main\n";
        let (out, cfg) = import(text);
        assert_eq!(cfg.mirrors.len(), 1, "{out}");
        assert_eq!(apt(&cfg.mirrors[0]).architectures, vec!["amd64", "arm64"]);
    }

    #[test]
    fn mirror_path_shared_by_two_mirrors_is_applied_once() {
        // Different keyrings keep two mirrors; the dir must not be reused.
        let text = "mirror_path http://x shared\n\
                    deb [signed-by=/a.gpg] http://x bookworm main\n\
                    deb [signed-by=/b.gpg] http://x bookworm main\n";
        let (out, cfg) = import(text);
        assert_eq!(cfg.mirrors.len(), 2, "{out}");
        assert_eq!(cfg.mirrors[0].path, PathBuf::from("shared"));
        assert_ne!(cfg.mirrors[1].path, PathBuf::from("shared"));
        assert!(out.contains("overlaps the directory of mirror"), "{out}");
    }

    #[test]
    fn nested_mirror_path_is_not_applied() {
        let text = "mirror_path http://a debian\n\
                    mirror_path http://b debian/pve\n\
                    deb http://a bookworm main\n\
                    deb http://b bookworm main\n";
        let (out, cfg) = import(text);
        assert_eq!(cfg.mirrors[0].path, PathBuf::from("debian"));
        assert_eq!(cfg.mirrors[1].path, PathBuf::from("b"), "{out}");
    }

    #[test]
    fn unsafe_mirror_path_becomes_comment() {
        for dir in ["/srv/mirror-x", "../x", "."] {
            let text = format!("mirror_path http://x {dir}\ndeb http://x bookworm main\n");
            let (out, cfg) = import(&text);
            assert!(!out.contains("path = "), "{out}");
            assert!(
                out.contains(&format!(
                    "# mirror_path `http://x` `{dir}` (line 1) not applied"
                )),
                "{out}"
            );
            assert_eq!(cfg.mirrors[0].path, PathBuf::from("x"));
        }
    }

    #[test]
    fn mirror_path_prefers_exact_then_longest_prefix() {
        let text = "mirror_path http://x/ short\n\
                    mirror_path http://x/debian/pve pve\n\
                    deb http://x/debian/pve/ bookworm main\n";
        let (_, cfg) = import(text);
        assert_eq!(cfg.mirrors[0].path, PathBuf::from("pve"));
        let (_, cfg) = import(&text.replace("pve/ bookworm", "pve bookworm"));
        assert_eq!(cfg.mirrors[0].path, PathBuf::from("pve"));
    }

    #[test]
    fn mirror_path_prefix_respects_path_boundaries() {
        let text = "mirror_path http://x/debian debian\n\
                    deb http://x/debian bookworm main\n\
                    deb http://x/debian-security bookworm-security main\n\
                    deb http://x/debian/sub bookworm main\n";
        let (out, cfg) = import(text);
        assert_eq!(cfg.mirrors[0].path, PathBuf::from("debian"));
        assert_eq!(
            cfg.mirrors[1].path,
            PathBuf::from("x-debian-security"),
            "{out}"
        );
        // `/debian/sub` is under the prefix, but its dir is taken.
        assert!(out.contains("overlaps the directory of mirror"), "{out}");
    }

    #[test]
    fn trailing_slash_variants_are_one_mirror_with_canonical_url() {
        let text = "deb http://x/debian bookworm main\n\
                    deb http://x/debian/ trixie main\n";
        let (out, cfg) = import(text);
        assert_eq!(cfg.mirrors.len(), 1, "{out}");
        assert_eq!(cfg.mirrors[0].url.as_str(), "http://x/debian");
        assert_eq!(apt(&cfg.mirrors[0]).suites, vec!["bookworm", "trixie"]);
    }

    #[test]
    fn unused_mirror_paths_are_commented_and_warned() {
        let text = "mirror_path HTTP://X/Debian dd\n\
                    mirror_path http://x/elsewhere ee\n\
                    mirror_path http://x/debian first\n\
                    mirror_path http://x/debian/ second\n\
                    deb http://x/Debian bookworm main\n\
                    deb http://x/debian bookworm main\n";
        let conv = convert(&parse_ok(text));
        let (out, cfg) = import(text);
        assert_eq!(out, conv.toml);
        // Case-insensitive scheme/host, case-sensitive path.
        assert_eq!(cfg.mirrors[0].path, PathBuf::from("dd"));
        assert_eq!(cfg.mirrors[1].path, PathBuf::from("second"));
        for needle in [
            "mirror_path `http://x/elsewhere` `ee` (line 2) not applied: it is the best match \
             for no deb line",
            "mirror_path `http://x/debian` `first` (line 3) not applied: line 4 sets the same \
             prefix",
        ] {
            assert!(
                out.contains(&format!("# {needle}\n")),
                "{needle}\n---\n{out}"
            );
            assert!(
                conv.warnings.iter().any(|w| w == needle),
                "{:?}",
                conv.warnings
            );
        }
    }

    #[test]
    fn mirror_path_absolute_dir_is_reported_not_applied() {
        let text = "deb-amd64 http://download.proxmox.com/debian/pve bookworm pve-no-subscription\n\
                    mirror_path http://download.proxmox.com/debian/pve /srv/mirrors/proxmox\n";
        let (out, cfg) = import(text);
        assert!(
            out.contains(
                "# mirror_path `http://download.proxmox.com/debian/pve` `/srv/mirrors/proxmox` \
                 (line 2) not applied: path must be relative"
            ),
            "{out}"
        );
        assert_eq!(
            cfg.mirrors[0].path,
            PathBuf::from("download.proxmox.com-debian-pve")
        );
    }

    #[test]
    fn generated_toml_roundtrips_through_config_parser() {
        let text = "deb http://deb.debian.org/debian bookworm main\n\
                    deb-src http://deb.debian.org/debian bookworm main\n\
                    deb [arch=arm64] http://x bookworm main\n";
        let (_, cfg) = import(text);
        assert_eq!(cfg.mirrors.len(), 2);
    }

    #[test]
    fn defaults_arch_note_present_when_any_line_lacks_arch() {
        let (out, _) = import("deb http://x bookworm main\n");
        assert!(
            out.contains("[defaults]\narchitectures = [\"amd64\"]"),
            "{out}"
        );
    }

    #[test]
    fn same_slug_on_different_urls_gets_suffix() {
        let text = "deb https://x/debian bookworm main\n\
                    deb http://x/debian bookworm main\n";
        let (_, cfg) = import(text);
        assert_eq!(cfg.mirrors.len(), 2);
        assert_eq!(cfg.mirrors[0].name, "x-debian");
        assert_eq!(cfg.mirrors[1].name, "x-debian-2");
    }

    #[test]
    fn suffixed_names_never_collide_with_other_slugs() {
        let text = "deb http://x/debian bookworm main\n\
                    deb https://x/debian bookworm main\n\
                    deb http://x/debian-2 bookworm main\n";
        let (_, cfg) = import(text);
        let names: Vec<&str> = cfg.mirrors.iter().map(|m| m.name.as_str()).collect();
        assert_eq!(names, vec!["x-debian", "x-debian-2", "x-debian-2-2"]);
    }

    #[test]
    fn no_defaults_note_when_every_line_has_arch() {
        let text = "deb [arch=amd64] http://x bookworm main\n\
                    deb-amd64 http://y bookworm main\n";
        let (out, _) = import(text);
        assert!(
            !out.contains("[defaults]"),
            "unexpected defaults block:\n{out}"
        );
    }

    /// Whatever parses must convert into something `tain check` accepts.
    #[test]
    fn weird_inputs_always_yield_a_loadable_config() {
        let text = "mirror_path http://x/ /abs\n\
                    mirror_path http://x/a ../up\n\
                    mirror_path http://x/b a\n\
                    mirror_path http://x/c x-a\n\
                    deb http://x/a bookworm main\n\
                    deb http://x/a/ trixie main\n\
                    deb https://x/a bookworm main\n\
                    deb http://x/a-2 bookworm main\n\
                    deb http://x/b bookworm main\n\
                    deb http://x/c bookworm main\n\
                    deb http://x/ bookworm main\n\
                    deb http://x/a stable/updates main\n\
                    deb http://x/a ./ \n\
                    deb http://x/a ../x main\n\
                    deb http://x/a a/../../b main\n\
                    deb ftp://x/a bookworm main\n\
                    deb http://x/a bookworm\n\
                    deb-src http://x/new bookworm main\n\
                    deb [signed-by=/k\"q.gpg] http://x/a bookworm main\n\
                    deb [arch=amd64] http://user@x/a?q=1#frag bookworm main\n\
                    deb http://x/\u{1}ctl bookworm main\u{7f}\n";
        let (out, cfg) = import(text);
        assert!(!cfg.mirrors.is_empty(), "{out}");
    }
}
