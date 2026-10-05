//! One-shot converter from apt-mirror style `mirrors.list` to Tain TOML.
//!
//! The runtime never reads `mirrors.list`; operators convert once with
//! `tain import mirrors-list` and review the printed TOML.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::PathBuf;

use url::Url;

use super::env::derive_name_from_url;
use super::model::is_flat_suite;

#[derive(Debug, thiserror::Error)]
pub enum ImportError {
    #[error("line {line}: {msg}")]
    Line { line: usize, msg: String },
}

fn err<T>(line: usize, msg: impl Into<String>) -> Result<T, ImportError> {
    Err(ImportError::Line {
        line,
        msg: msg.into(),
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Entry {
    Deb(DebEntry),
    MirrorPath { url_prefix: String, dir: PathBuf },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DebEntry {
    /// 1-based.
    pub line: usize,
    /// Trimmed original line, for diagnostics.
    pub source: String,
    pub kind: DebKind,
    pub arch_override: Option<Vec<String>>, // from `deb-<arch>` or `[arch=...]`
    pub keyring: Option<PathBuf>,
    pub url: Url,
    pub suite: String,
    pub components: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DebKind {
    Binary,
    Source,
}

/// Parse one line; comments and blank lines yield `None`.
pub fn parse_line(line_no: usize, raw: &str) -> Result<Option<Entry>, ImportError> {
    let stripped = strip_comment(raw).trim();
    if stripped.is_empty() {
        return Ok(None);
    }

    // Not a plain whitespace split: `[ ... ]` options may contain spaces.
    let mut tokens = tokenize(stripped).map_err(|msg| ImportError::Line { line: line_no, msg })?;

    let head = tokens.remove(0);

    if head == "mirror_path" {
        return parse_mirror_path(line_no, &tokens).map(Some);
    }

    let (kind, arch_override_from_head) = match head.as_str() {
        "deb" => (DebKind::Binary, None),
        "deb-src" => (DebKind::Source, None),
        s if s.starts_with("deb-") => {
            let arch = s.trim_start_matches("deb-");
            if arch.is_empty() {
                return err(line_no, format!("unrecognized directive `{head}`"));
            }
            (DebKind::Binary, Some(vec![arch.to_owned()]))
        }
        _ => return err(line_no, format!("unrecognized directive `{head}`")),
    };

    let mut arch_override = arch_override_from_head;
    let mut keyring = None;
    if tokens.first().is_some_and(|t| t.starts_with('[')) {
        let bracket = tokens.remove(0);
        parse_bracket(line_no, &bracket, &mut arch_override, &mut keyring)?;
    }

    if tokens.len() < 2 {
        return err(
            line_no,
            "expected `URL SUITE [COMPONENT...]` after directive",
        );
    }
    let url_str = tokens.remove(0);
    let url = Url::parse(&url_str).map_err(|e| ImportError::Line {
        line: line_no,
        msg: format!("URL `{url_str}` is invalid: {e}"),
    })?;
    let suite = tokens.remove(0);
    let components = tokens;

    Ok(Some(Entry::Deb(DebEntry {
        line: line_no,
        source: raw.trim().to_owned(),
        kind,
        arch_override,
        keyring,
        url,
        suite,
        components,
    })))
}

/// Strip a `#` comment only at line start or after a space, so a URL
/// fragment `#` survives.
fn strip_comment(s: &str) -> &str {
    if let Some(idx) = s.find(" #") {
        &s[..idx]
    } else if let Some(rest) = s.strip_prefix('#') {
        let _ = rest;
        ""
    } else {
        s
    }
}

fn tokenize(s: &str) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_bracket = false;
    for c in s.chars() {
        if c == '[' {
            if in_bracket {
                return Err("nested `[` in options bracket".into());
            }
            if !cur.is_empty() {
                out.push(std::mem::take(&mut cur));
            }
            in_bracket = true;
            cur.push('[');
            continue;
        }
        if c == ']' {
            if !in_bracket {
                return Err("stray `]` without opening `[`".into());
            }
            cur.push(']');
            out.push(std::mem::take(&mut cur));
            in_bracket = false;
            continue;
        }
        if c.is_whitespace() && !in_bracket {
            if !cur.is_empty() {
                out.push(std::mem::take(&mut cur));
            }
            continue;
        }
        cur.push(c);
    }
    if in_bracket {
        return Err("unterminated options bracket".into());
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    Ok(out)
}

fn parse_bracket(
    line_no: usize,
    bracket: &str,
    arch_override: &mut Option<Vec<String>>,
    keyring: &mut Option<PathBuf>,
) -> Result<(), ImportError> {
    let inner = bracket
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .ok_or_else(|| ImportError::Line {
            line: line_no,
            msg: format!("malformed options bracket `{bracket}`"),
        })?;
    for kv in inner.split_whitespace() {
        let (k, v) = kv.split_once('=').ok_or_else(|| ImportError::Line {
            line: line_no,
            msg: format!("options entry `{kv}` is not key=value"),
        })?;
        match k {
            "arch" => {
                let archs: Vec<String> = v
                    .split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned)
                    .collect();
                if archs.is_empty() {
                    return err(line_no, "options `arch=` has no values");
                }
                *arch_override = Some(archs);
            }
            "signed-by" => {
                *keyring = Some(PathBuf::from(v));
            }
            "trusted" | "target-" | "lang" => {
                // Irrelevant to a mirror; ignored.
            }
            other => {
                return err(line_no, format!("unknown options key `{other}`"));
            }
        }
    }
    Ok(())
}

fn parse_mirror_path(line_no: usize, tokens: &[String]) -> Result<Entry, ImportError> {
    if tokens.len() != 2 {
        return err(line_no, "expected `mirror_path <url_prefix> <local_dir>`");
    }
    Ok(Entry::MirrorPath {
        url_prefix: tokens[0].clone(),
        dir: PathBuf::from(&tokens[1]),
    })
}

pub fn parse(text: &str) -> Result<Vec<Entry>, ImportError> {
    let mut out = Vec::new();
    for (idx, line) in text.lines().enumerate() {
        if let Some(entry) = parse_line(idx + 1, line)? {
            out.push(entry);
        }
    }
    Ok(out)
}

/// Emit TOML, merging entries with the same URL, architecture set and keyring
/// into one `[[mirror]]` with the union of suites and components.
pub fn to_toml(entries: &[Entry]) -> String {
    let mut path_map: BTreeMap<String, PathBuf> = BTreeMap::new();
    let mut debs: Vec<&DebEntry> = Vec::new();
    for e in entries {
        match e {
            Entry::MirrorPath { url_prefix, dir } => {
                path_map.insert(url_prefix.clone(), dir.clone());
            }
            // Unsupported; `write_flat_block` keeps them as comments.
            Entry::Deb(d) if is_flat_suite(&d.suite) => {}
            Entry::Deb(d) => debs.push(d),
        }
    }

    // Binary and source lines share a group; `include_source` records the latter.
    #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
    struct GroupKey {
        url: String,
        arch: Vec<String>,
        keyring: Option<PathBuf>,
    }

    struct Group {
        url: Url,
        arch: Vec<String>,
        keyring: Option<PathBuf>,
        include_source: bool,
        suites: Vec<String>,
        components: Vec<String>,
    }

    let mut order: Vec<GroupKey> = Vec::new();
    let mut groups: BTreeMap<GroupKey, Group> = BTreeMap::new();

    for d in debs {
        let mut arch = d.arch_override.clone().unwrap_or_default();
        arch.sort();
        arch.dedup();
        let key = GroupKey {
            url: d.url.as_str().to_owned(),
            arch: arch.clone(),
            keyring: d.keyring.clone(),
        };
        let key_for_order = key.clone();
        let entry = groups.entry(key).or_insert_with(|| {
            order.push(key_for_order);
            Group {
                url: d.url.clone(),
                arch,
                keyring: d.keyring.clone(),
                include_source: false,
                suites: Vec::new(),
                components: Vec::new(),
            }
        });
        if !entry.suites.iter().any(|s| s == &d.suite) {
            entry.suites.push(d.suite.clone());
        }
        for c in &d.components {
            if !entry.components.iter().any(|x| x == c) {
                entry.components.push(c.clone());
            }
        }
        if d.kind == DebKind::Source {
            entry.include_source = true;
        }
    }

    let any_no_arch = groups.values().any(|g| g.arch.is_empty());
    let mut out = String::new();
    out.push_str("# Generated by `tain import mirrors-list` — review before use.\n");
    out.push_str("# See docs/configuration.md in the tain repository for the full schema.\n\n");
    if path_map.is_empty() {
        out.push_str("[global]\n\n");
    } else {
        out.push_str("[global]\n");
        out.push_str("# mirror_path lines had no direct TOML equivalent; the paths were\n");
        out.push_str("# applied to matching mirrors below where possible.\n\n");
    }
    if any_no_arch {
        out.push_str("# One or more `deb` lines in the source file did not declare\n");
        out.push_str("# `[arch=...]`; amd64 is used as a safe default. Adjust as needed.\n");
        out.push_str("[defaults]\n");
        out.push_str("architectures = [\"amd64\"]\n\n");
    }

    // Names must be unique, so extra groups on one URL get `-2`, `-3`, ….
    let mut name_counts: BTreeMap<String, usize> = BTreeMap::new();
    for key in &order {
        let g = &groups[key];
        let base_name = derive_name_from_url(&g.url);
        let n = name_counts.entry(base_name.clone()).or_insert(0);
        *n += 1;
        let name = if *n == 1 {
            base_name
        } else {
            format!("{base_name}-{}", *n)
        };
        let path = path_map.get(g.url.as_str()).cloned().or_else(|| {
            path_map
                .iter()
                .find(|(prefix, _)| g.url.as_str().starts_with(prefix.as_str()))
                .map(|(_, dir)| dir.clone())
        });

        writeln!(out, "[[mirror]]").unwrap();
        writeln!(out, "name = {}", toml_string(&name)).unwrap();
        writeln!(out, "url = {}", toml_string(g.url.as_str())).unwrap();
        if let Some(p) = path {
            writeln!(out, "path = {}", toml_string(&p.to_string_lossy())).unwrap();
        }
        writeln!(out, "suites = {}", toml_string_list(&g.suites)).unwrap();
        writeln!(out, "components = {}", toml_string_list(&g.components)).unwrap();
        if !g.arch.is_empty() {
            writeln!(out, "architectures = {}", toml_string_list(&g.arch)).unwrap();
        }
        if g.include_source {
            writeln!(out, "[mirror.indexes]").unwrap();
            writeln!(out, "sources = true").unwrap();
        }
        if let Some(kr) = &g.keyring {
            writeln!(out, "[mirror.verify]").unwrap();
            writeln!(out, "pgp = \"required\"").unwrap();
            writeln!(out, "keyring = {}", toml_string(&kr.to_string_lossy())).unwrap();
        }
        out.push('\n');
    }

    write_flat_block(&mut out, entries);
    out
}

/// Flat-repository `deb` lines, which `to_toml` emits only as comments.
pub fn flat_entries(entries: &[Entry]) -> impl Iterator<Item = &DebEntry> {
    entries.iter().filter_map(|e| match e {
        Entry::Deb(d) if is_flat_suite(&d.suite) => Some(d),
        _ => None,
    })
}

fn write_flat_block(out: &mut String, entries: &[Entry]) {
    let mut flat = flat_entries(entries).peekable();
    if flat.peek().is_none() {
        return;
    }
    out.push_str("# Not converted: flat repositories are not supported yet.\n");
    for d in flat {
        writeln!(out, "# line {}: {}", d.line, d.source).unwrap();
    }
}

fn toml_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            _ => out.push(c),
        }
    }
    out.push('"');
    out
}

fn toml_string_list(v: &[String]) -> String {
    let mut out = String::from("[");
    for (i, s) in v.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        out.push_str(&toml_string(s));
    }
    out.push(']');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_ok(s: &str) -> Vec<Entry> {
        parse(s).unwrap()
    }

    #[test]
    fn ignores_blank_and_comment_lines() {
        assert_eq!(parse_line(1, "").unwrap(), None);
        assert_eq!(parse_line(1, "   ").unwrap(), None);
        assert_eq!(parse_line(1, "# hello").unwrap(), None);
        assert_eq!(parse_line(1, "  # hello").unwrap(), None);
    }

    #[test]
    fn parses_plain_deb() {
        let e = parse_line(1, "deb http://deb.debian.org/debian bookworm main contrib")
            .unwrap()
            .unwrap();
        match e {
            Entry::Deb(d) => {
                assert_eq!(d.kind, DebKind::Binary);
                assert!(d.arch_override.is_none());
                assert!(d.keyring.is_none());
                assert_eq!(d.suite, "bookworm");
                assert_eq!(d.components, vec!["main", "contrib"]);
            }
            _ => panic!("expected deb entry"),
        }
    }

    #[test]
    fn parses_deb_src() {
        let e = parse_line(1, "deb-src http://deb.debian.org/debian bookworm main")
            .unwrap()
            .unwrap();
        match e {
            Entry::Deb(d) => assert_eq!(d.kind, DebKind::Source),
            _ => panic!(),
        }
    }

    #[test]
    fn parses_ustcmirror_style_arch_directive() {
        let e = parse_line(
            1,
            "deb-amd64 http://download.proxmox.com/debian/pve bookworm pve-no-subscription",
        )
        .unwrap()
        .unwrap();
        match e {
            Entry::Deb(d) => {
                assert_eq!(d.arch_override.as_deref(), Some(&["amd64".to_owned()][..]));
                assert_eq!(d.suite, "bookworm");
            }
            _ => panic!(),
        }
    }

    #[test]
    fn parses_arch_bracket() {
        let e = parse_line(1, "deb [arch=amd64,arm64] http://foo bookworm main")
            .unwrap()
            .unwrap();
        match e {
            Entry::Deb(d) => {
                assert_eq!(
                    d.arch_override.as_deref(),
                    Some(&["amd64".to_owned(), "arm64".to_owned()][..])
                );
            }
            _ => panic!(),
        }
    }

    #[test]
    fn parses_signed_by_bracket() {
        let e = parse_line(
            1,
            "deb [arch=amd64 signed-by=/etc/keyrings/proxmox.gpg] http://download.proxmox.com/debian/pve bookworm pve-no-subscription",
        )
        .unwrap()
        .unwrap();
        match e {
            Entry::Deb(d) => {
                assert_eq!(d.arch_override.as_deref(), Some(&["amd64".to_owned()][..]));
                assert_eq!(
                    d.keyring.as_deref(),
                    Some(std::path::Path::new("/etc/keyrings/proxmox.gpg"))
                );
            }
            _ => panic!(),
        }
    }

    #[test]
    fn parses_signed_by_without_arch() {
        let e = parse_line(1, "deb [signed-by=/etc/keys.gpg] http://foo bookworm main")
            .unwrap()
            .unwrap();
        match e {
            Entry::Deb(d) => {
                assert!(d.arch_override.is_none());
                assert_eq!(
                    d.keyring.as_deref(),
                    Some(std::path::Path::new("/etc/keys.gpg"))
                );
            }
            _ => panic!(),
        }
    }

    #[test]
    fn parses_mirror_path() {
        let e = parse_line(1, "mirror_path http://foo/ /srv/foo")
            .unwrap()
            .unwrap();
        match e {
            Entry::MirrorPath { url_prefix, dir } => {
                assert_eq!(url_prefix, "http://foo/");
                assert_eq!(dir, PathBuf::from("/srv/foo"));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn rejects_unknown_directive() {
        let err = parse_line(1, "foo bar").unwrap_err();
        assert!(matches!(err, ImportError::Line { line: 1, .. }));
    }

    #[test]
    fn rejects_bad_url() {
        let err = parse_line(1, "deb not-a-url bookworm main").unwrap_err();
        assert!(matches!(err, ImportError::Line { line: 1, .. }));
    }

    #[test]
    fn rejects_too_few_tokens() {
        let err = parse_line(1, "deb http://foo").unwrap_err();
        assert!(matches!(err, ImportError::Line { line: 1, .. }));
    }

    #[test]
    fn rejects_unterminated_bracket() {
        let err = parse_line(1, "deb [arch=amd64 http://foo bookworm main").unwrap_err();
        assert!(matches!(err, ImportError::Line { line: 1, .. }));
    }

    #[test]
    fn rejects_unknown_bracket_key() {
        let err = parse_line(1, "deb [tenderloin=yes] http://foo bookworm main").unwrap_err();
        assert!(matches!(err, ImportError::Line { line: 1, .. }));
    }

    #[test]
    fn rejects_empty_arch_bracket() {
        let err = parse_line(1, "deb [arch=] http://foo bookworm main").unwrap_err();
        assert!(matches!(err, ImportError::Line { line: 1, .. }));
    }

    #[test]
    fn strips_trailing_hash_comment() {
        let e = parse_line(1, "deb http://foo bookworm main # note")
            .unwrap()
            .unwrap();
        match e {
            Entry::Deb(d) => assert_eq!(d.components, vec!["main"]),
            _ => panic!(),
        }
    }

    #[test]
    fn merges_same_url_arch_keyring_into_one_mirror() {
        let text = "deb http://deb.debian.org/debian bookworm main contrib\n\
                    deb http://deb.debian.org/debian bookworm-updates main\n";
        let toml_out = to_toml(&parse_ok(text));
        assert_eq!(toml_out.matches("[[mirror]]").count(), 1);
        assert!(toml_out.contains("suites = [\"bookworm\", \"bookworm-updates\"]"));
        assert!(toml_out.contains("components = [\"main\", \"contrib\"]"));
    }

    #[test]
    fn different_url_separate_mirrors() {
        let text = "deb http://a.example bookworm main\n\
                    deb http://b.example bookworm main\n";
        let toml_out = to_toml(&parse_ok(text));
        assert_eq!(toml_out.matches("[[mirror]]").count(), 2);
    }

    #[test]
    fn deb_and_debsrc_merge_and_enable_sources() {
        let text = "deb http://x bookworm main\n\
                    deb-src http://x bookworm main\n";
        let toml_out = to_toml(&parse_ok(text));
        assert_eq!(toml_out.matches("[[mirror]]").count(), 1);
        assert!(toml_out.contains("[mirror.indexes]"));
        assert!(toml_out.contains("sources = true"));
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
        let toml_out = to_toml(&parse_ok(&lines.join("\n")));
        assert!(!toml_out.contains("[[mirror]]"), "{toml_out}");
        assert!(
            toml_out.contains("flat repositories are not supported yet"),
            "{toml_out}"
        );
        for (idx, line) in lines.iter().enumerate() {
            let commented = format!("# line {}: {line}\n", idx + 1);
            assert!(
                toml_out.contains(&commented),
                "missing `{commented}`:\n{toml_out}"
            );
        }
        let cfg = super::super::toml::parse(&toml_out)
            .unwrap_or_else(|e| panic!("generated TOML rejected: {e}\n---\n{toml_out}"));
        assert!(cfg.mirrors.is_empty());
    }

    #[test]
    fn import_with_flat_line_keeps_other_mirrors_loadable() {
        let text = "deb http://deb.debian.org/debian bookworm main\n\
                    deb https://example.com/repo ./\n\
                    deb https://example.com/repo bookworm main\n";
        let entries = parse_ok(text);
        let flat: Vec<usize> = flat_entries(&entries).map(|d| d.line).collect();
        assert_eq!(flat, vec![2]);
        let toml_out = to_toml(&entries);
        assert!(
            toml_out.contains("# line 2: deb https://example.com/repo ./\n"),
            "{toml_out}"
        );
        let cfg = super::super::toml::parse(&toml_out)
            .unwrap_or_else(|e| panic!("generated TOML rejected: {e}\n---\n{toml_out}"));
        assert_eq!(cfg.mirrors.len(), 2);
        for m in &cfg.mirrors {
            match &m.backend_options {
                crate::config::model::BackendOptions::Apt(a) => {
                    assert_eq!(a.suites, vec!["bookworm".to_owned()]);
                }
            }
        }
    }

    #[test]
    fn keyring_emits_verify_block_with_required_pgp() {
        let text = "deb [signed-by=/etc/keys.gpg] http://x bookworm main\n";
        let toml_out = to_toml(&parse_ok(text));
        assert!(toml_out.contains("[mirror.verify]"));
        assert!(toml_out.contains("pgp = \"required\""));
        assert!(toml_out.contains("keyring = \"/etc/keys.gpg\""));
    }

    #[test]
    fn different_arch_yields_separate_mirrors() {
        let text = "deb [arch=amd64] http://x bookworm main\n\
                    deb [arch=arm64] http://x bookworm main\n";
        let toml_out = to_toml(&parse_ok(text));
        assert_eq!(toml_out.matches("[[mirror]]").count(), 2);
    }

    #[test]
    fn mirror_path_applied_by_prefix() {
        let text = "mirror_path http://x /srv/mirror-x\n\
                    deb http://x bookworm main\n";
        let toml_out = to_toml(&parse_ok(text));
        assert!(toml_out.contains("path = \"/srv/mirror-x\""));
    }

    #[test]
    fn tokenize_handles_bracket_content_with_spaces() {
        let toks = tokenize("deb [arch=amd64 signed-by=/a b] http://x bookworm main").unwrap();
        assert_eq!(toks[0], "deb");
        assert_eq!(toks[1], "[arch=amd64 signed-by=/a b]");
        assert_eq!(toks[2], "http://x");
    }

    #[test]
    fn full_example_from_documented_syntaxes() {
        let text = r#"
# comment
deb http://deb.debian.org/debian bookworm main contrib non-free
deb-src http://deb.debian.org/debian bookworm main
deb [arch=amd64,arm64] http://foo/bar bookworm main
deb-amd64 http://download.proxmox.com/debian/pve bookworm pve-no-subscription
deb [signed-by=/etc/keys.gpg] http://x bookworm main
mirror_path http://download.proxmox.com/debian/pve /srv/mirrors/proxmox
"#;
        let entries = parse_ok(text);
        assert_eq!(
            entries
                .iter()
                .filter(|e| matches!(e, Entry::Deb(_)))
                .count(),
            5
        );
        assert_eq!(
            entries
                .iter()
                .filter(|e| matches!(e, Entry::MirrorPath { .. }))
                .count(),
            1
        );
        let out = to_toml(&entries);
        assert!(out.contains("[[mirror]]"));
        assert!(out.contains("/srv/mirrors/proxmox"));
    }

    #[test]
    fn generated_toml_roundtrips_through_config_parser() {
        let text = "deb http://deb.debian.org/debian bookworm main\n\
                    deb-src http://deb.debian.org/debian bookworm main\n\
                    deb [arch=arm64] http://x bookworm main\n";
        let out = to_toml(&parse_ok(text));
        let cfg = crate::config::toml::parse(&out)
            .unwrap_or_else(|e| panic!("generated TOML rejected: {e}\n---\n{out}"));
        assert_eq!(cfg.mirrors.len(), 2);
    }

    #[test]
    fn defaults_arch_note_present_when_any_line_lacks_arch() {
        let text = "deb http://x bookworm main\n";
        let out = to_toml(&parse_ok(text));
        assert!(out.contains("[defaults]"));
        assert!(out.contains("architectures = [\"amd64\"]"));
    }

    #[test]
    fn duplicate_url_across_arch_groups_gets_suffix() {
        let text = "deb [arch=amd64] http://x bookworm main\n\
                    deb [arch=arm64] http://x bookworm main\n";
        let out = to_toml(&parse_ok(text));
        let cfg = crate::config::toml::parse(&out)
            .unwrap_or_else(|e| panic!("generated TOML rejected: {e}\n---\n{out}"));
        assert_eq!(cfg.mirrors.len(), 2);
        assert_ne!(cfg.mirrors[0].name, cfg.mirrors[1].name);
    }

    #[test]
    fn no_defaults_note_when_every_line_has_arch() {
        let text = "deb [arch=amd64] http://x bookworm main\n\
                    deb-amd64 http://y bookworm main\n";
        let out = to_toml(&parse_ok(text));
        assert!(
            !out.contains("[defaults]"),
            "unexpected defaults block:\n{out}"
        );
    }
}
