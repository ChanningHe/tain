//! One-shot converter from apt-mirror's `mirror.list` to Tain TOML.
//!
//! The runtime never reads `mirror.list`; operators convert once with
//! `tain import mirrors-list` and review the printed TOML.

use std::path::PathBuf;

use url::Url;

mod emit;
mod lines;
mod mirror_paths;
mod options;

pub use emit::{Conversion, convert, to_toml};

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
    Deb(Box<DebEntry>),
    MirrorPath {
        /// 1-based.
        line: usize,
        url_prefix: String,
        dir: PathBuf,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DebEntry {
    /// 1-based.
    pub line: usize,
    /// Trimmed original line, for diagnostics.
    pub source: String,
    pub kind: DebKind,
    pub arch_override: Option<Vec<String>>, // from `deb-<arch>` or `[arch=...]`
    /// Raw `signed-by=` value; `emit` decides whether it is a usable keyring.
    pub keyring: Option<PathBuf>,
    /// Options that do not affect the mirror, as written.
    pub ignored_options: Vec<String>,
    /// Why an option keeps this line from being converted.
    pub unsupported_option: Option<String>,
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
    let stripped = strip_comment(raw).trim_matches(is_apt_space);
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

    let mut opts = options::Options::default();
    if let Some(inner) = tokens
        .first()
        .and_then(|t| t.strip_prefix('['))
        .and_then(|t| t.strip_suffix(']'))
    {
        opts = options::parse(inner).map_err(|msg| ImportError::Line { line: line_no, msg })?;
        tokens.remove(0);
    }
    let arch_override = opts
        .arch
        .or(arch_override_from_head)
        .map(|base| options::apply_arch_edits(&base, &opts.arch_edits));
    if arch_override.is_none() && !opts.arch_edits.is_empty() {
        opts.unsupported.get_or_insert_with(|| {
            "`arch+=` / `arch-=` edit apt's configured architectures, which the importer \
             cannot see; list them with `arch=`"
                .to_owned()
        });
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

    Ok(Some(Entry::Deb(Box::new(DebEntry {
        line: line_no,
        source: raw.trim_matches(is_apt_space).to_owned(),
        kind,
        arch_override,
        keyring: opts.signed_by.map(PathBuf::from),
        ignored_options: opts.ignored,
        unsupported_option: opts.unsupported,
        url,
        suite,
        components,
    }))))
}

/// The separators apt's line parser knows (C `isspace`); other Unicode
/// spaces are ordinary token characters there.
fn is_apt_space(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\n' | '\x0b' | '\x0c' | '\r')
}

/// Strip a `#` comment only at line start or after whitespace. apt also
/// cuts at a `#` inside a token; keeping it instead makes such a token
/// invalid, so the importer reports it rather than silently shortening it.
fn strip_comment(s: &str) -> &str {
    let mut prev_is_space = true;
    for (idx, c) in s.char_indices() {
        if c == '#' && prev_is_space {
            return &s[..idx];
        }
        prev_is_space = is_apt_space(c);
    }
    s
}

/// Split on apt whitespace. Only a token right after the directive that
/// starts with `[` is the options bracket (it may contain spaces); a `[`
/// elsewhere, as in an IPv6 URL, is an ordinary character.
fn tokenize(s: &str) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_bracket = false;
    for c in s.chars() {
        if c == '[' && in_bracket {
            return Err("nested `[` in options bracket".into());
        }
        if c == '[' && out.len() == 1 && cur.is_empty() {
            in_bracket = true;
            cur.push('[');
            continue;
        }
        if c == ']' && in_bracket {
            cur.push(']');
            out.push(std::mem::take(&mut cur));
            in_bracket = false;
            continue;
        }
        if is_apt_space(c) && !in_bracket {
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

fn parse_mirror_path(line_no: usize, tokens: &[String]) -> Result<Entry, ImportError> {
    if tokens.len() != 2 {
        return err(line_no, "expected `mirror_path <url_prefix> <local_dir>`");
    }
    Ok(Entry::MirrorPath {
        line: line_no,
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
            Entry::MirrorPath {
                url_prefix, dir, ..
            } => {
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
    fn unknown_bracket_key_marks_only_its_line() {
        let e = parse_line(1, "deb [tenderloin=yes] http://foo bookworm main")
            .unwrap()
            .unwrap();
        match e {
            Entry::Deb(d) => assert!(d.unsupported_option.unwrap().contains("tenderloin")),
            _ => panic!(),
        }
    }

    #[test]
    fn ipv6_url_brackets_are_not_options() {
        let e = parse_line(1, "deb http://[::1]:8080/debian bookworm main")
            .unwrap()
            .unwrap();
        match e {
            Entry::Deb(d) => {
                assert_eq!(d.url.host_str(), Some("[::1]"));
                assert!(d.unsupported_option.is_none());
            }
            _ => panic!(),
        }
        let toks = tokenize("deb [arch=amd64] http://[::1]/d bookworm main").unwrap();
        assert_eq!(toks[1], "[arch=amd64]");
        assert_eq!(toks[2], "http://[::1]/d");
    }

    #[test]
    fn arch_edits_apply_to_the_directive_arch() {
        match parse_line(1, "deb-amd64 [arch+=arm64] http://x bookworm main")
            .unwrap()
            .unwrap()
        {
            Entry::Deb(d) => assert_eq!(
                d.arch_override,
                Some(vec!["amd64".to_owned(), "arm64".to_owned()])
            ),
            _ => panic!(),
        }
        match parse_line(1, "deb [arch-=i386] http://x bookworm main")
            .unwrap()
            .unwrap()
        {
            Entry::Deb(d) => assert!(d.unsupported_option.unwrap().contains("arch=")),
            _ => panic!(),
        }
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
    fn strips_comment_after_any_whitespace_but_keeps_hashes_inside_tokens() {
        for line in [
            "deb http://foo bookworm main\t# note",
            "deb http://foo bookworm main\t#note",
            "deb [arch=amd64] http://foo bookworm main #",
        ] {
            match parse_line(1, line).unwrap().unwrap() {
                Entry::Deb(d) => assert_eq!(d.components, vec!["main"], "{line:?}"),
                _ => panic!(),
            }
        }
        assert_eq!(parse_line(1, "\t# only a comment").unwrap(), None);
        match parse_line(1, "deb http://foo/#frag bookworm main#x")
            .unwrap()
            .unwrap()
        {
            Entry::Deb(d) => {
                assert_eq!(d.url.fragment(), Some("frag"));
                assert_eq!(d.components, vec!["main#x"]);
            }
            _ => panic!(),
        }
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
        let dirs: Vec<&PathBuf> = entries
            .iter()
            .filter_map(|e| match e {
                Entry::MirrorPath { dir, .. } => Some(dir),
                Entry::Deb(_) => None,
            })
            .collect();
        // Conversion of absolute dirs: see `emit::tests`.
        assert_eq!(dirs, vec![&PathBuf::from("/srv/mirrors/proxmox")]);
    }
}
