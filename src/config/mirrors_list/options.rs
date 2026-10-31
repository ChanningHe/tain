//! The `[key=value ...]` options of a `deb` line, sorted by what they mean
//! for a mirror: applied (`arch`, `signed-by`), ignored with a warning, or
//! keeping the line from being converted. Only malformed syntax fails the
//! whole import.

use super::is_apt_space;

/// Options that change neither which files a mirror holds nor how tain
/// verifies them. Verification relaxations (`trusted`, `allow-*`) are
/// dropped too: tain verifies exactly what `signed-by` asks for.
const IGNORED: &[&str] = &[
    "trusted",
    "pdiffs",
    "by-hash",
    "check-valid-until",
    "valid-until-min",
    "valid-until-max",
    "check-date",
    "date-max-future",
    "allow-insecure",
    "allow-weak",
    "allow-downgrade-to-insecure",
];

/// List options apt lets `+=` / `-=` edit and tain has no use for: tain
/// picks indexes through `[mirror.indexes]`.
const IGNORED_LISTS: &[&str] = &["lang", "target"];

/// Options that change what apt fetches in a way tain cannot mirror.
const UNSUPPORTED: &[&str] = &["snapshot", "inrelease-path"];

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(super) struct Options {
    /// `arch=`, with any `arch+=` / `arch-=` in the same bracket applied.
    pub arch: Option<Vec<String>>,
    /// `arch+=` / `arch-=` entries still waiting for a base list.
    pub arch_edits: Vec<ArchEdit>,
    pub signed_by: Option<String>,
    /// Ignored entries, as written.
    pub ignored: Vec<String>,
    /// Why the line cannot be converted, if an option prevents it.
    pub unsupported: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ArchEdit {
    pub add: bool,
    pub archs: Vec<String>,
}

/// Apply `arch+=` / `arch-=` edits to a base list, as apt does: additions
/// first, then removals.
pub(super) fn apply_arch_edits(base: &[String], edits: &[ArchEdit]) -> Vec<String> {
    let mut out = base.to_vec();
    for a in edits.iter().filter(|e| e.add).flat_map(|e| &e.archs) {
        if !out.contains(a) {
            out.push(a.clone());
        }
    }
    let removed: Vec<&String> = edits
        .iter()
        .filter(|e| !e.add)
        .flat_map(|e| &e.archs)
        .collect();
    out.retain(|a| !removed.contains(&a));
    out
}

/// Parse the text between `[` and `]`.
///
/// # Errors
///
/// A message for an entry that is not `key=value` with both parts set.
pub(super) fn parse(inner: &str) -> Result<Options, String> {
    let mut opts = Options::default();
    for kv in inner.split(is_apt_space).filter(|s| !s.is_empty()) {
        let (k, v) = kv
            .split_once('=')
            .ok_or_else(|| format!("options entry `{kv}` is not key=value"))?;
        let (key, modifier) = match k.strip_suffix(['+', '-']) {
            Some(base) => (base, k.chars().last()),
            None => (k, None),
        };
        if key.is_empty() {
            return Err(format!("options entry `{kv}` has no key"));
        }
        if v.is_empty() {
            return Err(format!("options entry `{kv}` has no value"));
        }
        match (key, modifier) {
            ("arch", None) => opts.arch = Some(split_list(kv, v)?),
            ("arch", Some(m)) => opts.arch_edits.push(ArchEdit {
                add: m == '+',
                archs: split_list(kv, v)?,
            }),
            ("signed-by", None) => opts.signed_by = Some(v.to_owned()),
            (key, None) if IGNORED.contains(&key) => opts.ignored.push(kv.to_owned()),
            (key, _) if IGNORED_LISTS.contains(&key) => opts.ignored.push(kv.to_owned()),
            (key, None) if UNSUPPORTED.contains(&key) => {
                let why = format!("option `{k}=` changes what apt fetches; tain cannot mirror it");
                opts.unsupported.get_or_insert(why);
            }
            _ => {
                let why = format!("option `{k}=` is not one the importer knows");
                opts.unsupported.get_or_insert(why);
            }
        }
    }
    if let Some(base) = &opts.arch {
        opts.arch = Some(apply_arch_edits(base, &opts.arch_edits));
        opts.arch_edits.clear();
    }
    Ok(opts)
}

fn split_list(kv: &str, v: &str) -> Result<Vec<String>, String> {
    let items: Vec<String> = v
        .split(',')
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect();
    if items.is_empty() {
        return Err(format!("options entry `{kv}` has no values"));
    }
    Ok(items)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn applies_arch_and_signed_by() {
        let o = parse("arch=amd64,arm64 signed-by=/k.gpg").unwrap();
        assert_eq!(o.arch, Some(strings(&["amd64", "arm64"])));
        assert_eq!(o.signed_by.as_deref(), Some("/k.gpg"));
        assert!(o.ignored.is_empty() && o.unsupported.is_none());
    }

    #[test]
    fn arch_edits_apply_to_an_arch_list_in_the_same_bracket() {
        let o = parse("arch=amd64,i386 arch+=arm64 arch-=i386").unwrap();
        assert_eq!(o.arch, Some(strings(&["amd64", "arm64"])));
        assert!(o.arch_edits.is_empty());
    }

    #[test]
    fn arch_edits_without_a_base_are_kept_for_the_caller() {
        let o = parse("arch+=arm64").unwrap();
        assert_eq!(o.arch, None);
        assert_eq!(
            o.arch_edits,
            vec![ArchEdit {
                add: true,
                archs: strings(&["arm64"])
            }]
        );
    }

    #[test]
    fn harmless_options_are_ignored_as_written() {
        let o = parse("trusted=yes check-valid-until=no lang+=de target-=Contents-deb").unwrap();
        assert_eq!(
            o.ignored,
            strings(&[
                "trusted=yes",
                "check-valid-until=no",
                "lang+=de",
                "target-=Contents-deb"
            ])
        );
        assert!(o.unsupported.is_none());
    }

    #[test]
    fn semantic_unknown_and_modified_scalar_options_block_the_line() {
        for (text, needle) in [
            ("snapshot=20240101T000000Z", "changes what apt fetches"),
            ("inrelease-path=x", "changes what apt fetches"),
            ("tenderloin=yes", "not one the importer knows"),
            ("signed-by+=/k.gpg", "`signed-by+=`"),
            ("trusted-=yes", "`trusted-=`"),
        ] {
            let why = parse(text).unwrap().unsupported.unwrap();
            assert!(why.contains(needle), "{text}: {why}");
        }
    }

    #[test]
    fn malformed_entries_are_errors() {
        for text in ["arch", "=x", "arch=", "arch=,", "+=x"] {
            assert!(parse(text).is_err(), "{text}");
        }
        assert!(parse("arch=").unwrap_err().contains("has no value"));
        assert!(parse("=x").unwrap_err().contains("has no key"));
    }
}
