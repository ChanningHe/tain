//! `mirror_path` lines for the importer: prefixes are parsed as URLs and
//! matched on scheme, host, port and whole path segments; a directory is
//! handed out only when valid and unshared. Every line that ends up unused
//! is reported, never dropped silently.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use url::Url;

use super::Entry;
use crate::config::model::normalize_mirror_path;

/// Scheme, host, port and non-empty path segments: what makes two URLs the
/// same repository location regardless of spelling (case, default port,
/// punycode, trailing `/`).
type Key = (String, Option<String>, Option<u16>, Vec<String>);

fn key(url: &Url) -> Key {
    let segments = url
        .path_segments()
        .map(|s| s.filter(|seg| !seg.is_empty()).map(str::to_owned).collect())
        .unwrap_or_default();
    (
        url.scheme().to_owned(),
        url.host_str().map(str::to_owned),
        url.port_or_known_default(),
        segments,
    )
}

/// `url` with trailing slashes trimmed, so `/debian` and `/debian/` group
/// as one mirror.
#[must_use]
pub(super) fn canonical(url: &Url) -> Url {
    let mut out = url.clone();
    let trimmed = url.path().trim_end_matches('/').to_owned();
    out.set_path(&trimmed);
    out
}

struct Rule<'a> {
    line: usize,
    prefix: &'a str,
    dir: &'a Path,
    key: Key,
}

impl Rule<'_> {
    /// `prefix` is the URL itself or a parent directory of it.
    fn covers(&self, url: &Key) -> bool {
        let (scheme, host, port, segments) = &self.key;
        (scheme, host, port) == (&url.0, &url.1, &url.2) && url.3.starts_with(segments)
    }

    fn not_applied(&self, why: &str) -> String {
        format!(
            "mirror_path `{}` `{}` (line {}) not applied: {why}",
            self.prefix,
            self.dir.display(),
            self.line
        )
    }
}

/// Outcome per mirror plus messages for lines that apply to no mirror.
pub(super) struct Resolution {
    /// Per mirror: the directory, a message why the matching line was not
    /// applied, or `None` when no line matches.
    pub per_mirror: Vec<Option<Result<PathBuf, String>>>,
    pub unused: Vec<String>,
}

/// Resolve `mirror_path` lines for mirrors with these URLs and names (a
/// name is the default path, so it counts as a taken directory).
pub(super) fn resolve(entries: &[Entry], urls: &[&Url], names: &[String]) -> Resolution {
    let mut unused = Vec::new();
    // Later lines for the same location win; earlier ones are reported.
    let mut rules: BTreeMap<Key, Rule<'_>> = BTreeMap::new();
    for e in entries {
        let Entry::MirrorPath {
            line,
            url_prefix,
            dir,
        } = e
        else {
            continue;
        };
        let Ok(parsed) = Url::parse(url_prefix) else {
            unused.push(format!(
                "mirror_path `{url_prefix}` (line {line}) not applied: the prefix is not a URL"
            ));
            continue;
        };
        let rule = Rule {
            line: *line,
            prefix: url_prefix,
            dir,
            key: key(&parsed),
        };
        if let Some(old) = rules.insert(rule.key.clone(), rule) {
            unused.push(old.not_applied(&format!(
                "line {} sets the same prefix",
                rules[&old.key].line
            )));
        }
    }

    let mut used = vec![false; rules.len()];
    let mut claimed: Vec<(PathBuf, &str)> = Vec::new();
    let mut per_mirror = Vec::with_capacity(urls.len());
    for (url, name) in urls.iter().zip(names) {
        let url_key = key(url);
        // Longest covering prefix wins.
        let best = rules
            .values()
            .enumerate()
            .filter(|(_, r)| r.covers(&url_key))
            .max_by_key(|(_, r)| r.key.3.len());
        let Some((idx, rule)) = best else {
            per_mirror.push(None);
            continue;
        };
        used[idx] = true;
        per_mirror.push(Some(claim(rule, name, names, &mut claimed)));
    }

    for (rule, _) in rules.values().zip(&used).filter(|(_, u)| !**u) {
        unused.push(rule.not_applied("it is the best match for no deb line"));
    }
    Resolution { per_mirror, unused }
}

/// Give `rule.dir` to mirror `name` unless it is invalid or overlaps a
/// directory already claimed or another mirror's default path.
fn claim<'a>(
    rule: &Rule<'_>,
    name: &'a str,
    names: &'a [String],
    claimed: &mut Vec<(PathBuf, &'a str)>,
) -> Result<PathBuf, String> {
    let norm = normalize_mirror_path(rule.dir).map_err(|reason| {
        rule.not_applied(&format!(
            "path {reason}; tain paths are relative to [global] target"
        ))
    })?;
    let other_names = names
        .iter()
        .filter(|n| *n != name)
        .map(|n| (PathBuf::from(n), n.as_str()));
    let clash = claimed
        .iter()
        .cloned()
        .chain(other_names)
        .find(|(p, _)| norm.starts_with(p) || p.starts_with(&norm));
    if let Some((_, other)) = clash {
        return Err(rule.not_applied(&format!("it overlaps the directory of mirror `{other}`")));
    }
    claimed.push((norm, name));
    Ok(rule.dir.to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(lines: &[(&str, &str)]) -> Vec<Entry> {
        lines
            .iter()
            .enumerate()
            .map(|(i, (prefix, dir))| Entry::MirrorPath {
                line: i + 1,
                url_prefix: (*prefix).to_owned(),
                dir: PathBuf::from(dir),
            })
            .collect()
    }

    fn resolve_one(lines: &[(&str, &str)], url: &str) -> Resolution {
        let url = Url::parse(url).unwrap();
        resolve(&rules(lines), &[&url], &["m".to_owned()])
    }

    fn dir_of(res: &Resolution) -> Option<PathBuf> {
        res.per_mirror[0].clone().and_then(Result::ok)
    }

    #[test]
    fn matches_on_normalized_url_parts() {
        for (prefix, url) in [
            ("HTTP://X/Debian", "http://x/Debian"),
            ("http://y:80/d", "http://y/d"),
            ("https://y:443/d/", "https://y/d"),
            ("http://bücher.example/d", "http://xn--bcher-kva.example/d"),
            ("http://x/debian", "http://x/debian/sub/"),
        ] {
            let res = resolve_one(&[(prefix, "dd")], url);
            assert_eq!(dir_of(&res), Some(PathBuf::from("dd")), "{prefix} vs {url}");
            assert!(res.unused.is_empty(), "{:?}", res.unused);
        }
    }

    #[test]
    fn non_matching_rules_are_reported_not_dropped() {
        for (prefix, url) in [
            ("http://x/debian", "http://x/debian-security"),
            ("http://x/Debian", "http://x/debian"),
            ("https://x/d", "http://x/d"),
            ("http://x:8080/d", "http://x/d"),
        ] {
            let res = resolve_one(&[(prefix, "dd")], url);
            assert_eq!(dir_of(&res), None, "{prefix} vs {url}");
            assert_eq!(res.unused.len(), 1);
            assert!(
                res.unused[0].contains("best match for no deb line"),
                "{:?}",
                res.unused
            );
        }
    }

    #[test]
    fn longest_prefix_wins_and_shorter_is_reported() {
        let res = resolve_one(
            &[("http://x/", "short"), ("http://x/debian/pve", "pve")],
            "http://x/debian/pve/",
        );
        assert_eq!(dir_of(&res), Some(PathBuf::from("pve")));
        assert_eq!(res.unused.len(), 1);
        assert!(
            res.unused[0].contains("`short` (line 1)"),
            "{:?}",
            res.unused
        );
    }

    #[test]
    fn duplicate_prefix_last_wins_and_loser_is_reported() {
        let res = resolve_one(
            &[("http://x/d", "first"), ("http://x/d/", "second")],
            "http://x/d",
        );
        assert_eq!(dir_of(&res), Some(PathBuf::from("second")));
        assert_eq!(res.unused.len(), 1);
        assert!(
            res.unused[0].contains("(line 1) not applied: line 2 sets the same prefix"),
            "{:?}",
            res.unused
        );
    }

    #[test]
    fn unparsable_prefix_is_reported() {
        let res = resolve_one(&[("not a url", "dd")], "http://x/d");
        assert_eq!(dir_of(&res), None);
        assert!(res.unused[0].contains("not a URL"), "{:?}", res.unused);
    }

    #[test]
    fn canonical_trims_trailing_slashes_only() {
        for (raw, want) in [
            ("http://x/debian/", "http://x/debian"),
            ("http://x/debian", "http://x/debian"),
            ("http://x/", "http://x/"),
            ("http://x/a//", "http://x/a"),
        ] {
            assert_eq!(canonical(&Url::parse(raw).unwrap()).as_str(), want);
        }
    }
}
