//! Per-line verdicts for the importer: whether a `deb` line converts and
//! which of its parts are left out. The checks are the ones `tain check`
//! applies, so the generated TOML always loads.

use std::borrow::Cow;
use std::path::Path;

use super::{DebEntry, Entry};
use crate::backends::apt::unsafe_suite_reason;
use crate::config::model::{
    apt_value_problem, has_query_or_fragment, is_apt_value, is_flat_suite, keyring_path_problem,
};
use crate::config::toml_quote::comment_safe;

/// Why a line cannot be converted, or `None` if it can.
pub(super) fn skip_reason(d: &DebEntry) -> Option<Cow<'static, str>> {
    if let Some(why) = &d.unsupported_option {
        return Some(Cow::Owned(comment_safe(why)));
    }
    let why = if is_flat_suite(&d.suite) {
        "flat repositories are not supported yet"
    } else if !matches!(d.url.scheme(), "http" | "https") {
        "only http and https URLs are supported"
    } else if has_query_or_fragment(&d.url) {
        "the URL has a query or fragment, which tain cannot request"
    } else if !is_apt_value(&d.suite, true) {
        "the suite is not a valid apt suite name"
    } else if d
        .arch_override
        .iter()
        .flatten()
        .any(|a| !is_apt_value(a, false))
    {
        "an architecture is not a valid apt architecture name"
    } else if d.components.is_empty() {
        "a dists-style suite needs at least one component"
    } else if kept_components(d).next().is_none() {
        "no component is a valid apt component name"
    } else if unsafe_suite_reason(&d.url, &d.suite).is_some() {
        "the suite does not stay inside the mirror"
    } else {
        d.keyring.as_deref().and_then(signed_by_problem)?
    };
    Some(Cow::Borrowed(why))
}

/// Why a `signed-by=` value cannot become `verify.keyring`. Such a line is
/// not converted at all: a mirror of it would not check signatures.
fn signed_by_problem(value: &Path) -> Option<&'static str> {
    let text = value.to_string_lossy();
    if !cfg!(feature = "pgp") {
        Some("`signed-by` needs OpenPGP support, which this tain build lacks")
    } else if text.split(',').any(is_fingerprint) {
        Some(
            "`signed-by` names key fingerprints; tain needs one keyring file (export the keys to it)",
        )
    } else if text.contains(',') {
        Some("`signed-by` lists several keyrings; tain takes one keyring file")
    } else if keyring_path_problem(value).is_some() {
        Some("`signed-by` is not an absolute keyring path without control characters")
    } else {
        None
    }
}

/// A v4 (40) or v5 (64 hex digit) key fingerprint, optionally with apt's
/// exact-subkey `!` suffix.
fn is_fingerprint(s: &str) -> bool {
    let hex = s.strip_suffix('!').unwrap_or(s);
    matches!(hex.len(), 40 | 64) && hex.bytes().all(|b| b.is_ascii_hexdigit())
}

/// The components `tain check` accepts, in source order.
pub(super) fn kept_components(d: &DebEntry) -> impl Iterator<Item = &String> {
    d.components.iter().filter(|c| is_apt_value(c, false))
}

/// Lines that are emitted only as comments, with the reason.
pub(super) fn skipped_entries(
    entries: &[Entry],
) -> impl Iterator<Item = (&DebEntry, Cow<'static, str>)> {
    entries.iter().filter_map(|e| match e {
        Entry::Deb(d) => skip_reason(d).map(|r| (&**d, r)),
        Entry::MirrorPath { .. } => None,
    })
}

/// What a converted line loses on the way: invalid components and options
/// that do not affect the mirror.
pub(super) fn dropped_parts(d: &DebEntry) -> Vec<String> {
    let mut notes: Vec<String> = d
        .components
        .iter()
        .filter_map(|c| {
            let why = apt_value_problem(c, false)?;
            Some(format!(
                "line {}: component `{}` dropped: it {why}",
                d.line,
                comment_safe(c)
            ))
        })
        .collect();
    if !d.ignored_options.is_empty() {
        notes.push(format!(
            "line {}: options ignored (tain selects indexes in `[mirror.indexes]` and verifies \
             only what `signed-by` names): {}",
            d.line,
            comment_safe(&d.ignored_options.join(" "))
        ));
    }
    notes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprints_are_recognized_by_length_and_hex() {
        assert!(is_fingerprint(&"A".repeat(40)));
        assert!(is_fingerprint(&format!("{}!", "f".repeat(64))));
        assert!(!is_fingerprint(&"A".repeat(39)));
        assert!(!is_fingerprint(&"g".repeat(40)));
    }

    #[cfg(feature = "pgp")]
    #[test]
    fn only_one_absolute_keyring_path_is_usable() {
        assert!(signed_by_problem(Path::new("/etc/k.gpg")).is_none());
        for bad in ["k.gpg", "/a.gpg,/b.gpg", "/k\u{7}.gpg", &"A".repeat(40)] {
            assert!(signed_by_problem(Path::new(bad)).is_some(), "{bad}");
        }
    }

    #[cfg(not(feature = "pgp"))]
    #[test]
    fn no_signed_by_is_usable_without_pgp() {
        assert!(signed_by_problem(Path::new("/etc/k.gpg")).is_some());
    }
}
