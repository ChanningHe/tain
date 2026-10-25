//! Suite root files (`InRelease` / `Release` / `Release.gpg`): the change
//! token, the published copy on disk (spot-check, Date floor, PGP downgrade
//! guard) and vetting of sibling forms.

use std::path::Path;

use sha2::{Digest as _, Sha256};
use tracing::warn;

use crate::backends::apt::clearsign::{ReleaseKind, extract_signed_body};
use crate::backends::apt::datetime::parse_release_datetime;
use crate::backends::apt::pgp::{self, VerifyOutcome};
use crate::backends::apt::release::parse_release;
use crate::config::model::{PgpMode, VerifyConfig};

use super::hex::hex_of;
use super::root_fetch::{MAX_RELEASE_BYTES, MAX_SIGNATURE_BYTES};

/// Which signed body drives the sync: selects clearsign vs detached
/// verification, the recheck URL and the spot-checked file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum VerbatimKind {
    InRelease,
    Release,
}

impl VerbatimKind {
    pub(super) fn file_name(self) -> &'static str {
        match self {
            Self::InRelease => "InRelease",
            Self::Release => "Release",
        }
    }
}

/// Change token: SHA-256 of the signed body without trailing whitespace or
/// trailing blank lines — exactly what a clearsign signature covers. Armor,
/// signature packets and whitespace an on-path attacker can alter without
/// invalidating the signature therefore can't force a resync. (A genuine
/// re-signature of an unchanged body is picked up with the next body
/// change.)
pub(super) fn change_token(raw: &[u8]) -> String {
    let Ok(text) = std::str::from_utf8(raw) else {
        return raw_token(raw);
    };
    let Ok(extracted) = extract_signed_body(text) else {
        return raw_token(raw);
    };
    hex_of(Sha256::digest(canonical_text(&extracted.body).as_bytes()))
}

/// Pre-canonical token (v0.1.0 state files): SHA-256 of the raw bytes.
fn raw_token(raw: &[u8]) -> String {
    hex_of(Sha256::digest(raw))
}

/// True when `raw` is the body recorded as `token`, in either token form.
pub(super) fn token_matches(raw: &[u8], token: &str) -> bool {
    !token.is_empty() && (change_token(raw) == token || raw_token(raw) == token)
}

fn canonical_text(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for line in s.split('\n') {
        out.push_str(line.trim_end_matches([' ', '\t', '\r']));
        out.push('\n');
    }
    let kept = out.trim_end_matches('\n').len();
    out.truncate(kept);
    out
}

pub(super) fn is_clearsigned(bytes: &[u8]) -> bool {
    std::str::from_utf8(bytes)
        .ok()
        .and_then(|s| extract_signed_body(s).ok())
        .is_some_and(|e| e.kind == ReleaseKind::Clearsigned)
}

/// The suite root as currently published — the truth after a crash between
/// swap and state save.
pub(super) struct PublishedRoot {
    inrelease: Option<Vec<u8>>,
    release: Option<Vec<u8>>,
    release_gpg: Option<Vec<u8>>,
}

impl PublishedRoot {
    pub(super) fn read(dist_dir: &Path) -> Self {
        Self {
            inrelease: read_published(&dist_dir.join("InRelease"), MAX_RELEASE_BYTES),
            release: read_published(&dist_dir.join("Release"), MAX_RELEASE_BYTES),
            release_gpg: read_published(&dist_dir.join("Release.gpg"), MAX_SIGNATURE_BYTES),
        }
    }

    fn file(&self, kind: VerbatimKind) -> Option<&[u8]> {
        match kind {
            VerbatimKind::InRelease => self.inrelease.as_deref(),
            VerbatimKind::Release => self.release.as_deref(),
        }
    }

    /// Spot-check: does the published copy of this round's token source
    /// still carry `token`?
    pub(super) fn matches(&self, kind: VerbatimKind, token: &str) -> bool {
        self.file(kind).is_some_and(|b| token_matches(b, token))
    }

    /// The published `Date` that bounds this round (Date monotonicity).
    /// Only trusted forms count, so an unvetted sibling (e.g. published by v0.1.0) with a
    /// bogus future Date can't freeze the suite: with PGP on, the root
    /// files that verify now; otherwise the published driver of `kind`.
    /// `Required` with nothing verifiable yields no disk floor (state's
    /// Date still applies).
    pub(super) fn date_floor(&self, kind: VerbatimKind, verify: &VerifyConfig) -> Option<String> {
        let verified = self.verified_files(verify);
        let sources: Vec<&[u8]> = if !verified.is_empty() {
            verified
        } else if verify.pgp == PgpMode::Required {
            Vec::new()
        } else {
            self.file(kind).into_iter().collect()
        };
        sources
            .into_iter()
            .filter_map(published_date)
            .max_by_key(|(dt, _)| *dt)
            .map(|(_, raw)| raw)
    }

    fn verified_files(&self, verify: &VerifyConfig) -> Vec<&[u8]> {
        if verify.pgp == PgpMode::Off {
            return Vec::new();
        }
        let keyring = verify.keyring.as_deref();
        let mut out = Vec::new();
        if let Some(b) = self.inrelease.as_deref()
            && is_clearsigned(b)
            && matches!(
                pgp::verify_inrelease(PgpMode::Required, b, true, keyring),
                Ok(VerifyOutcome::Verified)
            )
        {
            out.push(b);
        }
        if let Some(release) = self.verified_release(keyring) {
            out.push(release);
        }
        out
    }

    /// The published Release, if the published Release.gpg verifies over it.
    fn verified_release(&self, keyring: Option<&Path>) -> Option<&[u8]> {
        let (release, sig) = (self.release.as_deref()?, self.release_gpg.as_deref()?);
        matches!(
            pgp::verify_release_gpg(PgpMode::Required, release, Some(sig), keyring),
            Ok(VerifyOutcome::Verified)
        )
        .then_some(release)
    }

    /// Which published file drove the last round, and so owns the stored
    /// cache validators: a usable InRelease (clearsigned under PGP), else
    /// Release.
    pub(super) fn driver(&self, pgp_on: bool) -> Option<VerbatimKind> {
        let usable_inrelease =
            self.inrelease.is_some() && !(pgp_on && self.has_unsigned_inrelease());
        if usable_inrelease {
            Some(VerbatimKind::InRelease)
        } else if self.release.is_some() {
            Some(VerbatimKind::Release)
        } else {
            None
        }
    }

    /// A published InRelease that isn't clearsigned. apt rejects it outright
    /// (no fallback to Release.gpg), so under PGP such a tree is broken.
    pub(super) fn has_unsigned_inrelease(&self) -> bool {
        self.inrelease
            .as_deref()
            .is_some_and(|b| !is_clearsigned(b))
    }

    /// A signature is published: a clearsigned InRelease, or a Release.gpg
    /// that verifies with the configured keyring. A Release.gpg alone is not
    /// enough — v0.1.0 republished siblings unvetted.
    pub(super) fn is_signed(&self, verify: &VerifyConfig) -> bool {
        let clearsigned = self.inrelease.as_deref().is_some_and(is_clearsigned);
        clearsigned || self.verified_release(verify.keyring.as_deref()).is_some()
    }
}

/// A symlink is ignored: a crafted target could otherwise vouch for an
/// arbitrary published tree.
fn read_published(path: &Path, cap: usize) -> Option<Vec<u8>> {
    let meta = std::fs::symlink_metadata(path).ok()?;
    if meta.file_type().is_symlink() {
        warn!(path = %path.display(), "published root file is a symlink — ignoring it");
        return None;
    }
    if !meta.is_file() || meta.len() > cap as u64 {
        return None;
    }
    std::fs::read(path).ok()
}

/// `Date` of a published root file. An unreadable one is reported and
/// skipped; state's Date remains a floor.
fn published_date(bytes: &[u8]) -> Option<(time::OffsetDateTime, String)> {
    let parsed = std::str::from_utf8(bytes)
        .ok()
        .and_then(|text| extract_signed_body(text).ok())
        .and_then(|e| parse_release(&e.body).ok());
    let Some((header, _)) = parsed else {
        warn!("published root file does not parse — ignoring it as a Date floor");
        return None;
    };
    let raw = header.date_raw?;
    match parse_release_datetime(&raw) {
        Ok(dt) => Some((dt, raw)),
        Err(e) => {
            warn!(date = %raw, err = %e, "published Date does not parse — ignoring it as a floor");
            None
        }
    }
}

/// InRelease-mode siblings worth publishing. `Release` only when it carries
/// the same canonical content as the verified InRelease; `Release.gpg` only
/// next to it and, with PGP on, only when it verifies over those bytes.
/// Anything else (stale CDN copy, on-path garbage) is dropped, never
/// published.
pub(super) fn vet_siblings(
    inrelease_body: &str,
    release: Option<Vec<u8>>,
    release_gpg: Option<Vec<u8>>,
    verify: &VerifyConfig,
    suite: &str,
) -> Vec<(&'static str, Vec<u8>)> {
    let Some(release) = release else {
        return Vec::new();
    };
    let same_content = std::str::from_utf8(&release)
        .is_ok_and(|r| canonical_text(r) == canonical_text(inrelease_body));
    if !same_content {
        warn!(
            suite,
            "upstream Release differs from the InRelease signed body — not publishing it"
        );
        return Vec::new();
    }
    let mut out = Vec::with_capacity(2);
    if let Some(sig) = release_gpg {
        if detached_signature_ok(&release, &sig, verify) {
            out.push(("Release.gpg", sig));
        } else {
            warn!(
                suite,
                "upstream Release.gpg does not verify over Release — not publishing it"
            );
        }
    }
    out.push(("Release", release));
    out
}

fn detached_signature_ok(release: &[u8], sig: &[u8], verify: &VerifyConfig) -> bool {
    if verify.pgp == PgpMode::Off {
        return true;
    }
    matches!(
        pgp::verify_release_gpg(
            PgpMode::Required,
            release,
            Some(sig),
            verify.keyring.as_deref(),
        ),
        Ok(VerifyOutcome::Verified)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const BODY: &str = "Suite: x\nDate: Sat, 03 Feb 2024 09:15:38 UTC\n";

    fn clearsigned(body: &str, sig: &str) -> String {
        format!(
            "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n{body}-----BEGIN PGP SIGNATURE-----\n\n{sig}\n=AbCd\n-----END PGP SIGNATURE-----\n"
        )
    }

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("tain-rootfiles-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn token_ignores_whitespace_and_signature_packets() {
        let a = clearsigned(BODY, "iQEzBAEB\nCAAdFiEE");
        let b = clearsigned(
            "Suite: x  \nDate: Sat, 03 Feb 2024 09:15:38 UTC\t\n\n",
            "iQEzBAEC",
        )
        .replace("Hash: SHA256", "Hash: SHA256\nComment: injected")
            + "\n\n";
        assert_eq!(change_token(a.as_bytes()), change_token(b.as_bytes()));
    }

    #[test]
    fn token_tracks_body_changes() {
        let a = clearsigned(BODY, "iQEzBAEB");
        let body = clearsigned("Suite: y\n", "iQEzBAEB");
        assert_ne!(change_token(a.as_bytes()), change_token(body.as_bytes()));
        // Same body as a plain Release: same content, same token.
        assert_eq!(change_token(a.as_bytes()), change_token(BODY.as_bytes()));
    }

    #[test]
    fn legacy_raw_token_still_matches() {
        let raw = clearsigned(BODY, "iQEzBAEB");
        let legacy = hex_of(Sha256::digest(raw.as_bytes()));
        assert!(token_matches(raw.as_bytes(), &legacy));
        assert!(token_matches(raw.as_bytes(), &change_token(raw.as_bytes())));
        assert!(!token_matches(raw.as_bytes(), ""));
    }

    #[test]
    fn sibling_release_kept_only_when_content_matches() {
        let off = VerifyConfig::default();
        let kept = vet_siblings(BODY, Some(BODY.as_bytes().to_vec()), None, &off, "x");
        assert_eq!(kept.len(), 1);
        // gpg's clearsign keeps one extra newline before the signature.
        let body_nl = format!("{BODY}\n");
        assert_eq!(
            vet_siblings(&body_nl, Some(BODY.as_bytes().to_vec()), None, &off, "x").len(),
            1
        );
        let stale = BODY.replace("2024", "2023");
        let gpg = Some(b"sig".to_vec());
        assert!(vet_siblings(BODY, Some(stale.into_bytes()), gpg.clone(), &off, "x").is_empty());
        assert!(vet_siblings(BODY, None, gpg, &off, "x").is_empty());
    }

    #[test]
    fn unverifiable_release_gpg_is_dropped_when_pgp_is_on() {
        let on = VerifyConfig {
            pgp: PgpMode::Required,
            keyring: None,
            allow_weak_hash: false,
        };
        let kept = vet_siblings(
            BODY,
            Some(BODY.as_bytes().to_vec()),
            Some(b"garbage".to_vec()),
            &on,
            "x",
        );
        let names: Vec<_> = kept.iter().map(|(n, _)| *n).collect();
        assert_eq!(names, vec!["Release"]);
    }

    #[test]
    fn date_floor_reads_only_the_driver_without_pgp() {
        let dir = temp_dir("floor");
        std::fs::write(dir.join("Release"), BODY).unwrap();
        let newer = clearsigned("Date: Sun, 04 Feb 2024 09:15:38 UTC\n", "iQEz");
        std::fs::write(dir.join("InRelease"), &newer).unwrap();
        let root = PublishedRoot::read(&dir);
        let off = VerifyConfig::default();
        assert_eq!(
            root.date_floor(VerbatimKind::InRelease, &off).as_deref(),
            Some("Sun, 04 Feb 2024 09:15:38 UTC")
        );
        assert_eq!(
            root.date_floor(VerbatimKind::Release, &off).as_deref(),
            Some("Sat, 03 Feb 2024 09:15:38 UTC")
        );
        // `Required` trusts only what verifies now — nothing here does.
        let required = VerifyConfig {
            pgp: PgpMode::Required,
            ..VerifyConfig::default()
        };
        assert!(
            root.date_floor(VerbatimKind::InRelease, &required)
                .is_none()
        );
        assert!(root.is_signed(&required));
        assert!(root.matches(VerbatimKind::Release, &change_token(BODY.as_bytes())));
        std::fs::remove_dir_all(&dir).ok();
    }

    fn if_present_with_fixture_keyring() -> VerifyConfig {
        VerifyConfig {
            pgp: PgpMode::IfPresent,
            keyring: Some(
                std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("tests/fixtures/pgp/signed-repo/keyring.asc"),
            ),
            allow_weak_hash: false,
        }
    }

    /// A Release.gpg published unvetted (v0.1.0) must not count as a
    /// signature, or `if-present` would report a false downgrade.
    #[test]
    fn unverified_detached_signature_is_not_signed() {
        let dir = temp_dir("gpg");
        for name in ["InRelease", "Release"] {
            std::fs::write(dir.join(name), BODY).unwrap();
        }
        let verify = if_present_with_fixture_keyring();
        assert!(!PublishedRoot::read(&dir).is_signed(&verify));
        std::fs::write(dir.join("Release.gpg"), b"sig").unwrap();
        let root = PublishedRoot::read(&dir);
        assert!(!root.is_signed(&verify));
        assert!(root.has_unsigned_inrelease());
        std::fs::write(dir.join("InRelease"), clearsigned(BODY, "iQEz")).unwrap();
        assert!(!PublishedRoot::read(&dir).has_unsigned_inrelease());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(feature = "pgp")]
    #[test]
    fn verifying_detached_signature_counts_as_signed() {
        let fixture = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/pgp/signed-repo/dists/bookworm");
        let dir = temp_dir("gpg-ok");
        for name in ["Release", "Release.gpg"] {
            std::fs::copy(fixture.join(name), dir.join(name)).unwrap();
        }
        let root = PublishedRoot::read(&dir);
        assert!(root.is_signed(&if_present_with_fixture_keyring()));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn published_symlink_is_ignored() {
        let dir = temp_dir("ln");
        std::fs::write(dir.join("real"), BODY).unwrap();
        std::os::unix::fs::symlink(dir.join("real"), dir.join("InRelease")).unwrap();
        let root = PublishedRoot::read(&dir);
        assert!(!root.matches(VerbatimKind::InRelease, &change_token(BODY.as_bytes())));
        let off = VerifyConfig::default();
        assert!(root.date_floor(VerbatimKind::InRelease, &off).is_none());
        std::fs::remove_dir_all(&dir).ok();
    }
}
