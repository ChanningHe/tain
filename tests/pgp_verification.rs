//! `verify.pgp` against real Debian bookworm fixtures and a locally minted
//! expired key (all under `tests/fixtures/pgp/`, offline).

#![cfg(feature = "pgp")]

use std::path::PathBuf;

use tain::backends::apt::pgp::{PgpError, VerifyOutcome, verify_inrelease, verify_release_gpg};
use tain::config::model::PgpMode;

fn fixture(sub: &str) -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests/fixtures/pgp");
    p.push(sub);
    p
}

fn read(sub: &str) -> Vec<u8> {
    std::fs::read(fixture(sub)).unwrap_or_else(|e| panic!("read {sub}: {e}"))
}

#[test]
fn debian_bookworm_inrelease_verifies_with_binary_keyring() {
    let in_release = read("debian-bookworm/InRelease");
    let keyring = fixture("debian-bookworm/keyring.gpg");
    let outcome = verify_inrelease(PgpMode::Required, &in_release, true, Some(&keyring)).unwrap();
    assert_eq!(outcome, VerifyOutcome::Verified);
}

#[test]
fn debian_bookworm_inrelease_verifies_with_armored_keyring() {
    let in_release = read("debian-bookworm/InRelease");
    // Armor parsing may surface only the first cert; it is still a release signer.
    let keyring = fixture("debian-bookworm/keyring.asc");
    let outcome = verify_inrelease(PgpMode::Required, &in_release, true, Some(&keyring)).unwrap();
    assert_eq!(outcome, VerifyOutcome::Verified);
}

#[test]
fn debian_bookworm_release_gpg_detached_verifies() {
    let release = read("debian-bookworm/Release");
    let sig = read("debian-bookworm/Release.gpg");
    let keyring = fixture("debian-bookworm/keyring.gpg");
    let outcome =
        verify_release_gpg(PgpMode::Required, &release, Some(&sig), Some(&keyring)).unwrap();
    assert_eq!(outcome, VerifyOutcome::Verified);
}

#[test]
fn tampered_signature_is_rejected() {
    let release = read("debian-bookworm/Release");
    let mut sig = read("debian-bookworm/Release.gpg");
    // Flip a mid-payload byte, clear of the armor CRC at the end.
    let idx = sig.len() / 2;
    sig[idx] ^= 0xFF;
    let keyring = fixture("debian-bookworm/keyring.gpg");
    let err = verify_release_gpg(PgpMode::Required, &release, Some(&sig), Some(&keyring))
        .expect_err("tampered signature must not verify");
    assert!(
        matches!(
            err,
            PgpError::BadSignature { .. } | PgpError::SignatureParse { .. }
        ),
        "unexpected error: {err:?}"
    );
}

#[test]
fn tampered_body_is_rejected() {
    let mut release = read("debian-bookworm/Release");
    let idx = release.len() / 2;
    release[idx] ^= 0x01;
    let sig = read("debian-bookworm/Release.gpg");
    let keyring = fixture("debian-bookworm/keyring.gpg");
    let err = verify_release_gpg(PgpMode::Required, &release, Some(&sig), Some(&keyring))
        .expect_err("body tamper must not verify");
    assert!(
        matches!(err, PgpError::BadSignature { .. }),
        "unexpected error: {err:?}"
    );
}

#[test]
fn keyring_without_issuer_returns_no_usable_key() {
    let in_release = read("debian-bookworm/InRelease");
    let keyring = fixture("other-key/keyring.asc");
    let err = verify_inrelease(PgpMode::Required, &in_release, true, Some(&keyring))
        .expect_err("unrelated keyring must not accept");
    assert!(
        matches!(
            err,
            PgpError::BadSignature { .. } | PgpError::NoUsableKey { .. }
        ),
        "unexpected error: {err:?}"
    );
}

#[test]
fn expired_key_rejects_inrelease() {
    let in_release = read("expired/InRelease");
    let keyring = fixture("expired/keyring.asc");
    let err = verify_inrelease(PgpMode::Required, &in_release, true, Some(&keyring))
        .expect_err("expired key must not verify");
    assert!(
        matches!(
            err,
            PgpError::BadSignature { .. } | PgpError::NoUsableKey { .. }
        ),
        "unexpected error: {err:?}"
    );
}

#[test]
fn expired_key_rejects_release_gpg() {
    let body = read("expired/body.txt");
    let sig = read("expired/Release.gpg");
    let keyring = fixture("expired/keyring.asc");
    let err = verify_release_gpg(PgpMode::Required, &body, Some(&sig), Some(&keyring))
        .expect_err("expired key must not verify");
    assert!(
        matches!(
            err,
            PgpError::BadSignature { .. } | PgpError::NoUsableKey { .. }
        ),
        "unexpected error: {err:?}"
    );
}

#[test]
fn if_present_treats_bad_signature_as_hard_failure() {
    let release = read("debian-bookworm/Release");
    let mut sig = read("debian-bookworm/Release.gpg");
    let idx = sig.len() / 2;
    sig[idx] ^= 0xFF;
    let keyring = fixture("debian-bookworm/keyring.gpg");
    // apt semantics: `if-present` with a present but invalid signature is a hard failure.
    let err = verify_release_gpg(PgpMode::IfPresent, &release, Some(&sig), Some(&keyring))
        .expect_err("if-present + bad signature must fail");
    assert!(
        matches!(
            err,
            PgpError::BadSignature { .. } | PgpError::SignatureParse { .. }
        ),
        "unexpected error: {err:?}"
    );
}

#[test]
fn malformed_keyring_surfaces_keyring_load() {
    let tmp = tempdir().join("bogus.gpg");
    std::fs::write(&tmp, b"not a keyring at all\n").unwrap();
    let in_release = read("debian-bookworm/InRelease");
    let err = verify_inrelease(PgpMode::Required, &in_release, true, Some(&tmp))
        .expect_err("malformed keyring must not verify");
    assert!(
        matches!(err, PgpError::KeyringLoad { .. }),
        "unexpected error: {err:?}"
    );
    let _ = std::fs::remove_file(&tmp);
}

#[test]
fn random_signature_bytes_return_parse_error_never_panic() {
    let release = read("debian-bookworm/Release");
    let keyring = fixture("debian-bookworm/keyring.gpg");
    let mut seed: u64 = 0x12345678_9ABCDEF0;
    for iteration in 0..100 {
        // Deterministic PRNG for reproducible failures.
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        let len = ((seed as usize) % 512) + 32;
        let mut bytes = Vec::with_capacity(len);
        let mut s = seed;
        for _ in 0..len {
            s = s
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            bytes.push((s >> 33) as u8);
        }
        let result = verify_release_gpg(PgpMode::Required, &release, Some(&bytes), Some(&keyring));
        match result {
            Ok(VerifyOutcome::Verified) => {
                panic!("iteration {iteration}: random bytes must not verify")
            }
            Ok(other) => panic!("iteration {iteration}: unexpected Ok({other:?})"),
            Err(PgpError::SignatureParse { .. }) | Err(PgpError::BadSignature { .. }) => {}
            Err(PgpError::NoUsableKey { .. }) => {}
            Err(other) => panic!("iteration {iteration}: unexpected error {other:?}"),
        }
    }
}

fn tempdir() -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "tain-pgp-test-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

// --- subkey fixtures (tests/fixtures/pgp/subkeys/README.md) ---

fn verify_subkey_fixture(keyring: &str, sig: &str) -> Result<VerifyOutcome, PgpError> {
    let body = read("subkeys/body.txt");
    let sig = read(&format!("subkeys/{sig}"));
    let keyring = fixture(&format!("subkeys/{keyring}"));
    verify_release_gpg(PgpMode::Required, &body, Some(&sig), Some(&keyring))
}

#[test]
fn signing_subkey_with_valid_binding_verifies() {
    let outcome = verify_subkey_fixture("keyring.asc", "good.sig").unwrap();
    assert_eq!(outcome, VerifyOutcome::Verified);
}

#[test]
fn unrelated_key_signature_is_rejected() {
    let err = verify_subkey_fixture("keyring.asc", "rogue.sig").unwrap_err();
    assert!(
        matches!(err, PgpError::BadSignature { .. }),
        "unexpected error: {err:?}"
    );
}

#[test]
fn subkey_with_forged_binding_signature_is_rejected() {
    // forged.gpg grafts the rogue key under a certify-only primary with a
    // binding signature that does not cover it, leaving no usable signer.
    let err = verify_subkey_fixture("forged.gpg", "rogue.sig").unwrap_err();
    assert!(
        matches!(err, PgpError::NoUsableKey { .. }),
        "unexpected error: {err:?}"
    );
}

#[test]
fn revoked_subkey_is_rejected() {
    let err = verify_subkey_fixture("revoked.asc", "good.sig").unwrap_err();
    assert!(
        matches!(err, PgpError::NoUsableKey { .. }),
        "unexpected error: {err:?}"
    );
}

#[test]
fn revoked_primary_is_rejected() {
    let err = verify_subkey_fixture("revoked-primary.asc", "revoked-primary.sig").unwrap_err();
    assert!(
        matches!(err, PgpError::NoUsableKey { .. }),
        "unexpected error: {err:?}"
    );
}

#[test]
fn signature_older_than_key_is_rejected() {
    let err = verify_subkey_fixture("late.asc", "early.sig").unwrap_err();
    assert!(
        matches!(err, PgpError::NoUsableKey { .. }),
        "unexpected error: {err:?}"
    );
}

#[test]
fn detached_signature_verifies_via_its_second_packet() {
    // Two signature packets; the keyring holds only the second signer.
    for sig in ["dual.sig", "dual.sig.bin"] {
        let outcome = verify_subkey_fixture("dual-second.asc", sig).unwrap();
        assert_eq!(outcome, VerifyOutcome::Verified, "{sig}");
    }
}

#[test]
fn multi_packet_detached_signature_from_unknown_keys_is_rejected() {
    for sig in ["dual.sig", "dual.sig.bin"] {
        let err = verify_subkey_fixture("keyring.asc", sig).unwrap_err();
        assert!(
            matches!(err, PgpError::BadSignature { .. }),
            "{sig}: unexpected error: {err:?}"
        );
    }
}

#[test]
fn key_in_second_armor_block_of_keyring_verifies() {
    // concat.asc = `cat keyring.asc rogue-key.asc`.
    let outcome = verify_subkey_fixture("concat.asc", "rogue.sig").unwrap();
    assert_eq!(outcome, VerifyOutcome::Verified);
}

#[test]
fn signature_in_second_armor_block_verifies() {
    // concat.sig = `cat rogue.sig good.sig`; only good.sig's signer is trusted.
    let outcome = verify_subkey_fixture("keyring.asc", "concat.sig").unwrap();
    assert_eq!(outcome, VerifyOutcome::Verified);
}

#[test]
fn legacy_keyring_with_trust_packets_verifies() {
    // Same keys as keyring.asc, stored the way ubuntu-archive-keyring.gpg is.
    let outcome = verify_subkey_fixture("trust.gpg", "good.sig").unwrap();
    assert_eq!(outcome, VerifyOutcome::Verified);
}

#[test]
fn weak_digest_signatures_are_rejected() {
    for sig in ["md5.sig", "sha1.sig", "ripemd160.sig"] {
        let err = verify_subkey_fixture("keyring.asc", sig)
            .expect_err("weak-digest signature must not verify");
        assert!(
            matches!(err, PgpError::WeakDigest { .. }),
            "{sig}: unexpected error: {err:?}"
        );
    }
}
