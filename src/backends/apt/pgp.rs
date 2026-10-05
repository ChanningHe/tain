//! PGP verification of `InRelease` / `Release.gpg` against a `.gpg` or `.asc` keyring.
//!
//! Modes: `off` skips; `if-present` accepts a missing signature but rejects a bad one
//! (apt semantics); `required` rejects both. Without the `pgp` feature, any check that
//! needs a signature fails with `PgpError::PgpFeatureDisabled`.

use std::path::Path;

use crate::config::model::PgpMode;

/// Verify (or accept) an `InRelease` clearsign document.
///
/// `armored_input` is the raw InRelease as served. `is_clearsigned == false` (plain-body
/// InRelease) counts as an absent signature.
///
/// # Errors
///
/// See [`PgpError`].
pub fn verify_inrelease(
    mode: PgpMode,
    armored_input: &[u8],
    is_clearsigned: bool,
    keyring_path: Option<&Path>,
) -> Result<VerifyOutcome, PgpError> {
    match mode {
        PgpMode::Off => return Ok(VerifyOutcome::Skipped),
        PgpMode::IfPresent if !is_clearsigned => return Ok(VerifyOutcome::AbsentInIfPresent),
        PgpMode::IfPresent | PgpMode::Required => {}
    }
    let keyring_path = keyring_path.ok_or(PgpError::KeyringMissing)?;
    if !is_clearsigned {
        return Err(PgpError::RequiredButAbsent {
            artifact: PGP_ARTIFACT_INRELEASE,
        });
    }
    imp::verify_clearsigned(armored_input, keyring_path, PGP_ARTIFACT_INRELEASE)
}

/// Verify a plain `Release` against its detached `Release.gpg`.
///
/// # Errors
///
/// See [`PgpError`].
pub fn verify_release_gpg(
    mode: PgpMode,
    release_bytes: &[u8],
    signature_bytes: Option<&[u8]>,
    keyring_path: Option<&Path>,
) -> Result<VerifyOutcome, PgpError> {
    match mode {
        PgpMode::Off => return Ok(VerifyOutcome::Skipped),
        PgpMode::IfPresent if signature_bytes.is_none() => {
            return Ok(VerifyOutcome::AbsentInIfPresent);
        }
        PgpMode::IfPresent | PgpMode::Required => {}
    }
    let keyring_path = keyring_path.ok_or(PgpError::KeyringMissing)?;
    let Some(signature) = signature_bytes else {
        return Err(PgpError::RequiredButAbsent {
            artifact: PGP_ARTIFACT_RELEASE_GPG,
        });
    };
    imp::verify_detached(
        release_bytes,
        signature,
        keyring_path,
        PGP_ARTIFACT_RELEASE_GPG,
    )
}

/// Outcome of a signature check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyOutcome {
    /// Mode was `Off`.
    Skipped,
    Verified,
    /// Mode was `IfPresent` and no signature was present.
    AbsentInIfPresent,
}

const PGP_ARTIFACT_INRELEASE: &str = "InRelease";
const PGP_ARTIFACT_RELEASE_GPG: &str = "Release.gpg";

#[derive(Debug, thiserror::Error)]
pub enum PgpError {
    #[error(
        "verify.pgp = required needs a Release.gpg / InRelease clearsign signature but none was present for {artifact}"
    )]
    RequiredButAbsent { artifact: &'static str },
    /// Only reachable when a caller bypasses config validation.
    #[error("verify.pgp is not `off` but no verify.keyring is configured")]
    KeyringMissing,
    #[error("failed to load keyring `{}`: {source}", path.display())]
    KeyringLoad {
        path: std::path::PathBuf,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    #[error("could not parse PGP signature for {artifact}: {source}")]
    SignatureParse {
        artifact: &'static str,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    #[error("PGP signature for {artifact} did not verify against any key in the keyring")]
    BadSignature { artifact: &'static str },
    #[error("keyring holds no key that could have signed {artifact}")]
    NoUsableKey { artifact: &'static str },
    #[error(
        "PGP verification for {artifact} was requested but the tain binary was built without the `pgp` cargo feature"
    )]
    PgpFeatureDisabled { artifact: &'static str },
}

#[cfg(feature = "pgp")]
mod imp {
    use super::{PgpError, VerifyOutcome};
    use pgp::composed::{
        CleartextSignedMessage, Deserializable, DetachedSignature, SignedPublicKey,
    };
    use pgp::types::KeyDetails as _;
    use std::io::BufReader;
    use std::path::Path;
    use std::time::{Duration, SystemTime};

    fn to_std_duration(d: pgp::types::Duration) -> Duration {
        Duration::from(d)
    }

    pub(super) fn verify_clearsigned(
        armored_input: &[u8],
        keyring_path: &Path,
        artifact: &'static str,
    ) -> Result<VerifyOutcome, PgpError> {
        let keys = load_keyring(keyring_path)?;

        let (msg, _headers) = CleartextSignedMessage::from_armor(armored_input).map_err(|e| {
            PgpError::SignatureParse {
                artifact,
                source: Box::new(SnafuWrap(e.to_string())),
            }
        })?;

        let now = SystemTime::now();
        let mut ever_attempted = false;
        for cert in &keys {
            if !key_expired(cert, now) {
                ever_attempted = true;
                if msg.verify(&cert.primary_key).is_ok() {
                    return Ok(VerifyOutcome::Verified);
                }
            }
            for sub in &cert.public_subkeys {
                if subkey_expired(sub, now) {
                    continue;
                }
                ever_attempted = true;
                if msg.verify(&sub.key).is_ok() {
                    return Ok(VerifyOutcome::Verified);
                }
            }
        }
        if ever_attempted {
            Err(PgpError::BadSignature { artifact })
        } else {
            Err(PgpError::NoUsableKey { artifact })
        }
    }

    pub(super) fn verify_detached(
        body: &[u8],
        signature_bytes: &[u8],
        keyring_path: &Path,
        artifact: &'static str,
    ) -> Result<VerifyOutcome, PgpError> {
        let keys = load_keyring(keyring_path)?;

        let sig = parse_detached(signature_bytes).map_err(|e| PgpError::SignatureParse {
            artifact,
            source: Box::new(SnafuWrap(e)),
        })?;

        let now = SystemTime::now();
        let mut ever_attempted = false;
        for cert in &keys {
            if !key_expired(cert, now) {
                ever_attempted = true;
                if sig.verify(&cert.primary_key, body).is_ok() {
                    return Ok(VerifyOutcome::Verified);
                }
            }
            for sub in &cert.public_subkeys {
                if subkey_expired(sub, now) {
                    continue;
                }
                ever_attempted = true;
                if sig.verify(&sub.key, body).is_ok() {
                    return Ok(VerifyOutcome::Verified);
                }
            }
        }
        if ever_attempted {
            Err(PgpError::BadSignature { artifact })
        } else {
            Err(PgpError::NoUsableKey { artifact })
        }
    }

    fn load_keyring(path: &Path) -> Result<Vec<SignedPublicKey>, PgpError> {
        let file = std::fs::File::open(path).map_err(|e| PgpError::KeyringLoad {
            path: path.to_path_buf(),
            source: Box::new(e),
        })?;
        // Auto-detects armored vs binary; multi-key bundles are supported.
        let reader = BufReader::new(file);
        let (iter, _headers) =
            SignedPublicKey::from_reader_many_buf(reader).map_err(|e| PgpError::KeyringLoad {
                path: path.to_path_buf(),
                source: Box::new(SnafuWrap(e.to_string())),
            })?;
        let keys: Vec<SignedPublicKey> =
            iter.collect::<Result<Vec<_>, _>>()
                .map_err(|e| PgpError::KeyringLoad {
                    path: path.to_path_buf(),
                    source: Box::new(SnafuWrap(e.to_string())),
                })?;
        if keys.is_empty() {
            return Err(PgpError::KeyringLoad {
                path: path.to_path_buf(),
                source: Box::new(SnafuWrap("keyring contains no OpenPGP public keys".into())),
            });
        }
        Ok(keys)
    }

    fn parse_detached(bytes: &[u8]) -> Result<DetachedSignature, String> {
        // Armored first, then binary packets.
        if let Ok((sig, _)) = DetachedSignature::from_armor_single(bytes) {
            return Ok(sig);
        }
        DetachedSignature::from_bytes(bytes).map_err(|e| e.to_string())
    }

    fn key_expired(cert: &SignedPublicKey, now: SystemTime) -> bool {
        let created = SystemTime::from(cert.primary_key.created_at());
        // Expiration lives on a direct-key signature or a user self-certification.
        let expiration = cert
            .details
            .direct_signatures
            .iter()
            .find_map(|s| s.key_expiration_time())
            .or_else(|| {
                cert.details
                    .users
                    .iter()
                    .flat_map(|u| u.signatures.iter())
                    .find_map(|s| s.key_expiration_time())
            });
        match expiration {
            Some(dur) if dur.as_secs() > 0 => now > created + to_std_duration(dur),
            _ => false,
        }
    }

    fn subkey_expired(sub: &pgp::composed::SignedPublicSubKey, now: SystemTime) -> bool {
        let created = SystemTime::from(sub.key.created_at());
        let expiration = sub.signatures.iter().find_map(|s| s.key_expiration_time());
        match expiration {
            Some(dur) if dur.as_secs() > 0 => now > created + to_std_duration(dur),
            _ => false,
        }
    }

    #[derive(Debug)]
    struct SnafuWrap(String);
    impl std::fmt::Display for SnafuWrap {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(&self.0)
        }
    }
    impl std::error::Error for SnafuWrap {}
}

#[cfg(not(feature = "pgp"))]
mod imp {
    use super::{PgpError, VerifyOutcome};
    use std::path::Path;

    pub(super) fn verify_clearsigned(
        _armored_input: &[u8],
        _keyring_path: &Path,
        artifact: &'static str,
    ) -> Result<VerifyOutcome, PgpError> {
        Err(PgpError::PgpFeatureDisabled { artifact })
    }

    pub(super) fn verify_detached(
        _body: &[u8],
        _signature_bytes: &[u8],
        _keyring_path: &Path,
        artifact: &'static str,
    ) -> Result<VerifyOutcome, PgpError> {
        Err(PgpError::PgpFeatureDisabled { artifact })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn off_always_skips() {
        assert_eq!(
            verify_inrelease(PgpMode::Off, b"body", true, None).unwrap(),
            VerifyOutcome::Skipped
        );
        assert_eq!(
            verify_release_gpg(PgpMode::Off, b"body", None, None).unwrap(),
            VerifyOutcome::Skipped
        );
    }

    #[test]
    fn if_present_absent_for_release_gpg() {
        let r = verify_release_gpg(PgpMode::IfPresent, b"body", None, None).unwrap();
        assert_eq!(r, VerifyOutcome::AbsentInIfPresent);
    }

    #[test]
    fn if_present_plain_inrelease_is_absent() {
        let r = verify_inrelease(PgpMode::IfPresent, b"body", false, None).unwrap();
        assert_eq!(r, VerifyOutcome::AbsentInIfPresent);
    }

    #[test]
    fn required_missing_keyring_errors() {
        let err = verify_inrelease(PgpMode::Required, b"body", true, None).unwrap_err();
        assert!(matches!(err, PgpError::KeyringMissing));
    }

    #[test]
    fn if_present_signed_inrelease_without_keyring_errors() {
        let err = verify_inrelease(PgpMode::IfPresent, b"body", true, None).unwrap_err();
        assert!(matches!(err, PgpError::KeyringMissing), "{err:?}");
    }

    #[test]
    fn if_present_release_gpg_without_keyring_errors() {
        let err = verify_release_gpg(PgpMode::IfPresent, b"body", Some(b"sig"), None).unwrap_err();
        assert!(matches!(err, PgpError::KeyringMissing), "{err:?}");
    }

    #[test]
    fn required_release_gpg_without_keyring_errors() {
        let err = verify_release_gpg(PgpMode::Required, b"body", Some(b"sig"), None).unwrap_err();
        assert!(matches!(err, PgpError::KeyringMissing), "{err:?}");
    }

    #[test]
    fn required_missing_signature_errors() {
        let key = PathBuf::from("/dev/null");
        let err = verify_release_gpg(PgpMode::Required, b"body", None, Some(&key)).unwrap_err();
        assert!(matches!(err, PgpError::RequiredButAbsent { .. }));
    }

    #[test]
    fn required_plain_inrelease_errors() {
        let key = PathBuf::from("/dev/null");
        let err = verify_inrelease(PgpMode::Required, b"body", false, Some(&key)).unwrap_err();
        assert!(matches!(err, PgpError::RequiredButAbsent { .. }));
    }

    #[cfg(feature = "pgp")]
    #[test]
    fn required_with_unusable_keyring_errors() {
        let key = PathBuf::from("/nonexistent/tain/test/keyring.gpg");
        let err =
            verify_inrelease(PgpMode::Required, b"-not-a-frame-", true, Some(&key)).unwrap_err();
        assert!(
            matches!(
                err,
                PgpError::KeyringLoad { .. } | PgpError::SignatureParse { .. }
            ),
            "unexpected error: {err:?}"
        );
    }

    #[cfg(not(feature = "pgp"))]
    #[test]
    fn if_present_with_signature_without_pgp_feature_errors() {
        let key = PathBuf::from("/dev/null");
        let err = verify_inrelease(PgpMode::IfPresent, b"body", true, Some(&key)).unwrap_err();
        assert!(matches!(err, PgpError::PgpFeatureDisabled { .. }));
    }
}
