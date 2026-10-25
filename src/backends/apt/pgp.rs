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
    #[error("PGP signature for {artifact} uses the weak digest {digest}, which apt rejects")]
    WeakDigest {
        artifact: &'static str,
        digest: String,
    },
    #[error(
        "PGP verification for {artifact} was requested but the tain binary was built without the `pgp` cargo feature"
    )]
    PgpFeatureDisabled { artifact: &'static str },
}

#[cfg(feature = "pgp")]
mod imp {
    //! Key usability follows gpgv as driven by apt: only self-signatures that
    //! verify count, revoked keys are dead, signing subkeys need a verified
    //! binding with the sign flag plus a back-signature, and both the signer and
    //! its primary must be valid at signature time and now.

    use super::{PgpError, VerifyOutcome};
    use pgp::armor::Dearmor;
    use pgp::composed::{
        CleartextSignedMessage, Deserializable, DetachedSignature, SignedPublicKey,
        SignedPublicSubKey,
    };
    use pgp::crypto::hash::HashAlgorithm;
    use pgp::packet::{
        Packet, PacketParser, PublicKey, PublicSubkey, Signature, SignatureType, SubpacketData,
    };
    use pgp::types::{KeyDetails as _, Tag};
    use std::io::Read as _;
    use std::path::Path;
    use std::time::SystemTime;

    /// Signatures examined per document; real archives use one to three, and
    /// each extra one costs a trial verification per keyring key.
    const MAX_SIGNATURES: usize = 32;

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
        let text = msg.signed_text();
        verify_any(&keys, msg.signatures(), text.as_bytes(), artifact)
    }

    pub(super) fn verify_detached(
        body: &[u8],
        signature_bytes: &[u8],
        keyring_path: &Path,
        artifact: &'static str,
    ) -> Result<VerifyOutcome, PgpError> {
        let keys = load_keyring(keyring_path)?;
        let sigs = parse_detached(signature_bytes).map_err(|e| PgpError::SignatureParse {
            artifact,
            source: Box::new(SnafuWrap(e)),
        })?;
        verify_any(&keys, &sigs, body, artifact)
    }

    fn verify_any(
        keys: &[SignedPublicKey],
        sigs: &[Signature],
        data: &[u8],
        artifact: &'static str,
    ) -> Result<VerifyOutcome, PgpError> {
        let sigs = &sigs[..sigs.len().min(MAX_SIGNATURES)];
        let candidates: Vec<Candidate<'_>> = keys.iter().flat_map(candidates).collect();
        let now = SystemTime::now();
        let mut weak = Vec::new();
        let mut ever_attempted = false;
        for sig in sigs {
            if let Some(alg) = sig.hash_alg().filter(is_weak_digest) {
                weak.push(alg);
                continue;
            }
            let Some(sig_time) = sig.created().map(SystemTime::from) else {
                continue;
            };
            for c in candidates
                .iter()
                .filter(|c| c.valid_at(sig_time) && c.valid_at(now))
            {
                ever_attempted = true;
                if c.verifies(sig, data) {
                    return Ok(VerifyOutcome::Verified);
                }
            }
        }
        if let Some(alg) = weak.first().filter(|_| weak.len() == sigs.len()) {
            return Err(PgpError::WeakDigest {
                artifact,
                digest: alg.to_string(),
            });
        }
        if ever_attempted {
            Err(PgpError::BadSignature { artifact })
        } else {
            Err(PgpError::NoUsableKey { artifact })
        }
    }

    /// gpgv as invoked by apt treats these as invalid.
    fn is_weak_digest(alg: &HashAlgorithm) -> bool {
        matches!(
            alg,
            HashAlgorithm::Md5 | HashAlgorithm::Sha1 | HashAlgorithm::Ripemd160
        )
    }

    enum KeyRef<'a> {
        Primary(&'a PublicKey),
        Sub(&'a PublicSubkey),
    }

    /// A key allowed to sign data, valid in `[created, expires)`.
    struct Candidate<'a> {
        key: KeyRef<'a>,
        created: SystemTime,
        expires: Option<SystemTime>,
    }

    impl Candidate<'_> {
        fn valid_at(&self, t: SystemTime) -> bool {
            self.created <= t && self.expires.is_none_or(|e| t < e)
        }

        fn verifies(&self, sig: &Signature, data: &[u8]) -> bool {
            match self.key {
                KeyRef::Primary(k) => sig.verify(k, data).is_ok(),
                KeyRef::Sub(k) => sig.verify(k, data).is_ok(),
            }
        }
    }

    /// Signing-capable keys of one certificate; empty if the primary is
    /// revoked or has no verifiable self-signature.
    fn candidates(cert: &SignedPublicKey) -> Vec<Candidate<'_>> {
        let pk = &cert.primary_key;
        if cert
            .details
            .revocation_signatures
            .iter()
            .any(|s| s.verify_key(pk).is_ok())
        {
            return Vec::new();
        }
        let Some(self_sig) = newest_self_signature(cert) else {
            return Vec::new();
        };
        let created = SystemTime::from(pk.created_at());
        let expires = expiry(created, self_sig);
        let mut out = Vec::new();
        // Legacy keys without a key-flags subpacket may sign with the primary.
        if !has_key_flags(self_sig) || self_sig.key_flags().sign() {
            out.push(Candidate {
                key: KeyRef::Primary(pk),
                created,
                expires,
            });
        }
        out.extend(
            cert.public_subkeys
                .iter()
                .filter_map(|sub| subkey_candidate(pk, sub, created, expires)),
        );
        out
    }

    /// Newest direct-key or user-ID self-signature that actually verifies.
    fn newest_self_signature(cert: &SignedPublicKey) -> Option<&Signature> {
        let pk = &cert.primary_key;
        let direct = cert
            .details
            .direct_signatures
            .iter()
            .filter(|s| s.verify_key(pk).is_ok());
        let user = cert.details.users.iter().flat_map(|u| {
            u.signatures.iter().filter(move |s| {
                s.typ() != Some(SignatureType::CertRevocation)
                    && s.verify_certification(pk, Tag::UserId, &u.id).is_ok()
            })
        });
        direct.chain(user).max_by_key(|s| s.created())
    }

    fn subkey_candidate<'a>(
        pk: &PublicKey,
        sub: &'a SignedPublicSubKey,
        primary_created: SystemTime,
        primary_expires: Option<SystemTime>,
    ) -> Option<Candidate<'a>> {
        let bound = |s: &&Signature| s.verify_subkey_binding(pk, &sub.key).is_ok();
        let of_type = |t| move |s: &&Signature| s.typ() == Some(t);
        if sub
            .signatures
            .iter()
            .filter(of_type(SignatureType::SubkeyRevocation))
            .any(|s| bound(&s))
        {
            return None;
        }
        let binding = sub
            .signatures
            .iter()
            .filter(of_type(SignatureType::SubkeyBinding))
            .filter(bound)
            .max_by_key(|s| s.created())?;
        if !binding.key_flags().sign() {
            return None;
        }
        // Without the back-signature anyone could bind someone else's signing key.
        binding
            .embedded_signature()?
            .verify_primary_key_binding(&sub.key, pk)
            .ok()?;
        let created = SystemTime::from(sub.key.created_at());
        let expires = match (expiry(created, binding), primary_expires) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        Some(Candidate {
            key: KeyRef::Sub(&sub.key),
            created: created.max(primary_created),
            expires,
        })
    }

    fn expiry(created: SystemTime, sig: &Signature) -> Option<SystemTime> {
        sig.key_expiration_time()
            .map(std::time::Duration::from)
            .filter(|d| !d.is_zero())
            .map(|d| created + d)
    }

    fn has_key_flags(sig: &Signature) -> bool {
        sig.config().is_some_and(|c| {
            c.hashed_subpackets()
                .any(|p| matches!(p.data, SubpacketData::KeyFlags(_)))
        })
    }

    fn load_keyring(path: &Path) -> Result<Vec<SignedPublicKey>, PgpError> {
        let load_err = |msg: String| PgpError::KeyringLoad {
            path: path.to_path_buf(),
            source: Box::new(SnafuWrap(msg)),
        };
        let raw = std::fs::read(path).map_err(|e| PgpError::KeyringLoad {
            path: path.to_path_buf(),
            source: Box::new(e),
        })?;
        let binary = dearmor_all(&raw).map_err(load_err)?;
        let packets = PacketParser::new(&binary[..])
            .filter_map(keyring_packet)
            .peekable();
        let keys = SignedPublicKey::from_packets(packets)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| load_err(e.to_string()))?;
        if keys.is_empty() {
            return Err(load_err("keyring contains no OpenPGP public keys".into()));
        }
        Ok(keys)
    }

    /// Binary OpenPGP packets from binary or armored input. Armored input may
    /// hold several blocks (`cat a.asc b.asc > keyring.asc`); all are decoded
    /// and concatenated, and text between them is ignored.
    fn dearmor_all(bytes: &[u8]) -> Result<Vec<u8>, String> {
        const BEGIN: &[u8] = b"-----BEGIN PGP ";
        const END: &[u8] = b"-----END PGP ";
        if bytes.first().is_some_and(|b| b & 0x80 != 0) {
            return Ok(bytes.to_vec());
        }
        let find = |hay: &[u8], needle: &[u8]| hay.windows(needle.len()).position(|w| w == needle);
        let mut out = Vec::new();
        let mut rest = bytes;
        while let Some(start) = find(rest, BEGIN) {
            let block = &rest[start..];
            // Through the end of the `-----END PGP ...-----` line.
            let end = find(block, END).map_or(block.len(), |e| {
                block[e..]
                    .iter()
                    .position(|&b| b == b'\n')
                    .map_or(block.len(), |nl| e + nl + 1)
            });
            Dearmor::new(&block[..end])
                .read_to_end(&mut out)
                .map_err(|e| format!("bad armor block: {e}"))?;
            rest = &block[end..];
        }
        if out.is_empty() {
            return Err("no OpenPGP data (neither binary nor an armor block)".into());
        }
        Ok(out)
    }

    /// rpgp's own skip rules for binary input (its `filter_parsed_packet_results`
    /// is private), plus GnuPG trust packets: legacy keyrings such as
    /// ubuntu-archive-keyring.gpg interleave them, and rpgp's key parser stops
    /// at the first one, dropping the user IDs, signatures and subkeys after it.
    fn keyring_packet(p: pgp::errors::Result<Packet>) -> Option<pgp::errors::Result<Packet>> {
        use pgp::errors::Error;
        let skip = match &p {
            Ok(packet) => matches!(
                packet,
                Packet::Trust(_) | Packet::Marker(_) | Packet::Padding(_)
            ),
            Err(Error::Unsupported { .. } | Error::PacketIncomplete { .. }) => true,
            Err(Error::InvalidPacketContent { source }) => matches!(
                **source,
                Error::Unsupported { .. } | Error::EllipticCurve { .. }
            ),
            Err(_) => false,
        };
        (!skip).then_some(p)
    }

    /// Every signature packet in a detached signature (binary, or armored in
    /// one or more blocks). Multi-signed `Release.gpg` files (e.g.
    /// security.debian.org) carry one packet per archive key, and any one of
    /// them may be the trusted one. Unparseable packets are skipped as long as
    /// at least one parses.
    fn parse_detached(bytes: &[u8]) -> Result<Vec<Signature>, String> {
        let binary = dearmor_all(bytes)?;
        let iter = DetachedSignature::from_bytes_many(&binary[..]).map_err(|e| e.to_string())?;
        let mut first_err = None;
        let sigs: Vec<Signature> = iter
            .filter_map(|r| {
                r.map_err(|e| first_err.get_or_insert(e.to_string()).clone())
                    .ok()
            })
            .map(|d| d.signature)
            .take(MAX_SIGNATURES)
            .collect();
        if sigs.is_empty() {
            return Err(first_err.unwrap_or_else(|| "no signature packets".to_owned()));
        }
        Ok(sigs)
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
