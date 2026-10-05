//! Pure-data types crossing the core/backend boundary.

use std::time::Duration;

use url::Url;

/// Publish layer. Layers publish in order so every index a client can read
/// references only files already in place.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Layer {
    /// Immutable pool objects.
    Content,
    /// Per-suite index files (`Packages`, `Contents-*`, ...).
    Index,
    /// Root files that flip atomically as a set (`InRelease`, `Release`, `Release.gpg`).
    Root,
}

impl Layer {
    #[must_use]
    pub const fn all_ordered() -> [Self; 3] {
        [Self::Content, Self::Index, Self::Root]
    }
}

/// A validated mirror-relative path; upstream must not be able to steer
/// writes outside the mirror.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RelPath(String);

impl RelPath {
    /// # Errors
    ///
    /// `PathError` if empty, absolute, or containing NUL, backslash, `.`/`..`
    /// components, or empty segments.
    pub fn new(s: impl Into<String>) -> Result<Self, PathError> {
        let s = s.into();
        if s.is_empty() {
            return Err(PathError::Empty);
        }
        if s.starts_with('/') {
            return Err(PathError::Absolute(s));
        }
        if s.contains('\0') {
            return Err(PathError::Nul(s));
        }
        if s.contains('\\') {
            return Err(PathError::Backslash(s));
        }
        if s.split('/').any(|seg| seg == "..") {
            return Err(PathError::ParentTraversal(s));
        }
        // `.` and empty segments would give one path several dedup keys.
        if s.split('/').any(|seg| seg == ".") {
            return Err(PathError::CurrentDir(s));
        }
        if s.split('/').any(str::is_empty) {
            return Err(PathError::EmptySegment(s));
        }
        Ok(Self(s))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn as_std_path(&self) -> &std::path::Path {
        std::path::Path::new(&self.0)
    }
}

impl std::fmt::Display for RelPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PathError {
    #[error("relative path is empty")]
    Empty,
    #[error("relative path `{0}` starts with `/` (absolute)")]
    Absolute(String),
    #[error("relative path `{0}` contains a `..` component")]
    ParentTraversal(String),
    #[error("relative path `{0}` contains a `.` component")]
    CurrentDir(String),
    #[error("relative path `{0}` contains an empty segment (`//` or trailing `/`)")]
    EmptySegment(String),
    #[error("relative path `{0}` contains a NUL byte")]
    Nul(String),
    #[error("relative path `{0}` contains a backslash")]
    Backslash(String),
}

/// Lowercase hex, for error messages only.
fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// Supported hash algorithms, ordered weakest to strongest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DigestAlgo {
    Md5,
    Sha1,
    Sha256,
    Sha512,
}

impl DigestAlgo {
    #[must_use]
    pub const fn byte_len(self) -> usize {
        match self {
            Self::Md5 => 16,
            Self::Sha1 => 20,
            Self::Sha256 => 32,
            Self::Sha512 => 64,
        }
    }

    /// Weak algorithms are rejected unless `verify.allow_weak_hash`.
    #[must_use]
    pub const fn is_weak(self) -> bool {
        matches!(self, Self::Md5 | Self::Sha1)
    }

    /// Strength rank; larger is stronger.
    #[must_use]
    pub const fn strength(self) -> u8 {
        match self {
            Self::Md5 => 1,
            Self::Sha1 => 2,
            Self::Sha256 => 3,
            Self::Sha512 => 4,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Digest {
    pub algo: DigestAlgo,
    pub bytes: Vec<u8>,
}

impl Digest {
    /// # Errors
    ///
    /// `LengthMismatch` if `bytes` has the wrong length for `algo`.
    pub fn new(algo: DigestAlgo, bytes: Vec<u8>) -> Result<Self, DigestError> {
        if bytes.len() != algo.byte_len() {
            return Err(DigestError::LengthMismatch {
                algo,
                expected: algo.byte_len(),
                got: bytes.len(),
            });
        }
        Ok(Self { algo, bytes })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DigestError {
    #[error("digest byte length mismatch for {algo:?}: expected {expected}, got {got}")]
    LengthMismatch {
        algo: DigestAlgo,
        expected: usize,
        got: usize,
    },
}

/// A `DigestSet` already holds a different hash for this algorithm.
/// Self-contradicting upstream metadata must fail the suite, not pick a side.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("duplicate digest for {algo:?}: existing {existing} vs incoming {incoming}")]
pub struct DuplicateDigest {
    pub algo: DigestAlgo,
    /// Lowercase hex.
    pub existing: String,
    /// Lowercase hex.
    pub incoming: String,
}

/// Digests for one file, at most one per algorithm.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DigestSet(Vec<Digest>);

impl DigestSet {
    #[must_use]
    pub fn new() -> Self {
        Self(Vec::new())
    }

    /// Insert a digest; re-inserting an identical one is a no-op.
    ///
    /// # Errors
    ///
    /// `DuplicateDigest` if a different digest for the same algorithm exists.
    pub fn push(&mut self, digest: Digest) -> Result<(), DuplicateDigest> {
        if let Some(existing) = self.0.iter().find(|d| d.algo == digest.algo) {
            if existing.bytes == digest.bytes {
                return Ok(());
            }
            return Err(DuplicateDigest {
                algo: digest.algo,
                existing: hex_lower(&existing.bytes),
                incoming: hex_lower(&digest.bytes),
            });
        }
        self.0.push(digest);
        Ok(())
    }

    #[must_use]
    pub fn strongest(&self) -> Option<&Digest> {
        self.0.iter().max_by_key(|d| d.algo.strength())
    }

    #[must_use]
    pub fn get(&self, algo: DigestAlgo) -> Option<&Digest> {
        self.0.iter().find(|d| d.algo == algo)
    }

    pub fn iter(&self) -> impl Iterator<Item = &Digest> {
        self.0.iter()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// True iff non-empty and every digest is weak.
    #[must_use]
    pub fn all_weak(&self) -> bool {
        !self.0.is_empty() && self.0.iter().all(|d| d.algo.is_weak())
    }
}

/// One file a backend's `plan` expects upstream to provide.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileSpec {
    pub rel_path: RelPath,
    /// Must be non-empty; the strongest is verified.
    pub digests: DigestSet,
    /// `None` when the index omits it.
    pub size: Option<u64>,
    /// Usually `base + rel_path`, but by-hash fetches point elsewhere.
    pub url: Url,
    pub layer: Layer,
    /// Content never changes at this path, so unchanged local copies skip
    /// re-verification.
    pub immutable: bool,
}

/// How the backend wants staged files landed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishSpec {
    /// Must be a permutation of the layers in use; checked before writing.
    pub layer_order: Vec<Layer>,
    /// Files flipped last as one atomic set (`RENAME_EXCHANGE`).
    pub atomic_root: Vec<RelPath>,
    /// GC never deletes past-generation files younger than this.
    pub grace: Duration,
}

/// Opaque backend revision token, persisted for the next `probe`.
pub type Token = Vec<u8>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Probe {
    Unchanged,
    Changed(Token),
}

/// Result of `pre_publish_check`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckOutcome {
    Ok,
    Stale,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layer_all_ordered_is_content_index_root() {
        assert_eq!(
            Layer::all_ordered(),
            [Layer::Content, Layer::Index, Layer::Root]
        );
    }

    #[test]
    fn relpath_accepts_normal_paths() {
        assert_eq!(
            RelPath::new("pool/main/n/nginx/nginx.deb")
                .unwrap()
                .as_str(),
            "pool/main/n/nginx/nginx.deb"
        );
        assert!(RelPath::new("dists/bookworm/InRelease").is_ok());
        assert!(RelPath::new("a").is_ok());
    }

    #[test]
    fn relpath_rejects_empty() {
        assert!(matches!(RelPath::new(""), Err(PathError::Empty)));
    }

    #[test]
    fn relpath_rejects_absolute() {
        assert!(matches!(
            RelPath::new("/etc/passwd"),
            Err(PathError::Absolute(_))
        ));
    }

    #[test]
    fn relpath_rejects_parent_traversal_various_positions() {
        assert!(matches!(
            RelPath::new(".."),
            Err(PathError::ParentTraversal(_))
        ));
        assert!(matches!(
            RelPath::new("../etc/passwd"),
            Err(PathError::ParentTraversal(_))
        ));
        assert!(matches!(
            RelPath::new("pool/../../etc"),
            Err(PathError::ParentTraversal(_))
        ));
        assert!(matches!(
            RelPath::new("pool/main/../../etc"),
            Err(PathError::ParentTraversal(_))
        ));
        assert!(matches!(
            RelPath::new("pool/main/n/.."),
            Err(PathError::ParentTraversal(_))
        ));
    }

    #[test]
    fn relpath_rejects_current_dir_component() {
        assert!(matches!(RelPath::new("."), Err(PathError::CurrentDir(_))));
        assert!(matches!(
            RelPath::new("./foo"),
            Err(PathError::CurrentDir(_))
        ));
        assert!(matches!(
            RelPath::new("foo/./bar"),
            Err(PathError::CurrentDir(_))
        ));
    }

    #[test]
    fn relpath_rejects_empty_segments() {
        assert!(matches!(
            RelPath::new("foo//bar"),
            Err(PathError::EmptySegment(_))
        ));
        assert!(matches!(
            RelPath::new("foo/"),
            Err(PathError::EmptySegment(_))
        ));
        assert!(matches!(
            RelPath::new("foo///bar"),
            Err(PathError::EmptySegment(_))
        ));
    }

    #[test]
    fn relpath_rejects_nul_and_backslash() {
        assert!(matches!(RelPath::new("foo\0bar"), Err(PathError::Nul(_))));
        assert!(matches!(
            RelPath::new("foo\\bar"),
            Err(PathError::Backslash(_))
        ));
    }

    #[test]
    fn relpath_allows_dot_prefix_in_filename() {
        assert!(RelPath::new(".hidden").is_ok());
        assert!(RelPath::new("..bad").is_ok());
        assert!(RelPath::new("foo/..bar/baz").is_ok());
    }

    #[test]
    fn relpath_display() {
        let p = RelPath::new("dists/bookworm/InRelease").unwrap();
        assert_eq!(format!("{p}"), "dists/bookworm/InRelease");
    }

    #[test]
    fn digest_algo_byte_lengths() {
        assert_eq!(DigestAlgo::Md5.byte_len(), 16);
        assert_eq!(DigestAlgo::Sha1.byte_len(), 20);
        assert_eq!(DigestAlgo::Sha256.byte_len(), 32);
        assert_eq!(DigestAlgo::Sha512.byte_len(), 64);
    }

    #[test]
    fn digest_algo_weakness() {
        assert!(DigestAlgo::Md5.is_weak());
        assert!(DigestAlgo::Sha1.is_weak());
        assert!(!DigestAlgo::Sha256.is_weak());
        assert!(!DigestAlgo::Sha512.is_weak());
    }

    #[test]
    fn digest_algo_strength_ordering() {
        assert!(DigestAlgo::Sha512.strength() > DigestAlgo::Sha256.strength());
        assert!(DigestAlgo::Sha256.strength() > DigestAlgo::Sha1.strength());
        assert!(DigestAlgo::Sha1.strength() > DigestAlgo::Md5.strength());
    }

    #[test]
    fn digest_rejects_wrong_length() {
        let err = Digest::new(DigestAlgo::Sha256, vec![0; 31]).unwrap_err();
        assert!(matches!(err, DigestError::LengthMismatch { .. }));
    }

    #[test]
    fn digest_accepts_correct_length() {
        assert!(Digest::new(DigestAlgo::Sha256, vec![0; 32]).is_ok());
        assert!(Digest::new(DigestAlgo::Sha512, vec![0; 64]).is_ok());
        assert!(Digest::new(DigestAlgo::Md5, vec![0; 16]).is_ok());
    }

    fn d(algo: DigestAlgo) -> Digest {
        Digest::new(algo, vec![0; algo.byte_len()]).unwrap()
    }

    #[test]
    fn digest_set_picks_strongest() {
        let mut s = DigestSet::new();
        s.push(d(DigestAlgo::Md5)).unwrap();
        s.push(d(DigestAlgo::Sha256)).unwrap();
        s.push(d(DigestAlgo::Sha1)).unwrap();
        assert_eq!(s.strongest().unwrap().algo, DigestAlgo::Sha256);
        s.push(d(DigestAlgo::Sha512)).unwrap();
        assert_eq!(s.strongest().unwrap().algo, DigestAlgo::Sha512);
    }

    #[test]
    fn push_same_algo_same_bytes_is_idempotent_ok() {
        let mut s = DigestSet::new();
        s.push(d(DigestAlgo::Sha256)).unwrap();
        s.push(d(DigestAlgo::Sha256))
            .expect("identical digest must be idempotent");
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn push_same_algo_different_bytes_returns_duplicate_err() {
        let mut s = DigestSet::new();
        s.push(Digest::new(DigestAlgo::Sha256, vec![0x00; 32]).unwrap())
            .unwrap();
        let err = s
            .push(Digest::new(DigestAlgo::Sha256, vec![0xff; 32]).unwrap())
            .expect_err("conflicting bytes must Err");
        assert_eq!(err.algo, DigestAlgo::Sha256);
        assert_eq!(err.existing, "0".repeat(64));
        assert_eq!(err.incoming, "f".repeat(64));
        assert_eq!(s.len(), 1);
        assert_eq!(s.get(DigestAlgo::Sha256).unwrap().bytes, vec![0x00; 32]);
    }

    #[test]
    fn push_different_algo_appends() {
        let mut s = DigestSet::new();
        s.push(d(DigestAlgo::Sha256)).unwrap();
        s.push(d(DigestAlgo::Sha512)).unwrap();
        assert_eq!(s.len(), 2);
        assert!(s.get(DigestAlgo::Sha256).is_some());
        assert!(s.get(DigestAlgo::Sha512).is_some());
    }

    #[test]
    fn digest_set_empty_has_no_strongest() {
        assert!(DigestSet::new().strongest().is_none());
        assert!(DigestSet::new().is_empty());
    }

    #[test]
    fn digest_set_all_weak_detects_reject_case() {
        let mut only_weak = DigestSet::new();
        only_weak.push(d(DigestAlgo::Md5)).unwrap();
        only_weak.push(d(DigestAlgo::Sha1)).unwrap();
        assert!(only_weak.all_weak());

        let mut mixed = DigestSet::new();
        mixed.push(d(DigestAlgo::Md5)).unwrap();
        mixed.push(d(DigestAlgo::Sha256)).unwrap();
        assert!(!mixed.all_weak());

        assert!(!DigestSet::new().all_weak(), "empty set is not all-weak");
    }

    #[test]
    fn probe_variants_construct() {
        let _ = Probe::Unchanged;
        let _ = Probe::Changed(vec![1, 2, 3]);
        assert_eq!(CheckOutcome::Ok, CheckOutcome::Ok);
        assert_ne!(CheckOutcome::Ok, CheckOutcome::Stale);
    }
}
