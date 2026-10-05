//! Download-with-verify sink: stream to `<final>.tmp~`, hash inline, verify
//! size and every expected digest, then rename into place. No network I/O.

use std::path::{Path, PathBuf};

use md5::Md5;
use sha1::Sha1;
use sha2::digest::Digest as _;
use sha2::{Sha256, Sha512};
use tokio::fs;
use tokio::io::{AsyncWriteExt, BufWriter};

use crate::core::types::{Digest, DigestAlgo, DigestSet};

/// Runs only the hashers the expected set names.
#[derive(Default)]
#[allow(missing_debug_implementations)]
pub struct MultiHasher {
    sha512: Option<Sha512>,
    sha256: Option<Sha256>,
    sha1: Option<Sha1>,
    md5: Option<Md5>,
}

impl MultiHasher {
    /// # Errors
    ///
    /// `SinkError::NoDigest` when `expected` is empty.
    pub fn from_expected(expected: &DigestSet) -> Result<Self, SinkError> {
        if expected.is_empty() {
            return Err(SinkError::NoDigest);
        }
        let mut me = Self::default();
        for d in expected.iter() {
            match d.algo {
                DigestAlgo::Sha512 => me.sha512 = Some(Sha512::new()),
                DigestAlgo::Sha256 => me.sha256 = Some(Sha256::new()),
                DigestAlgo::Sha1 => me.sha1 = Some(Sha1::new()),
                DigestAlgo::Md5 => me.md5 = Some(Md5::new()),
            }
        }
        Ok(me)
    }

    pub fn update(&mut self, chunk: &[u8]) {
        if let Some(h) = &mut self.sha512 {
            h.update(chunk);
        }
        if let Some(h) = &mut self.sha256 {
            h.update(chunk);
        }
        if let Some(h) = &mut self.sha1 {
            h.update(chunk);
        }
        if let Some(h) = &mut self.md5 {
            h.update(chunk);
        }
    }

    #[must_use]
    pub fn finalize(self) -> DigestSet {
        let mut out = DigestSet::new();
        if let Some(h) = self.sha512 {
            let bytes = h.finalize().to_vec();
            let d =
                Digest::new(DigestAlgo::Sha512, bytes).expect("Sha512 finalize length is fixed");
            out.push(d)
                .expect("MultiHasher only pushes one digest per algo");
        }
        if let Some(h) = self.sha256 {
            let bytes = h.finalize().to_vec();
            let d =
                Digest::new(DigestAlgo::Sha256, bytes).expect("Sha256 finalize length is fixed");
            out.push(d)
                .expect("MultiHasher only pushes one digest per algo");
        }
        if let Some(h) = self.sha1 {
            let bytes = h.finalize().to_vec();
            let d = Digest::new(DigestAlgo::Sha1, bytes).expect("Sha1 finalize length is fixed");
            out.push(d)
                .expect("MultiHasher only pushes one digest per algo");
        }
        if let Some(h) = self.md5 {
            let bytes = h.finalize().to_vec();
            let d = Digest::new(DigestAlgo::Md5, bytes).expect("Md5 finalize length is fixed");
            out.push(d)
                .expect("MultiHasher only pushes one digest per algo");
        }
        out
    }
}

/// Tmp-then-rename writer with inline hashing: `new` → `write`* → `finish`.
/// Dropping without `finish` leaves the `.tmp~` file behind.
pub struct HashingSink {
    final_path: PathBuf,
    tmp_path: PathBuf,
    writer: Option<BufWriter<fs::File>>,
    hasher: MultiHasher,
    bytes_written: u64,
    expected: DigestSet,
    expected_size: Option<u64>,
}

impl HashingSink {
    /// Large buffer: `tokio::fs` small writes are expensive.
    pub const DEFAULT_BUFFER: usize = 256 * 1024;

    pub const TMP_SUFFIX: &'static str = ".tmp~";

    /// # Errors
    ///
    /// `NoDigest` for an empty expected set; `Io` opening the temp file.
    pub async fn new(
        final_path: PathBuf,
        expected: DigestSet,
        expected_size: Option<u64>,
    ) -> Result<Self, SinkError> {
        let hasher = MultiHasher::from_expected(&expected)?;
        let tmp_path = tmp_path_for(&final_path);

        if let Some(parent) = tmp_path.parent() {
            fs::create_dir_all(parent)
                .await
                .map_err(|e| SinkError::Io {
                    path: tmp_path.clone(),
                    source: e,
                })?;
        }

        let file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp_path)
            .await
            .map_err(|e| SinkError::Io {
                path: tmp_path.clone(),
                source: e,
            })?;
        let writer = BufWriter::with_capacity(Self::DEFAULT_BUFFER, file);

        Ok(Self {
            final_path,
            tmp_path,
            writer: Some(writer),
            hasher,
            bytes_written: 0,
            expected,
            expected_size,
        })
    }

    /// # Errors
    ///
    /// I/O errors, or `Contract` after `finish`.
    pub async fn write(&mut self, chunk: &[u8]) -> Result<(), SinkError> {
        let w = self
            .writer
            .as_mut()
            .ok_or(SinkError::Contract("write after finish"))?;
        w.write_all(chunk).await.map_err(|e| SinkError::Io {
            path: self.tmp_path.clone(),
            source: e,
        })?;
        self.hasher.update(chunk);
        self.bytes_written += chunk.len() as u64;
        Ok(())
    }

    #[must_use]
    pub fn bytes_written(&self) -> u64 {
        self.bytes_written
    }

    /// Flush, fsync, verify, rename. Verification failure unlinks the temp.
    ///
    /// # Errors
    ///
    /// `SizeMismatch`, `DigestMismatch`, or `Io`.
    pub async fn finish(mut self) -> Result<SinkReport, SinkError> {
        let mut writer = self
            .writer
            .take()
            .ok_or(SinkError::Contract("double finish"))?;
        // `into_inner` does not flush.
        writer.flush().await.map_err(|e| SinkError::Io {
            path: self.tmp_path.clone(),
            source: e,
        })?;
        let inner = writer.into_inner();
        inner.sync_data().await.map_err(|e| SinkError::Io {
            path: self.tmp_path.clone(),
            source: e,
        })?;
        drop(inner);

        if let Some(want) = self.expected_size
            && want != self.bytes_written
        {
            self.discard_tmp().await;
            return Err(SinkError::SizeMismatch {
                expected: want,
                got: self.bytes_written,
            });
        }

        let computed = std::mem::take(&mut self.hasher).finalize();
        // Every expected digest must match, not just the strongest.
        for want in self.expected.iter() {
            let got = match computed.get(want.algo) {
                Some(g) => g,
                None => {
                    self.discard_tmp().await;
                    return Err(SinkError::Contract(
                        "hasher missing algo present in expected",
                    ));
                }
            };
            if got.bytes != want.bytes {
                let mismatch = SinkError::DigestMismatch {
                    algo: want.algo,
                    expected: hex_encode(&want.bytes),
                    got: hex_encode(&got.bytes),
                };
                self.discard_tmp().await;
                return Err(mismatch);
            }
        }

        fs::rename(&self.tmp_path, &self.final_path)
            .await
            .map_err(|e| SinkError::Io {
                path: self.tmp_path.clone(),
                source: e,
            })?;

        Ok(SinkReport {
            final_path: self.final_path,
            bytes_written: self.bytes_written,
            digests: computed,
        })
    }

    async fn discard_tmp(&self) {
        // Best-effort; the caller reports the real error.
        let _ = fs::remove_file(&self.tmp_path).await;
    }
}

#[derive(Debug, Clone)]
pub struct SinkReport {
    pub final_path: PathBuf,
    pub bytes_written: u64,
    pub digests: DigestSet,
}

#[must_use]
pub fn tmp_path_for(final_path: &Path) -> PathBuf {
    let mut s = final_path.as_os_str().to_owned();
    s.push(HashingSink::TMP_SUFFIX);
    PathBuf::from(s)
}

#[derive(Debug, thiserror::Error)]
pub enum SinkError {
    #[error("expected DigestSet is empty — nothing to verify against")]
    NoDigest,
    #[error("I/O error on `{path}`: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("size mismatch: expected {expected}, got {got}")]
    SizeMismatch { expected: u64, got: u64 },
    #[error("{algo:?} digest mismatch: expected `{expected}`, got `{got}`")]
    DigestMismatch {
        algo: DigestAlgo,
        expected: String,
        got: String,
    },
    /// Caller bug.
    #[error("contract violation: {0}")]
    Contract(&'static str),
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0F) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::types::{Digest, DigestAlgo, DigestSet};

    fn expected_sha256_of(bytes: &[u8]) -> DigestSet {
        let mut h = Sha256::new();
        h.update(bytes);
        let mut s = DigestSet::new();
        s.push(Digest::new(DigestAlgo::Sha256, h.finalize().to_vec()).unwrap())
            .unwrap();
        s
    }

    fn expected_sha512_of(bytes: &[u8]) -> DigestSet {
        let mut h = Sha512::new();
        h.update(bytes);
        let mut s = DigestSet::new();
        s.push(Digest::new(DigestAlgo::Sha512, h.finalize().to_vec()).unwrap())
            .unwrap();
        s
    }

    struct Tmp {
        dir: PathBuf,
    }
    impl Tmp {
        fn new() -> Self {
            use std::sync::atomic::{AtomicUsize, Ordering};
            static N: AtomicUsize = AtomicUsize::new(0);
            let dir = std::env::temp_dir().join(format!(
                "tain-sink-{}-{}",
                std::process::id(),
                N.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&dir).unwrap();
            Self { dir }
        }
        fn file(&self, name: &str) -> PathBuf {
            self.dir.join(name)
        }
    }
    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    #[test]
    fn multi_hasher_rejects_empty_expected() {
        match MultiHasher::from_expected(&DigestSet::new()) {
            Ok(_) => panic!("expected NoDigest error"),
            Err(SinkError::NoDigest) => {}
            Err(e) => panic!("wrong variant: {e:?}"),
        }
    }

    #[test]
    fn multi_hasher_computes_only_requested_algos() {
        let expected = expected_sha256_of(b"hello");
        let mut h = MultiHasher::from_expected(&expected).unwrap();
        h.update(b"hello");
        let out = h.finalize();
        assert_eq!(out.len(), 1);
        assert!(out.get(DigestAlgo::Sha256).is_some());
        assert!(out.get(DigestAlgo::Sha512).is_none());
    }

    #[tokio::test]
    async fn writes_and_verifies_sha256_body() {
        let tmp = Tmp::new();
        let path = tmp.file("hello.txt");
        let payload = b"hello world";
        let mut sink = HashingSink::new(
            path.clone(),
            expected_sha256_of(payload),
            Some(payload.len() as u64),
        )
        .await
        .unwrap();
        sink.write(payload).await.unwrap();
        let report = sink.finish().await.unwrap();

        assert_eq!(report.final_path, path);
        assert_eq!(report.bytes_written, payload.len() as u64);
        assert!(path.exists(), "final file should exist");
        let read = tokio::fs::read(&path).await.unwrap();
        assert_eq!(read, payload);
        assert!(!tmp_path_for(&path).exists());
    }

    #[tokio::test]
    async fn multiple_writes_accumulate() {
        let tmp = Tmp::new();
        let path = tmp.file("chunks.bin");
        let full = b"chunky monkey";
        let mut sink = HashingSink::new(
            path.clone(),
            expected_sha256_of(full),
            Some(full.len() as u64),
        )
        .await
        .unwrap();
        sink.write(&full[..7]).await.unwrap();
        sink.write(&full[7..]).await.unwrap();
        sink.finish().await.unwrap();
        assert_eq!(tokio::fs::read(&path).await.unwrap(), full);
    }

    #[tokio::test]
    async fn sha256_and_sha512_both_verified() {
        let tmp = Tmp::new();
        let path = tmp.file("both.bin");
        let payload = b"belt and suspenders";
        let mut both = DigestSet::new();
        let mut h256 = Sha256::new();
        h256.update(payload);
        both.push(Digest::new(DigestAlgo::Sha256, h256.finalize().to_vec()).unwrap())
            .unwrap();
        let mut h512 = Sha512::new();
        h512.update(payload);
        both.push(Digest::new(DigestAlgo::Sha512, h512.finalize().to_vec()).unwrap())
            .unwrap();

        let mut sink = HashingSink::new(path.clone(), both, Some(payload.len() as u64))
            .await
            .unwrap();
        sink.write(payload).await.unwrap();
        sink.finish().await.unwrap();
    }

    #[tokio::test]
    async fn size_mismatch_rejected_and_tmp_removed() {
        let tmp = Tmp::new();
        let path = tmp.file("short.bin");
        let payload = b"hello";
        let mut sink = HashingSink::new(
            path.clone(),
            expected_sha256_of(payload),
            Some(payload.len() as u64 + 1),
        )
        .await
        .unwrap();
        sink.write(payload).await.unwrap();
        let err = sink.finish().await.unwrap_err();
        assert!(matches!(err, SinkError::SizeMismatch { .. }), "{err:?}");
        assert!(!path.exists(), "final file must not exist on failure");
        assert!(!tmp_path_for(&path).exists(), "tmp file must be cleaned up");
    }

    #[tokio::test]
    async fn digest_mismatch_rejected_and_tmp_removed() {
        let tmp = Tmp::new();
        let path = tmp.file("wrong.bin");
        let expected = expected_sha256_of(b"expected");
        let payload = b"actual";
        let mut sink = HashingSink::new(path.clone(), expected, Some(payload.len() as u64))
            .await
            .unwrap();
        sink.write(payload).await.unwrap();
        let err = sink.finish().await.unwrap_err();
        assert!(
            matches!(
                err,
                SinkError::DigestMismatch {
                    algo: DigestAlgo::Sha256,
                    ..
                }
            ),
            "{err:?}"
        );
        assert!(!path.exists());
        assert!(!tmp_path_for(&path).exists());
    }

    #[tokio::test]
    async fn missing_size_still_verifies_digest() {
        let tmp = Tmp::new();
        let path = tmp.file("nosize.bin");
        let payload = b"stream-of-unknown-length";
        let mut sink = HashingSink::new(path.clone(), expected_sha512_of(payload), None)
            .await
            .unwrap();
        sink.write(payload).await.unwrap();
        sink.finish().await.unwrap();
        assert_eq!(tokio::fs::read(&path).await.unwrap(), payload);
    }

    #[tokio::test]
    async fn parent_dirs_auto_created() {
        let tmp = Tmp::new();
        let nested = tmp.file("a/b/c/deep.bin");
        let payload = b"deep in the tree";
        let mut sink = HashingSink::new(
            nested.clone(),
            expected_sha256_of(payload),
            Some(payload.len() as u64),
        )
        .await
        .unwrap();
        sink.write(payload).await.unwrap();
        sink.finish().await.unwrap();
        assert!(nested.exists());
    }

    #[test]
    fn tmp_path_appends_suffix() {
        assert_eq!(
            tmp_path_for(Path::new("/a/b/foo.deb")),
            PathBuf::from("/a/b/foo.deb.tmp~")
        );
    }
}
