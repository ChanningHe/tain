//! Pool specs come from untrusted indexes. Below the suite's own directory
//! they are staged; anywhere else they are written straight into the
//! published tree. A spec fails the suite when its path is a root file, a
//! by-hash object, a Release-listed file whose bytes cannot be shown to
//! match, another configured suite's directory, or anything under `dists/`
//! (including `dists` itself) that is not below this suite's own directory:
//! a suite alias symlink, a directory a later alias or suite would need, or
//! the suite directory itself. Other files under the suite's own directory
//! (Proxmox / Tailscale style pools) stay legal, as does a Release-listed
//! file vouched for with the same bytes (debian-installer's `SHA256SUMS`
//! lists `MD5SUMS`, which Release lists too).

use crate::backends::apt::checksums::{ChecksumEntry, ReleaseChecksums};
use crate::core::types::{DigestAlgo, FileSpec};

use super::AptFlowError;

const ROOT_FILES: [&str; 3] = ["InRelease", "Release", "Release.gpg"];
const DISTS: &str = "dists/";

/// Where one suite's pool specs may not land.
pub(super) struct PoolFence<'a> {
    /// This suite's directory, e.g. `dists/bookworm/`.
    pub(super) own: &'a str,
    /// Every other configured suite's directory.
    pub(super) others: &'a [String],
    /// This suite's Release entries (relative to `own`).
    pub(super) checksums: &'a ReleaseChecksums,
}

impl PoolFence<'_> {
    pub(super) fn check(&self, specs: &[FileSpec]) -> Result<(), AptFlowError> {
        specs.iter().try_for_each(|spec| {
            self.conflict(spec).map_or(Ok(()), |reason| {
                Err(AptFlowError::PoolPathConflict {
                    path: spec.rel_path.as_str().to_owned(),
                    reason,
                })
            })
        })
    }

    fn conflict(&self, spec: &FileSpec) -> Option<&'static str> {
        let rel = spec.rel_path.as_str();
        if self.is_root_file(rel) {
            return Some("a suite root file");
        }
        if is_by_hash(rel, self.own) {
            return Some("a by-hash object");
        }
        if let Some(reason) = self.release_listed_conflict(spec) {
            return Some(reason);
        }
        // Also covers a suite configured below this one's directory.
        if self.others.iter().any(|p| is_at_or_below(rel, p)) {
            return Some("another configured suite's directory");
        }
        if is_at_or_below(rel, DISTS) && !rel.starts_with(self.own) {
            return Some("a path under dists/ outside this suite's directory");
        }
        None
    }

    /// A path Release names may only carry the bytes Release vouches for;
    /// an entry the weak-hash policy dropped vouches for nothing.
    fn release_listed_conflict(&self, spec: &FileSpec) -> Option<&'static str> {
        let suffix = spec.rel_path.as_str().strip_prefix(self.own)?;
        match self.checksums.get(suffix) {
            Some(entry) if !same_bytes(spec, entry) => {
                Some("a file listed in Release with different content")
            }
            None if self.checksums.is_listed(suffix) => {
                Some("a file listed in Release with weak digests only")
            }
            _ => None,
        }
    }

    /// `InRelease` / `Release` / `Release.gpg` of this or any configured
    /// suite, or directly under any `dists/<name>/` (suite alias symlinks
    /// point into published trees).
    fn is_root_file(&self, rel: &str) -> bool {
        let (dir, name) = rel.rsplit_once('/').unwrap_or(("", rel));
        if !ROOT_FILES.contains(&name) {
            return false;
        }
        let dir_slash = format!("{dir}/");
        let is_suite_dir = |p: &str| p == dir_slash || (p.is_empty() && dir.is_empty());
        is_suite_dir(self.own)
            || self.others.iter().any(|p| is_suite_dir(p))
            || (dir.starts_with(DISTS) && dir.matches('/').count() == 1)
    }
}

/// `rel` is the directory `dir` (given with a trailing slash) or below it.
fn is_at_or_below(rel: &str, dir: &str) -> bool {
    rel.starts_with(dir) || Some(rel) == dir.strip_suffix('/')
}

/// Both sources vouch for the same bytes: equal SHA-256 (required on both
/// sides) and, when the index states one, equal size.
fn same_bytes(spec: &FileSpec, entry: &ChecksumEntry) -> bool {
    let same_hash = matches!(
        (spec.digests.get(DigestAlgo::Sha256), entry.digests.get(DigestAlgo::Sha256)),
        (Some(ours), Some(theirs)) if ours.bytes == theirs.bytes
    );
    same_hash && spec.size.is_none_or(|size| size == entry.size)
}

fn is_by_hash(rel: &str, own: &str) -> bool {
    (rel.starts_with(DISTS) || rel.starts_with(own)) && rel.split('/').any(|s| s == "by-hash")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::types::{DigestAlgo, Layer, RelPath};

    const SHA256_EMPTY: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    fn spec(rel: &str) -> FileSpec {
        let mut digests = crate::core::types::DigestSet::new();
        digests
            .push(
                crate::core::types::Digest::new(
                    DigestAlgo::Sha256,
                    (0..32).map(|i| i as u8).collect(),
                )
                .unwrap(),
            )
            .unwrap();
        FileSpec {
            rel_path: RelPath::new(rel.to_owned()).unwrap(),
            digests,
            size: Some(0),
            url: url::Url::parse("http://up/").unwrap().join(rel).unwrap(),
            layer: Layer::Content,
            immutable: true,
        }
    }

    fn checksums() -> ReleaseChecksums {
        let mut c = ReleaseChecksums::default();
        for p in [
            "main/binary-amd64/Packages",
            "main/binary-amd64/Packages.xz",
        ] {
            c.upsert(DigestAlgo::Sha256, SHA256_EMPTY, 0, p).unwrap();
        }
        c
    }

    fn check(rel: &str) -> Result<(), AptFlowError> {
        let others = vec!["dists/trixie/".to_owned()];
        let c = checksums();
        PoolFence {
            own: "dists/bookworm/",
            others: &others,
            checksums: &c,
        }
        .check(&[spec(rel)])
    }

    fn reason(rel: &str) -> &'static str {
        match check(rel) {
            Err(AptFlowError::PoolPathConflict { reason, .. }) => reason,
            other => panic!("{rel}: expected a conflict, got {other:?}"),
        }
    }

    #[test]
    fn rejects_root_files_of_any_suite_or_alias() {
        for rel in [
            "dists/bookworm/InRelease",
            "dists/bookworm/Release",
            "dists/bookworm/Release.gpg",
            "dists/trixie/InRelease",
            "dists/stable/Release",
        ] {
            assert_eq!(reason(rel), "a suite root file", "{rel}");
        }
    }

    #[test]
    fn rejects_release_listed_files_with_other_content() {
        assert_eq!(
            reason("dists/bookworm/main/binary-amd64/Packages.xz"),
            "a file listed in Release with different content"
        );
    }

    #[test]
    fn rejects_release_paths_listed_with_weak_digests_only() {
        let mut c = checksums();
        c.upsert(
            DigestAlgo::Md5,
            "d41d8cd98f00b204e9800998ecf8427e",
            0,
            "main/binary-amd64/Packages.bz2",
        )
        .unwrap();
        let (c, _) = c.apply_weak_hash_policy(false);
        let fence = PoolFence {
            own: "dists/bookworm/",
            others: &[],
            checksums: &c,
        };
        let err = fence
            .check(&[spec("dists/bookworm/main/binary-amd64/Packages.bz2")])
            .unwrap_err();
        assert!(
            matches!(err, AptFlowError::PoolPathConflict { reason, .. }
                if reason == "a file listed in Release with weak digests only"),
            "{err:?}"
        );
    }

    #[test]
    fn accepts_release_listed_file_with_same_content() {
        let mut same = spec("dists/bookworm/main/binary-amd64/Packages.xz");
        same.digests = crate::core::types::DigestSet::new();
        let empty = (0..64)
            .step_by(2)
            .map(|i| u8::from_str_radix(&SHA256_EMPTY[i..i + 2], 16).unwrap())
            .collect();
        same.digests
            .push(crate::core::types::Digest::new(DigestAlgo::Sha256, empty).unwrap())
            .unwrap();
        let c = checksums();
        let fence = PoolFence {
            own: "dists/bookworm/",
            others: &[],
            checksums: &c,
        };
        assert!(fence.check(std::slice::from_ref(&same)).is_ok());
        // Same hash but a different stated size is still a conflict.
        same.size = Some(1);
        assert!(fence.check(&[same]).is_err());
    }

    #[test]
    fn rejects_dists_paths_outside_own_directory() {
        for rel in [
            "dists",
            "dists/bookworm",
            "dists/stable",
            "dists/stable/main/binary-amd64/x.deb",
            "dists/stable/InRelease.deb",
            "dists/bookworm-security/x.deb",
            "dists/x.deb",
        ] {
            assert_eq!(
                reason(rel),
                "a path under dists/ outside this suite's directory",
                "{rel}"
            );
        }
    }

    #[test]
    fn rejects_by_hash_objects() {
        for rel in [
            "dists/bookworm/main/binary-amd64/by-hash/SHA256/abc",
            "dists/trixie/main/by-hash/SHA512/def",
        ] {
            assert_eq!(reason(rel), "a by-hash object", "{rel}");
        }
    }

    #[test]
    fn rejects_other_suites_trees() {
        for rel in ["dists/trixie/main/binary-amd64/x.deb", "dists/trixie"] {
            assert_eq!(reason(rel), "another configured suite's directory", "{rel}");
        }
    }

    #[test]
    fn rejects_a_suite_configured_below_own_directory() {
        let others = vec!["dists/bookworm/updates/".to_owned()];
        let c = checksums();
        let fence = PoolFence {
            own: "dists/bookworm/",
            others: &others,
            checksums: &c,
        };
        assert!(
            fence
                .check(&[spec("dists/bookworm/updates/main/x.deb")])
                .is_err()
        );
    }

    #[test]
    fn accepts_pool_and_in_suite_package_files() {
        for rel in [
            "pool/main/n/nginx/nginx_1.0_amd64.deb",
            "dists/bookworm/pve-no-subscription/binary-amd64/pve_1.0_amd64.deb",
            "dists/bookworm/main/binary-amd64/Packages.gz.deb",
            // `Release` deeper than a suite dir and not listed: not a root file.
            "dists/bookworm/main/installer-amd64/current/images/Release",
        ] {
            assert!(check(rel).is_ok(), "{rel}");
        }
    }
}
