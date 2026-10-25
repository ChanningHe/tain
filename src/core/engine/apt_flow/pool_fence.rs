//! Pool specs come from untrusted indexes. One whose path is a root file, a
//! by-hash object, lies in another configured suite's tree, or is a
//! Release-listed file with different bytes would overwrite verified
//! metadata (staged or published), so the suite fails instead. Other files
//! under the suite's own directory (Proxmox / Tailscale style pools) stay
//! legal, as does a Release-listed file vouched for with the same bytes
//! (debian-installer's `SHA256SUMS` lists `MD5SUMS`, which Release lists
//! too).

use crate::backends::apt::checksums::{ChecksumEntry, ReleaseChecksums};
use crate::core::types::{DigestAlgo, FileSpec};

use super::AptFlowError;

const ROOT_FILES: [&str; 3] = ["InRelease", "Release", "Release.gpg"];

/// Where one suite's pool specs may not land.
pub(super) struct PoolFence<'a> {
    /// This suite's directory, e.g. `dists/bookworm/`.
    pub(super) own: &'a str,
    /// Every other configured suite's directory.
    pub(super) others: &'a [String],
    /// This suite's Release entries (relative to `own`).
    pub(super) checksums: &'a ReleaseChecksums,
    /// `dists/<name>/` entries that are symlinks on disk (suite aliases such
    /// as `stable -> bookworm`): writing below one lands in its target's
    /// published tree.
    pub(super) symlinked: &'a [String],
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
        if self
            .symlinked
            .iter()
            .any(|p| p != self.own && rel.starts_with(p.as_str()))
        {
            return Some("a suite alias symlink's target");
        }
        if rel
            .strip_prefix(self.own)
            .and_then(|suffix| self.checksums.get(suffix))
            .is_some_and(|entry| !same_bytes(spec, entry))
        {
            return Some("a file listed in Release with different content");
        }
        if self.in_other_suite(rel) {
            return Some("another configured suite's directory");
        }
        None
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
            || (dir.starts_with("dists/") && dir.matches('/').count() == 1)
    }

    /// The longest matching suite directory owns a path, so suite `a/b`
    /// may use `dists/a/b/...` although suite `a` is configured too.
    fn in_other_suite(&self, rel: &str) -> bool {
        let own = rel.starts_with(self.own).then_some(self.own.len());
        let other = self
            .others
            .iter()
            .filter(|p| rel.starts_with(p.as_str()))
            .map(String::len)
            .max();
        other > own
    }
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

/// `dists/<name>/` for every symlink directly under `<mirror_root>/dists`.
pub(super) fn symlinked_dists(mirror_root: &std::path::Path) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(mirror_root.join("dists")) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_symlink()))
        .filter_map(|e| e.file_name().to_str().map(|n| format!("dists/{n}/")))
        .collect()
}

fn is_by_hash(rel: &str, own: &str) -> bool {
    (rel.starts_with("dists/") || rel.starts_with(own)) && rel.split('/').any(|s| s == "by-hash")
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
        let others = vec![
            "dists/trixie/".to_owned(),
            "dists/bookworm/updates/".to_owned(),
        ];
        let c = checksums();
        PoolFence {
            own: "dists/bookworm/",
            others: &others,
            checksums: &c,
            symlinked: &[],
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
            "dists/bookworm/updates/Release.gpg",
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
        let others = Vec::new();
        let c = checksums();
        let fence = PoolFence {
            own: "dists/bookworm/",
            others: &others,
            checksums: &c,
            symlinked: &[],
        };
        assert!(fence.check(std::slice::from_ref(&same)).is_ok());
        // Same hash but a different stated size is still a conflict.
        same.size = Some(1);
        assert!(fence.check(&[same]).is_err());
    }

    #[test]
    fn rejects_paths_below_a_symlinked_alias_but_not_own_dir() {
        let others = Vec::new();
        let c = checksums();
        let symlinked = vec!["dists/stable/".to_owned(), "dists/bookworm/".to_owned()];
        let fence = PoolFence {
            own: "dists/bookworm/",
            others: &others,
            checksums: &c,
            symlinked: &symlinked,
        };
        let err = fence
            .check(&[spec("dists/stable/main/binary-amd64/x.deb")])
            .unwrap_err();
        assert!(
            matches!(err, AptFlowError::PoolPathConflict { reason, .. }
                if reason == "a suite alias symlink's target"),
            "{err:?}"
        );
        // In-suite files are staged, never written through the own path.
        assert!(fence.check(&[spec("dists/bookworm/main/x.deb")]).is_ok());
    }

    #[test]
    fn symlinked_dists_lists_only_symlinks() {
        let root = std::env::temp_dir().join(format!("tain-fence-ln-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("dists/bookworm")).unwrap();
        std::os::unix::fs::symlink("bookworm", root.join("dists/stable")).unwrap();
        assert_eq!(symlinked_dists(&root), vec!["dists/stable/".to_owned()]);
        assert!(symlinked_dists(&root.join("missing")).is_empty());
        std::fs::remove_dir_all(&root).unwrap();
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
        for rel in [
            "dists/trixie/main/binary-amd64/x.deb",
            "dists/bookworm/updates/main/x.deb",
        ] {
            assert_eq!(reason(rel), "another configured suite's directory", "{rel}");
        }
    }

    #[test]
    fn accepts_pool_and_in_suite_package_files() {
        for rel in [
            "pool/main/n/nginx/nginx_1.0_amd64.deb",
            "dists/bookworm/pve-no-subscription/binary-amd64/pve_1.0_amd64.deb",
            "dists/bookworm/main/binary-amd64/Packages.gz.deb",
            "dists/bookworm-security/x.deb",
            // `Release` deeper than a suite dir and not listed: not a root file.
            "dists/bookworm/main/installer-amd64/current/images/Release",
        ] {
            assert!(check(rel).is_ok(), "{rel}");
        }
    }

    #[test]
    fn nested_suite_owns_its_own_tree() {
        let others = vec!["dists/bookworm/".to_owned()];
        let c = checksums();
        let fence = PoolFence {
            own: "dists/bookworm/updates/",
            others: &others,
            checksums: &c,
            symlinked: &[],
        };
        assert!(
            fence
                .check(&[spec("dists/bookworm/updates/main/x.deb")])
                .is_ok()
        );
        assert!(fence.check(&[spec("dists/bookworm/main/x.deb")]).is_err());
    }
}
