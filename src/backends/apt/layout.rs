//! APT archive layout arithmetic: suite/pool paths and URLs, no I/O.
//!
//! Every composed local path goes through `RelPath`, so `Filename` safety rules
//! apply to our own paths too.

use url::Url;

use crate::core::types::{PathError, RelPath};

/// Path and URL computations for one suite.
#[derive(Debug)]
pub struct SuiteLayout<'a> {
    /// Repo root, e.g. `https://deb.debian.org/debian`; trailing slash optional.
    pub base_url: &'a Url,
    /// `bookworm`, `stable/updates`, or `./` / `foo/./` for a flat repo.
    pub suite: &'a str,
}

impl<'a> SuiteLayout<'a> {
    #[must_use]
    pub fn new(base_url: &'a Url, suite: &'a str) -> Self {
        Self { base_url, suite }
    }

    /// True for a flat repo: the suite is `./` or ends with `/./`.
    #[must_use]
    pub fn is_flat(&self) -> bool {
        self.suite == "./" || self.suite.ends_with("/./")
    }

    /// `dists/<suite>/`, or the flat directory (empty for `./`).
    fn suite_prefix(&self) -> String {
        if self.suite == "./" {
            String::new()
        } else if let Some(dir) = self.suite.strip_suffix("/./") {
            format!("{dir}/")
        } else {
            format!("dists/{}/", self.suite.trim_end_matches('/'))
        }
    }

    /// Local relative path for a suite-scope filename such as `InRelease` or
    /// `main/binary-amd64/Packages`.
    ///
    /// # Errors
    ///
    /// [`PathError`] when the composed path is unsafe.
    pub fn suite_rel(&self, name: &str) -> Result<RelPath, PathError> {
        let prefix = self.suite_prefix();
        let joined = format!("{prefix}{name}");
        RelPath::new(joined)
    }

    /// Full URL for a suite-scope file.
    ///
    /// # Errors
    ///
    /// [`LayoutError`] when the path is unsafe or `Url::join` fails.
    pub fn suite_url(&self, name: &str) -> Result<Url, LayoutError> {
        // Gate URLs by the same rules as local paths.
        let _rel = self.suite_rel(name).map_err(LayoutError::from)?;
        let prefix = self.suite_prefix();
        let ref_path = format!("{prefix}{name}");
        join_url(self.base_url, &ref_path)
    }

    /// Local relative path for a root-scope file (`pool/main/n/nginx/*.deb`,
    /// or, in a flat repo, `xyz.deb`). Applies `Filename` path safety.
    pub fn root_rel(&self, name: &str) -> Result<RelPath, PathError> {
        RelPath::new(name.to_owned())
    }

    /// Full URL for a root-scope file.
    pub fn root_url(&self, name: &str) -> Result<Url, LayoutError> {
        let _rel = self.root_rel(name).map_err(LayoutError::from)?;
        join_url(self.base_url, name)
    }

    /// `InRelease` file.
    pub fn inrelease_rel(&self) -> Result<RelPath, PathError> {
        self.suite_rel("InRelease")
    }
    pub fn inrelease_url(&self) -> Result<Url, LayoutError> {
        self.suite_url("InRelease")
    }

    /// `Release` file (plain, non-clearsigned).
    pub fn release_rel(&self) -> Result<RelPath, PathError> {
        self.suite_rel("Release")
    }
    pub fn release_url(&self) -> Result<Url, LayoutError> {
        self.suite_url("Release")
    }

    /// `Release.gpg` detached signature.
    pub fn release_gpg_rel(&self) -> Result<RelPath, PathError> {
        self.suite_rel("Release.gpg")
    }
    pub fn release_gpg_url(&self) -> Result<Url, LayoutError> {
        self.suite_url("Release.gpg")
    }

    /// `by-hash/<algo>/<hex>` sibling for a suite-scope entry.
    ///
    /// `main/binary-amd64/Packages.xz` maps to `main/binary-amd64/by-hash/<algo>/<hex>`.
    ///
    /// # Errors
    ///
    /// Same as [`Self::suite_url`].
    pub fn by_hash_url(
        &self,
        entry_path: &str,
        algo_dir: &str,
        hex: &str,
    ) -> Result<Url, LayoutError> {
        let by_hash = compute_by_hash_rel(entry_path, algo_dir, hex);
        self.suite_url(&by_hash)
    }
}

fn compute_by_hash_rel(entry_path: &str, algo_dir: &str, hex: &str) -> String {
    match entry_path.rsplit_once('/') {
        Some((parent, _)) => format!("{parent}/by-hash/{algo_dir}/{hex}"),
        None => format!("by-hash/{algo_dir}/{hex}"),
    }
}

/// Join onto `base` as a directory, so `Url::join` keeps its last segment.
fn join_url(base: &Url, suffix: &str) -> Result<Url, LayoutError> {
    let base_str = base.as_str();
    let base_dir = if base_str.ends_with('/') {
        base.clone()
    } else {
        Url::parse(&format!("{base_str}/")).map_err(|e| LayoutError::UrlJoin(e.to_string()))?
    };
    base_dir
        .join(suffix)
        .map_err(|e| LayoutError::UrlJoin(e.to_string()))
}

#[derive(Debug, thiserror::Error)]
pub enum LayoutError {
    #[error(transparent)]
    Path(#[from] PathError),
    #[error("URL join failed: {0}")]
    UrlJoin(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    #[test]
    fn standard_suite_prefix() {
        let base = base("https://deb.debian.org/debian");
        let l = SuiteLayout::new(&base, "bookworm");
        assert!(!l.is_flat());
        assert_eq!(l.suite_prefix(), "dists/bookworm/");
    }

    #[test]
    fn slash_suite_prefix() {
        let base = base("https://example.com/repo");
        let l = SuiteLayout::new(&base, "stable/updates");
        assert_eq!(l.suite_prefix(), "dists/stable/updates/");
    }

    #[test]
    fn flat_dot_suite_has_empty_prefix() {
        let base = base("https://example.com/repo/");
        let l = SuiteLayout::new(&base, "./");
        assert!(l.is_flat());
        assert_eq!(l.suite_prefix(), "");
    }

    #[test]
    fn flat_dir_dot_suite_uses_dir_as_prefix() {
        let base = base("https://example.com/repo/");
        let l = SuiteLayout::new(&base, "foo/./");
        assert!(l.is_flat());
        assert_eq!(l.suite_prefix(), "foo/");
    }

    #[test]
    fn suite_rel_for_standard_layout() {
        let base = base("https://deb.debian.org/debian");
        let l = SuiteLayout::new(&base, "bookworm");
        assert_eq!(
            l.suite_rel("InRelease").unwrap().as_str(),
            "dists/bookworm/InRelease"
        );
        assert_eq!(
            l.suite_rel("main/binary-amd64/Packages").unwrap().as_str(),
            "dists/bookworm/main/binary-amd64/Packages"
        );
    }

    #[test]
    fn suite_rel_for_slash_suite() {
        let base = base("https://example.com/repo");
        let l = SuiteLayout::new(&base, "stable/updates");
        assert_eq!(
            l.suite_rel("main/binary-amd64/Packages").unwrap().as_str(),
            "dists/stable/updates/main/binary-amd64/Packages"
        );
    }

    #[test]
    fn suite_rel_for_flat_dot() {
        let base = base("https://example.com/repo/");
        let l = SuiteLayout::new(&base, "./");
        assert_eq!(l.suite_rel("InRelease").unwrap().as_str(), "InRelease");
        assert_eq!(l.suite_rel("Packages").unwrap().as_str(), "Packages");
    }

    #[test]
    fn suite_rel_for_flat_dir() {
        let base = base("https://example.com/repo/");
        let l = SuiteLayout::new(&base, "foo/./");
        assert_eq!(l.suite_rel("Release").unwrap().as_str(), "foo/Release");
    }

    #[test]
    fn suite_rel_rejects_traversal_in_name() {
        let base = base("https://example.com/repo/");
        let l = SuiteLayout::new(&base, "bookworm");
        assert!(l.suite_rel("main/../../etc/passwd").is_err());
    }

    #[test]
    fn suite_rel_rejects_absolute_name() {
        let base = base("https://example.com/repo/");
        let l = SuiteLayout::new(&base, "bookworm");
        assert!(l.suite_rel("/etc/passwd").is_err());
    }

    #[test]
    fn root_rel_for_pool_file() {
        let base = base("https://deb.debian.org/debian");
        let l = SuiteLayout::new(&base, "bookworm");
        assert_eq!(
            l.root_rel("pool/main/n/nginx/nginx_1.24.deb")
                .unwrap()
                .as_str(),
            "pool/main/n/nginx/nginx_1.24.deb"
        );
    }

    #[test]
    fn root_rel_rejects_absolute() {
        let base = base("https://deb.debian.org/debian");
        let l = SuiteLayout::new(&base, "bookworm");
        assert!(l.root_rel("/absolute/thing").is_err());
    }

    #[test]
    fn root_rel_rejects_traversal() {
        let base = base("https://deb.debian.org/debian");
        let l = SuiteLayout::new(&base, "bookworm");
        assert!(l.root_rel("../../etc/passwd").is_err());
    }

    #[test]
    fn suite_url_when_base_missing_trailing_slash() {
        let base = base("https://deb.debian.org/debian");
        let l = SuiteLayout::new(&base, "bookworm");
        assert_eq!(
            l.suite_url("InRelease").unwrap().as_str(),
            "https://deb.debian.org/debian/dists/bookworm/InRelease"
        );
    }

    #[test]
    fn suite_url_when_base_has_trailing_slash() {
        let base = base("https://deb.debian.org/debian/");
        let l = SuiteLayout::new(&base, "bookworm");
        assert_eq!(
            l.suite_url("InRelease").unwrap().as_str(),
            "https://deb.debian.org/debian/dists/bookworm/InRelease"
        );
    }

    #[test]
    fn root_url_for_pool_file() {
        let base = base("https://deb.debian.org/debian");
        let l = SuiteLayout::new(&base, "bookworm");
        assert_eq!(
            l.root_url("pool/main/n/nginx/nginx_1.24.deb")
                .unwrap()
                .as_str(),
            "https://deb.debian.org/debian/pool/main/n/nginx/nginx_1.24.deb"
        );
    }

    #[test]
    fn flat_suite_url_lands_at_archive_root() {
        let base = base("https://example.com/repo/");
        let l = SuiteLayout::new(&base, "./");
        assert_eq!(
            l.suite_url("Release").unwrap().as_str(),
            "https://example.com/repo/Release"
        );
    }

    #[test]
    fn slash_suite_url_composes_correctly() {
        let base = base("https://example.com/repo/");
        let l = SuiteLayout::new(&base, "stable/updates");
        assert_eq!(
            l.suite_url("InRelease").unwrap().as_str(),
            "https://example.com/repo/dists/stable/updates/InRelease"
        );
    }

    #[test]
    fn well_known_filename_shortcuts() {
        let base = base("https://deb.debian.org/debian");
        let l = SuiteLayout::new(&base, "bookworm");
        assert_eq!(
            l.inrelease_rel().unwrap().as_str(),
            "dists/bookworm/InRelease"
        );
        assert_eq!(l.release_rel().unwrap().as_str(), "dists/bookworm/Release");
        assert_eq!(
            l.release_gpg_rel().unwrap().as_str(),
            "dists/bookworm/Release.gpg"
        );
        assert!(l.inrelease_url().is_ok());
        assert!(l.release_url().is_ok());
        assert!(l.release_gpg_url().is_ok());
    }

    #[test]
    fn suite_url_rejects_unsafe_name_before_calling_url_join() {
        let base = base("https://example.com/repo/");
        let l = SuiteLayout::new(&base, "bookworm");
        assert!(l.suite_url("../../../etc/passwd").is_err());
    }

    #[test]
    fn root_url_rejects_unsafe_name() {
        let base = base("https://example.com/repo/");
        let l = SuiteLayout::new(&base, "bookworm");
        assert!(l.root_url("../etc/passwd").is_err());
    }
}
