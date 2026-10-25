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
    /// or, in a flat repo, `xyz.deb`). Applies `Filename` path safety,
    /// including `RelPath`'s refusal of `.tain/` and `~` sidecar names.
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

/// Append `suffix` (an already validated relative path) under `base` as
/// literal path segments. Never parsed as a URL reference, so `http:host/x`,
/// `?`, `#` and `%` cannot leave the base origin or alter the request path.
/// Errors name only the base path: the base may carry `user:password@`.
fn join_url(base: &Url, suffix: &str) -> Result<Url, LayoutError> {
    let mut url = base.clone();
    url.set_query(None);
    url.set_fragment(None);
    let base_dir = base.path().trim_end_matches('/').to_owned();
    url.path_segments_mut()
        .map_err(|()| {
            LayoutError::UrlJoin(format!("{} base URL cannot hold a path", base.scheme()))
        })?
        .pop_if_empty()
        .extend(suffix.split('/'));
    // Defense in depth: scheme and authority are untouched by construction, so
    // only the path prefix can go wrong.
    let Some(appended) = url
        .path()
        .strip_prefix(&base_dir)
        .filter(|rest| rest.starts_with('/'))
    else {
        return Err(LayoutError::UrlJoin(format!(
            "{suffix:?} escapes base path {base_dir:?}"
        )));
    };
    // `extend` leaves `+` and `~` literal; apt quotes both (`QuoteString(.., "+~ ")`),
    // and S3 reads a raw `+` as a space. Neither can come from the encoder itself.
    let appended = appended.replace('+', "%2B").replace('~', "%7E");
    url.set_path(&format!("{base_dir}{appended}"));
    Ok(url)
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
    fn root_rel_rejects_tain_state_and_sidecars() {
        let base = base("https://deb.debian.org/debian");
        let l = SuiteLayout::new(&base, "bookworm");
        for name in [".tain/state.json", ".tain/lock", "foo.tmp~"] {
            assert!(l.root_rel(name).is_err(), "{name}");
            assert!(l.root_url(name).is_err(), "{name}");
        }
    }

    #[test]
    fn flat_suite_rel_rejects_tain_state() {
        // A flat Release's checksum paths land directly under the mirror root.
        let base = base("https://example.com/repo/");
        let l = SuiteLayout::new(&base, "./");
        assert!(l.suite_rel(".tain/state.json").is_err());
    }

    #[test]
    fn scheme_relative_filename_stays_on_base_origin() {
        for base_str in [
            "https://deb.debian.org/debian",
            "http://deb.debian.org/debian/",
        ] {
            let base = base(base_str);
            let l = SuiteLayout::new(&base, "bookworm");
            for name in [
                "https:127.0.0.1:18799/x.deb",
                "http:169.254.169.254/latest/meta-data",
                "ftp:evil.example/x.deb",
                "javascript:alert(1)",
            ] {
                let url = l.root_url(name).unwrap();
                assert_eq!(url.host_str(), Some("deb.debian.org"), "{name} -> {url}");
                assert_eq!(url.scheme(), base.scheme(), "{name} -> {url}");
                assert!(url.path().starts_with("/debian/"), "{name} -> {url}");
            }
        }
    }

    #[test]
    fn url_metacharacters_in_filename_are_percent_encoded() {
        let base = base("https://example.com/repo");
        let l = SuiteLayout::new(&base, "bookworm");
        // Must stay one path, not a query/fragment or a decoded `%3a`.
        assert_eq!(
            l.root_url("pool/a?b#c.deb").unwrap().as_str(),
            "https://example.com/repo/pool/a%3Fb%23c.deb"
        );
        assert_eq!(
            l.root_url("pool/x/x_1%3a2.0_all.deb").unwrap().as_str(),
            "https://example.com/repo/pool/x/x_1%253a2.0_all.deb"
        );
    }

    #[test]
    fn plus_and_tilde_are_quoted_like_apt() {
        // apt quotes `+~ ` (S3 decodes a raw `+` as a space, LP#1003633);
        // the configured base path is left as written.
        let base = base("https://example.com/~me/debian");
        let l = SuiteLayout::new(&base, "bookworm");
        assert_eq!(
            l.root_url("pool/main/g/g++-12/g++-12_12.3.0-1~deb12u1_amd64.deb")
                .unwrap()
                .as_str(),
            "https://example.com/~me/debian/pool/main/g/g%2B%2B-12/g%2B%2B-12_12.3.0-1%7Edeb12u1_amd64.deb"
        );
    }

    #[test]
    fn url_errors_do_not_echo_the_base_url() {
        let base = base("mailto:user:s3cret@example.com");
        let l = SuiteLayout::new(&base, "bookworm");
        let err = l.root_url("pool/x.deb").unwrap_err().to_string();
        assert!(!err.contains("s3cret"), "{err}");
    }

    #[test]
    fn base_query_and_fragment_are_dropped() {
        let base = base("https://example.com/repo/?token=1#frag");
        let l = SuiteLayout::new(&base, "bookworm");
        assert_eq!(
            l.suite_url("InRelease").unwrap().as_str(),
            "https://example.com/repo/dists/bookworm/InRelease"
        );
    }

    #[test]
    fn root_url_rejects_unsafe_name() {
        let base = base("https://example.com/repo/");
        let l = SuiteLayout::new(&base, "bookworm");
        assert!(l.root_url("../etc/passwd").is_err());
    }
}
