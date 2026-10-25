//! Hostile `Filename:` values that point into `dists/` must fail only the
//! suite whose index carries them, on the pool fence: suite alias symlinks,
//! other suites' trees and Release-listed paths stay untouched.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::State;
use axum::http::{Response, StatusCode, Uri};
use tokio::net::TcpListener;

use tain::config::model::{
    AptOptions, BackendKind, BackendOptions, GcConfig, GlobalConfig, I18nSelection, IndexSelection,
    MirrorConfig, RetryConfig, VerifyConfig,
};
use tain::core::engine::apt_flow::{AptFlowError, FetchTuning, sync_apt_suite};
use tain::core::engine::{MirrorOutcome, sync_mirror};
use tain::core::fetch::budget::{Budget, BudgetConfig};
use tain::core::fetch::client::{ClientConfig, build_client};
use tain::core::store::manifest::GenerationManifest;
use tain::core::store::state;

mod common;
use common::{SyntheticRepo, TempDir};

/// Serves `root`, except for paths listed in `overrides` (a file and a
/// directory cannot share a name on disk, but upstream may claim both).
struct Upstream {
    root: PathBuf,
    overrides: HashMap<String, Vec<u8>>,
}

async fn handler(State(up): State<Arc<Upstream>>, uri: Uri) -> Response<Body> {
    let path = uri.path();
    let (status, body) = match up.overrides.get(path) {
        Some(bytes) => (StatusCode::OK, bytes.clone()),
        None => match std::fs::read(up.root.join(path.trim_start_matches('/'))) {
            Ok(bytes) => (StatusCode::OK, bytes),
            Err(_) => (StatusCode::NOT_FOUND, Vec::new()),
        },
    };
    Response::builder()
        .status(status)
        .body(Body::from(body))
        .unwrap()
}

async fn spawn_upstream(root: PathBuf, overrides: HashMap<String, Vec<u8>>) -> url::Url {
    let up = Arc::new(Upstream { root, overrides });
    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    let router: Router = Router::new().fallback(handler).with_state(up);
    tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    url::Url::parse(&format!("http://{addr}/")).unwrap()
}

fn build_mirror(base: url::Url, suites: &[&str], create_suite_symlinks: bool) -> MirrorConfig {
    let apt = AptOptions {
        suites: suites.iter().map(|s| (*s).to_owned()).collect(),
        components: vec!["main".to_owned()],
        architectures: vec!["amd64".to_owned()],
        indexes: IndexSelection {
            packages: true,
            contents: false,
            i18n: I18nSelection::None,
            dep11: false,
            cnf: false,
            sources: false,
            debian_installer: false,
        },
        create_suite_symlinks,
    };
    MirrorConfig {
        name: "up".to_owned(),
        backend: BackendKind::Apt,
        url: base,
        path: PathBuf::from("up"),
        verify: VerifyConfig::default(),
        gc: GcConfig::default(),
        force_http1: false,
        backend_options: BackendOptions::Apt(apt),
    }
}

fn build_global(target: &Path) -> GlobalConfig {
    GlobalConfig {
        target: target.to_path_buf(),
        retry: RetryConfig {
            count: 0,
            index_rounds: 2,
        },
        ..GlobalConfig::default()
    }
}

async fn sync(global: &GlobalConfig, mirror: &MirrorConfig) -> MirrorOutcome {
    sync_mirror(global, mirror, &global.target).await.unwrap()
}

const OUTSIDE_OWN: &str = "a path under dists/ outside this suite's directory";

/// Rerun `suite` alone as the engine does and check that it fails on the
/// pool fence for `path` with `reason`, not on something unrelated.
async fn assert_fenced(
    global: &GlobalConfig,
    mirror: &MirrorConfig,
    suite: &str,
    path: &str,
    reason: &str,
) {
    let mirror_root = global.target.join(&mirror.path);
    let prior = state::load(&mirror_root)
        .unwrap()
        .and_then(|s| s.suites.get(suite).cloned())
        .unwrap_or_default();
    let client = build_client(&ClientConfig::from(global)).unwrap();
    let budget = Budget::new(BudgetConfig::from(global));
    let mut manifest = GenerationManifest::new(1_000);
    let BackendOptions::Apt(apt) = &mirror.backend_options;
    let err = sync_apt_suite(
        &client,
        &budget,
        mirror,
        apt,
        &mirror_root,
        suite,
        &prior,
        &mut manifest,
        &FetchTuning::from(global),
        global.retry.index_rounds,
        false,
        None,
    )
    .await
    .unwrap_err();
    assert!(
        matches!(&err, AptFlowError::PoolPathConflict { path: p, reason: r }
            if p == path && *r == reason),
        "{suite}: {err:?}"
    );
}

fn is_symlink(p: &Path) -> bool {
    std::fs::symlink_metadata(p).is_ok_and(|m| m.file_type().is_symlink())
}

#[tokio::test]
async fn filename_equal_to_an_alias_never_replaces_the_alias_symlink() {
    let serve = TempDir::new("fence-alias-file-serve");
    SyntheticRepo::new(serve.path().to_path_buf(), "bookworm")
        .with_suite_alias("stable")
        .add_package("nginx", b"nginx bytes".to_vec())
        .write();
    SyntheticRepo::new(serve.path().to_path_buf(), "trixie")
        .add_package_at("evil", "dists/stable", b"forged".to_vec())
        .write();
    let base = spawn_upstream(serve.path().to_path_buf(), HashMap::new()).await;
    let target = TempDir::new("fence-alias-file-target");
    let global = build_global(target.path());
    let mirror = build_mirror(base, &["bookworm", "trixie"], true);
    let alias = target.path().join("up/dists/stable");

    for run in 0..2 {
        let outcome = sync(&global, &mirror).await;
        assert_eq!(
            outcome.suites_failed,
            vec!["trixie".to_owned()],
            "run {run}"
        );
        assert!(is_symlink(&alias), "run {run}: alias symlink replaced");
        assert!(alias.join("InRelease").is_file(), "run {run}");
    }
    assert_fenced(&global, &mirror, "trixie", "dists/stable", OUTSIDE_OWN).await;
}

#[tokio::test]
async fn filename_below_a_future_alias_never_creates_a_real_directory() {
    let serve = TempDir::new("fence-alias-dir-serve");
    SyntheticRepo::new(serve.path().to_path_buf(), "bookworm")
        .with_suite_alias("stable")
        .add_package("nginx", b"nginx bytes".to_vec())
        .write();
    SyntheticRepo::new(serve.path().to_path_buf(), "trixie")
        .add_package_at("evil", "dists/stable/InRelease.deb", b"forged".to_vec())
        .write();
    let base = spawn_upstream(serve.path().to_path_buf(), HashMap::new()).await;
    let target = TempDir::new("fence-alias-dir-target");
    let global = build_global(target.path());
    // trixie first: the alias does not exist yet when its pool is fenced.
    let mirror = build_mirror(base, &["trixie", "bookworm"], true);
    let alias = target.path().join("up/dists/stable");

    for run in 0..2 {
        let outcome = sync(&global, &mirror).await;
        assert_eq!(
            outcome.suites_failed,
            vec!["trixie".to_owned()],
            "run {run}"
        );
        assert!(is_symlink(&alias), "run {run}: alias is not a symlink");
        assert!(alias.join("InRelease").is_file(), "run {run}");
    }
    let path = "dists/stable/InRelease.deb";
    assert_fenced(&global, &mirror, "trixie", path, OUTSIDE_OWN).await;
}

#[tokio::test]
async fn filename_equal_to_another_suite_dir_does_not_block_that_suite() {
    let serve = TempDir::new("fence-other-suite-serve");
    SyntheticRepo::new(serve.path().to_path_buf(), "bookworm")
        .add_package_at("evil", "dists/trixie", b"forged".to_vec())
        .write();
    std::fs::remove_file(serve.path().join("dists/trixie")).unwrap();
    SyntheticRepo::new(serve.path().to_path_buf(), "trixie")
        .add_package("curl", b"curl bytes".to_vec())
        .write();
    let overrides = HashMap::from([("/dists/trixie".to_owned(), b"forged".to_vec())]);
    let base = spawn_upstream(serve.path().to_path_buf(), overrides).await;
    let target = TempDir::new("fence-other-suite-target");
    let global = build_global(target.path());
    let mirror = build_mirror(base, &["bookworm", "trixie"], false);

    for run in 0..2 {
        let outcome = sync(&global, &mirror).await;
        assert_eq!(
            outcome.suites_failed,
            vec!["bookworm".to_owned()],
            "run {run}"
        );
        assert!(
            target.path().join("up/dists/trixie/InRelease").is_file(),
            "run {run}: trixie not published"
        );
    }
    let reason = "another configured suite's directory";
    assert_fenced(&global, &mirror, "bookworm", "dists/trixie", reason).await;
}

/// Append a weak-only (MD5) entry to both root files of `suite`.
fn list_weak_only(serve: &Path, suite: &str, rel: &str, size: usize) {
    for name in ["Release", "InRelease"] {
        let path = serve.join(format!("dists/{suite}/{name}"));
        let mut body = std::fs::read_to_string(&path).unwrap();
        body.push_str(&format!("MD5Sum:\n {} {size} {rel}\n", "0".repeat(32)));
        std::fs::write(&path, body).unwrap();
    }
}

#[tokio::test]
async fn pool_file_on_a_weak_only_release_path_is_refused() {
    let serve = TempDir::new("fence-weak-only-serve");
    let rel = "main/binary-amd64/Packages.bz2";
    SyntheticRepo::new(serve.path().to_path_buf(), "bookworm")
        .add_package("nginx", b"nginx bytes".to_vec())
        .add_package_at("evil", format!("dists/bookworm/{rel}"), b"forged".to_vec())
        .write();
    list_weak_only(serve.path(), "bookworm", rel, 6);
    let base = spawn_upstream(serve.path().to_path_buf(), HashMap::new()).await;
    let target = TempDir::new("fence-weak-only-target");
    let global = build_global(target.path());
    let mirror = build_mirror(base, &["bookworm"], false);

    let outcome = sync(&global, &mirror).await;
    assert_eq!(outcome.suites_failed, vec!["bookworm".to_owned()]);
    assert!(!target.path().join("up/dists/bookworm").join(rel).exists());
    let path = format!("dists/bookworm/{rel}");
    let reason = "a file listed in Release with weak digests only";
    assert_fenced(&global, &mirror, "bookworm", &path, reason).await;
}
