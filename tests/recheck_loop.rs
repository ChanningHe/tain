//! InRelease recheck loop tests. An axum server appends a per-hit `# nonce=`
//! line to InRelease/Release until a given hit, simulating a mid-sync refresh.
//! The parser ignores the comment, and PGP is off, so only the bytes change.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::Router;
use axum::body::Body;
use axum::extract::{Path as AxumPath, State};
use axum::http::{Response, StatusCode};
use axum::routing::any;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tower_http::services::ServeDir;

use tain::config::model::{
    AptOptions, BackendKind, BackendOptions, GcConfig, GlobalConfig, I18nSelection, IndexSelection,
    MirrorConfig, RetryConfig, VerifyConfig,
};
use tain::core::engine::sync_mirror;

mod common;
use common::{SyntheticRepo, TempDir};

struct MutState {
    hits: AtomicUsize,
    /// First hit (1-based) that gets the stable suffix; earlier hits get a unique one.
    stabilize_from: usize,
    root: PathBuf,
}

async fn spawn_mutation_server(
    root: PathBuf,
    stabilize_from: usize,
) -> (
    SocketAddr,
    Arc<MutState>,
    oneshot::Sender<()>,
    JoinHandle<()>,
) {
    let state = Arc::new(MutState {
        hits: AtomicUsize::new(0),
        stabilize_from,
        root: root.clone(),
    });

    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    let (tx, rx) = oneshot::channel::<()>();

    let router: Router = Router::new()
        .route("/dists/{suite}/InRelease", any(mutate_handler))
        .route("/dists/{suite}/Release", any(mutate_handler))
        .with_state(state.clone())
        .fallback_service(ServeDir::new(root));

    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, router)
            .with_graceful_shutdown(async move {
                let _ = rx.await;
            })
            .await;
    });

    (addr, state, tx, handle)
}

async fn mutate_handler(
    State(s): State<Arc<MutState>>,
    AxumPath(suite): AxumPath<String>,
    req: axum::http::Request<Body>,
) -> Response<Body> {
    let hit = s.hits.fetch_add(1, Ordering::SeqCst) + 1;
    let disk = s.root.join(format!(
        "dists/{suite}/{}",
        req.uri().path().rsplit('/').next().unwrap()
    ));
    let Ok(mut bytes) = tokio::fs::read(&disk).await else {
        return Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::empty())
            .expect("resp");
    };
    let suffix = if hit >= s.stabilize_from {
        b"\n# nonce=stable\n".to_vec()
    } else {
        format!("\n# nonce={hit}\n").into_bytes()
    };
    bytes.extend_from_slice(&suffix);
    Response::builder()
        .status(StatusCode::OK)
        .header("content-length", bytes.len().to_string())
        .body(Body::from(bytes))
        .expect("resp")
}

fn build_mirror(base: url::Url, name: &str) -> MirrorConfig {
    let apt = AptOptions {
        suites: vec!["bookworm".to_owned()],
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
        create_suite_symlinks: false,
    };
    MirrorConfig {
        name: name.to_owned(),
        backend: BackendKind::Apt,
        url: base,
        path: PathBuf::from(name),
        verify: VerifyConfig::default(),
        gc: GcConfig::default(),
        force_http1: false,
        backend_options: BackendOptions::Apt(apt),
    }
}

fn build_global(target: PathBuf, retry: RetryConfig) -> GlobalConfig {
    GlobalConfig {
        target,
        parallel: 4,
        host_connections: 2,
        retry,
        ..GlobalConfig::default()
    }
}

fn retry(index_rounds: u32) -> RetryConfig {
    RetryConfig {
        count: 0,
        index_rounds,
    }
}

/// Relative path -> bytes for every regular file under `root`.
fn snapshot(root: &std::path::Path) -> BTreeMap<PathBuf, Vec<u8>> {
    let mut map = BTreeMap::new();
    fn walk(dir: &std::path::Path, base: &std::path::Path, map: &mut BTreeMap<PathBuf, Vec<u8>>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if let Ok(md) = std::fs::symlink_metadata(&path) {
                if md.file_type().is_symlink() {
                    continue;
                }
                if md.is_dir() {
                    walk(&path, base, map);
                } else if md.is_file() {
                    let rel = path.strip_prefix(base).unwrap().to_path_buf();
                    if let Ok(bytes) = std::fs::read(&path) {
                        map.insert(rel, bytes);
                    }
                }
            }
        }
    }
    walk(root, root, &mut map);
    map
}

/// Stable upstream publishes on round 0.
#[tokio::test(flavor = "current_thread", start_paused = false)]
async fn recheck_stable_first_try_publishes_and_lands_pool() {
    let serve = TempDir::new("recheck-stable-serve");
    SyntheticRepo::new(serve.path().to_path_buf(), "bookworm")
        .add_package("nginx", b"real nginx bytes".to_vec())
        .write();

    let (addr, _state, shutdown, join) = spawn_mutation_server(serve.path().to_path_buf(), 1).await;
    let base = url::Url::parse(&format!("http://{addr}/")).expect("url");

    let target = TempDir::new("recheck-stable-target");
    let global = build_global(target.path().to_path_buf(), retry(5));
    let mirror = build_mirror(base, "upstream");

    let outcome = sync_mirror(&global, &mirror, &global.target)
        .await
        .expect("sync_mirror ok");
    assert!(
        outcome.is_success(),
        "stable upstream must publish: {outcome:?}"
    );
    assert!(
        outcome.suites_failed.is_empty(),
        "no suite should have failed: {outcome:?}"
    );

    let pool = target
        .path()
        .join("upstream/pool/main/n/nginx/nginx_1.0_amd64.deb");
    assert!(pool.exists(), "pool file must be published");
    let inrelease = target.path().join("upstream/dists/bookworm/InRelease");
    assert!(inrelease.exists(), "InRelease must be published");

    let _ = shutdown.send(());
    let _ = join.await;
}

/// Upstream refreshes during round 0, then stabilizes: round 1 publishes the new bytes.
#[tokio::test(flavor = "current_thread", start_paused = false)]
async fn recheck_refolds_once_then_publishes_new_state() {
    let serve = TempDir::new("recheck-refold-serve");
    SyntheticRepo::new(serve.path().to_path_buf(), "bookworm")
        .add_package("nginx", b"real nginx bytes".to_vec())
        .write();

    // Round 0: hits 1 and 2 differ (mismatch). Round 1: hits 3 and 4 are stable.
    let (addr, state, shutdown, join) = spawn_mutation_server(serve.path().to_path_buf(), 3).await;
    let base = url::Url::parse(&format!("http://{addr}/")).expect("url");

    let target = TempDir::new("recheck-refold-target");
    let global = build_global(target.path().to_path_buf(), retry(5));
    let mirror = build_mirror(base, "upstream");

    let outcome = sync_mirror(&global, &mirror, &global.target)
        .await
        .expect("sync_mirror ok");
    assert!(
        outcome.is_success(),
        "one refold then stable must publish: {outcome:?} (hits={})",
        state.hits.load(Ordering::SeqCst)
    );

    // Published InRelease must be the "stable" variant (not the round-0
    // nonce=1/2 bytes).
    let inrelease = target.path().join("upstream/dists/bookworm/InRelease");
    let bytes = std::fs::read(&inrelease).expect("InRelease published");
    let body = String::from_utf8_lossy(&bytes);
    assert!(
        body.contains("# nonce=stable"),
        "published InRelease should carry the stable nonce, got tail: {:?}",
        &body[body.len().saturating_sub(80)..]
    );
    assert!(
        !body.contains("# nonce=1\n") && !body.contains("# nonce=2\n"),
        "published InRelease must not carry a pre-refold nonce"
    );

    let _ = shutdown.send(());
    let _ = join.await;
}

/// InRelease changes on every hit: after `index_rounds` the suite fails and
/// nothing is published.
#[tokio::test(flavor = "current_thread", start_paused = false)]
async fn recheck_exhausts_rounds_and_leaves_published_state_untouched() {
    let serve = TempDir::new("recheck-hostile-serve");
    SyntheticRepo::new(serve.path().to_path_buf(), "bookworm")
        .add_package("nginx", b"real nginx bytes".to_vec())
        .write();

    let (addr, state, shutdown, join) =
        spawn_mutation_server(serve.path().to_path_buf(), 9_999).await;
    let base = url::Url::parse(&format!("http://{addr}/")).expect("url");

    let target = TempDir::new("recheck-hostile-target");
    let mirror_root = target.path().join("upstream");
    let before = snapshot(&mirror_root);

    let global = build_global(target.path().to_path_buf(), retry(3));
    let mirror = build_mirror(base, "upstream");

    let outcome = sync_mirror(&global, &mirror, &global.target)
        .await
        .expect("sync_mirror runs");
    assert!(
        !outcome.is_success(),
        "hostile mutation must not publish (hits={})",
        state.hits.load(Ordering::SeqCst)
    );
    assert!(
        !outcome.suites_failed.is_empty(),
        "suite must be marked failed: {outcome:?}"
    );

    // Only dists/ matters: pool files may legitimately land early (pool-first).
    let _ = before;
    let after = snapshot(&mirror_root);
    let dists_files: Vec<_> = after
        .keys()
        .filter(|p| p.starts_with("dists/bookworm"))
        .collect();
    assert!(
        dists_files.is_empty(),
        "atomic-swap tree must NOT be published on exhausted recheck; got: {dists_files:?}"
    );
    assert!(
        !mirror_root.join("dists/bookworm").exists(),
        "dists/bookworm dir must not exist after exhausted refold"
    );

    let hits = state.hits.load(Ordering::SeqCst);
    assert!(
        hits >= 4,
        "hostile refresh should exercise multiple refold rounds; hits={hits}"
    );

    let _ = shutdown.send(());
    let _ = join.await;
}

/// `index_rounds = 0`: the first mid-sync refresh fails the suite.
#[tokio::test(flavor = "current_thread", start_paused = false)]
async fn recheck_zero_rounds_fails_on_first_refresh() {
    let serve = TempDir::new("recheck-zero-serve");
    SyntheticRepo::new(serve.path().to_path_buf(), "bookworm")
        .add_package("nginx", b"real nginx bytes".to_vec())
        .write();

    let (addr, _state, shutdown, join) =
        spawn_mutation_server(serve.path().to_path_buf(), 9_999).await;
    let base = url::Url::parse(&format!("http://{addr}/")).expect("url");

    let target = TempDir::new("recheck-zero-target");
    let global = build_global(target.path().to_path_buf(), retry(0));
    let mirror = build_mirror(base, "upstream");

    let outcome = sync_mirror(&global, &mirror, &global.target)
        .await
        .expect("sync_mirror runs");
    assert!(
        !outcome.is_success(),
        "index_rounds=0 with mid-sync refresh must fail: {outcome:?}"
    );
    assert!(
        !outcome.suites_failed.is_empty(),
        "suite must be marked failed at round 0 already"
    );

    // Pool files may remain (pool-first); dists/ must not.
    let mirror_root = target.path().join("upstream");
    let dists_suite = mirror_root.join("dists/bookworm");
    assert!(
        !dists_suite.exists(),
        "dists/bookworm must NOT exist under index_rounds=0 failure"
    );

    let _ = shutdown.send(());
    let _ = join.await;
}
