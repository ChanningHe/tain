//! 429 pacer and slow-body watchdog tests. An axum server injects one fault
//! on `/pool/` paths and serves everything else from disk.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

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
use tain::core::engine::apt_flow::download_verified;
use tain::core::engine::sync_mirror;
use tain::core::fetch::budget::{Budget, BudgetConfig};
use tain::core::fetch::client::{ClientConfig, build_client};
use tain::core::fetch::watchdog::WatchdogConfig;
use tain::core::types::{Digest, DigestAlgo, DigestSet};

mod common;
use common::{SyntheticRepo, TempDir};

struct PoolState {
    hits: AtomicUsize,
    fail_first_n: usize,
    retry_after_secs: u64,
    root: PathBuf,
    behavior: PoolBehavior,
}

#[derive(Clone, Copy)]
enum PoolBehavior {
    /// First N pool hits return 429, then serve from disk.
    ThrottleThenServe,
    /// Every pool hit returns 429.
    AlwaysThrottle,
    /// Serve the pool body one byte per `chunk_delay_ms`.
    SlowBody { chunk_delay_ms: u64 },
}

/// Returns (addr, shutdown trigger, join handle).
async fn spawn_pool_server(
    root: PathBuf,
    behavior: PoolBehavior,
    fail_first_n: usize,
    retry_after_secs: u64,
) -> (SocketAddr, oneshot::Sender<()>, JoinHandle<()>) {
    let state = Arc::new(PoolState {
        hits: AtomicUsize::new(0),
        fail_first_n,
        retry_after_secs,
        root: root.clone(),
        behavior,
    });

    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    let (tx, rx) = oneshot::channel::<()>();

    let router: Router = Router::new()
        .route("/pool/{*rest}", any(pool_handler))
        .with_state(state)
        .fallback_service(ServeDir::new(root));

    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, router)
            .with_graceful_shutdown(async move {
                let _ = rx.await;
            })
            .await;
    });

    (addr, tx, handle)
}

async fn pool_handler(
    State(s): State<Arc<PoolState>>,
    AxumPath(rest): AxumPath<String>,
) -> Response<Body> {
    let hit = s.hits.fetch_add(1, Ordering::SeqCst) + 1;
    let throttle_now = match s.behavior {
        PoolBehavior::ThrottleThenServe => hit <= s.fail_first_n,
        PoolBehavior::AlwaysThrottle => true,
        PoolBehavior::SlowBody { .. } => false,
    };
    if throttle_now {
        return Response::builder()
            .status(StatusCode::TOO_MANY_REQUESTS)
            .header("Retry-After", s.retry_after_secs.to_string())
            .body(Body::empty())
            .expect("resp");
    }

    if let PoolBehavior::SlowBody { chunk_delay_ms } = s.behavior {
        let full_path = s.root.join("pool").join(&rest);
        let bytes = tokio::fs::read(&full_path).await.unwrap_or_default();
        return slow_body_response(bytes, chunk_delay_ms);
    }

    let full_path = s.root.join("pool").join(&rest);
    match tokio::fs::read(&full_path).await {
        Ok(bytes) => Response::builder()
            .status(StatusCode::OK)
            .header("content-length", bytes.len().to_string())
            .body(Body::from(bytes))
            .expect("resp"),
        Err(_) => Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::empty())
            .expect("resp"),
    }
}

fn slow_body_response(bytes: Vec<u8>, chunk_delay_ms: u64) -> Response<Body> {
    use futures::stream;
    let chunks: Vec<Result<axum::body::Bytes, std::io::Error>> = bytes
        .into_iter()
        .map(|b| Ok(axum::body::Bytes::from(vec![b])))
        .collect();
    let s = stream::unfold(chunks.into_iter(), move |mut it| async move {
        let next = it.next()?;
        tokio::time::sleep(Duration::from_millis(chunk_delay_ms)).await;
        Some((next, it))
    });
    Response::builder()
        .status(StatusCode::OK)
        .body(Body::from_stream(s))
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

/// Two 429s with `Retry-After: 1`, then success: default `retry.count = 3` rides through.
#[tokio::test(flavor = "current_thread", start_paused = false)]
async fn pool_429_retry_after_sync_eventually_succeeds() {
    let serve = TempDir::new("pacer-serve");
    SyntheticRepo::new(serve.path().to_path_buf(), "bookworm")
        .add_package("nginx", b"real nginx bytes".to_vec())
        .write();

    let (addr, shutdown, join) = spawn_pool_server(
        serve.path().to_path_buf(),
        PoolBehavior::ThrottleThenServe,
        2, // fail first 2 requests, then serve
        1, // Retry-After: 1s
    )
    .await;
    let base = url::Url::parse(&format!("http://{addr}/")).expect("url");

    let target = TempDir::new("pacer-target");
    let global = build_global(target.path().to_path_buf(), RetryConfig::default());
    let mirror = build_mirror(base, "upstream");

    let outcome = sync_mirror(&global, &mirror, &global.target)
        .await
        .expect("sync_mirror ok");
    assert!(
        outcome.is_success(),
        "sync must succeed after 2× 429 backoff: {outcome:?}"
    );

    let pool = target
        .path()
        .join("upstream/pool/main/n/nginx/nginx_1.0_amd64.deb");
    assert_eq!(std::fs::read(&pool).unwrap(), b"real nginx bytes");

    let _ = shutdown.send(());
    let _ = join.await;
}

/// Permanent 429 with `retry.count = 0`: one attempt, then the suite fails.
#[tokio::test(flavor = "current_thread", start_paused = false)]
async fn pool_hostile_429_bails_when_retry_budget_is_zero() {
    let serve = TempDir::new("hostile-serve");
    SyntheticRepo::new(serve.path().to_path_buf(), "bookworm")
        .add_package("nginx", b"unreachable bytes".to_vec())
        .write();

    let (addr, shutdown, join) = spawn_pool_server(
        serve.path().to_path_buf(),
        PoolBehavior::AlwaysThrottle,
        0,
        0, // Retry-After: 0s — must not linger even without retry_count
    )
    .await;
    let base = url::Url::parse(&format!("http://{addr}/")).expect("url");

    let target = TempDir::new("hostile-target");
    let retry = RetryConfig {
        count: 0,
        index_rounds: 0,
    };
    let global = build_global(target.path().to_path_buf(), retry);
    let mirror = build_mirror(base, "upstream");

    let outcome = sync_mirror(&global, &mirror, &global.target)
        .await
        .expect("sync_mirror runs");
    assert!(
        !outcome.suites_failed.is_empty(),
        "suite must be marked failed under hostile 429: {outcome:?}"
    );
    assert!(!outcome.is_success(), "sync should not succeed");

    let pool = target
        .path()
        .join("upstream/pool/main/n/nginx/nginx_1.0_amd64.deb");
    assert!(!pool.exists(), "no pool file should have been published");

    let _ = shutdown.send(());
    let _ = join.await;
}

/// One byte per 100ms is far below a 10 KiB/s floor, so the watchdog trips.
/// Calls `download_verified` directly: the rate-floor knobs are not configurable.
#[tokio::test(flavor = "current_thread", start_paused = false)]
async fn slow_body_stream_trips_watchdog() {
    let serve = TempDir::new("slow-serve");
    let pool = serve.path().join("pool/main/n/nginx");
    std::fs::create_dir_all(&pool).unwrap();
    let payload = vec![b'x'; 32];
    std::fs::write(pool.join("nginx_1.0_amd64.deb"), &payload).unwrap();

    let (addr, shutdown, join) = spawn_pool_server(
        serve.path().to_path_buf(),
        PoolBehavior::SlowBody {
            chunk_delay_ms: 100,
        },
        0,
        0,
    )
    .await;

    let url = url::Url::parse(&format!(
        "http://{addr}/pool/main/n/nginx/nginx_1.0_amd64.deb"
    ))
    .unwrap();
    let client = build_client(&ClientConfig::default()).expect("client");
    let budget = Budget::new(BudgetConfig::default());
    let dest = TempDir::new("slow-dest");
    let dest_path = dest.path().join("nginx.deb");

    // Bogus digest: the download must abort before verification.
    let mut expected = DigestSet::default();
    expected
        .push(Digest::new(DigestAlgo::Sha256, vec![0u8; 32]).unwrap())
        .unwrap();

    let watchdog = WatchdogConfig {
        idle_timeout: Duration::from_secs(30), // don't want idle to fire — we want Slow
        min_rate_bytes_per_sec: 10 * 1024,
        min_rate_window: Duration::from_millis(200),
        startup_grace: Duration::from_millis(0),
    };

    let result = download_verified(
        &budget,
        &client,
        &url,
        &dest_path,
        expected,
        Some(payload.len() as u64),
        0,
        watchdog,
    )
    .await;

    assert!(
        matches!(
            result,
            Err(tain::core::engine::apt_flow::AptFlowError::WatchdogTripped { .. })
        ),
        "expected WatchdogTripped, got {result:?}"
    );

    let _ = shutdown.send(());
    let _ = join.await;
}
