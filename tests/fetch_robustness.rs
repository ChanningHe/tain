//! Download-layer robustness against hostile or flaky upstreams: bounded
//! waits, size enforcement, segment cleanup, and transient-failure retry.
//! Real sockets with real time: paused time would fire reqwest's read timers
//! while I/O is in flight.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use axum::Router;
use axum::body::{Body, Bytes};
use axum::http::{HeaderMap, Response, StatusCode};
use axum::routing::any;
use sha2::{Digest as _, Sha256};
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;

use tain::core::engine::apt_flow::{AptFlowError, download_verified};
use tain::core::fetch::budget::{Budget, BudgetConfig};
use tain::core::fetch::client::{
    CacheValidators, ClientConfig, ClientError, build_client, fetch_get,
};
use tain::core::fetch::segmented::{SegmentedConfig, download_segmented, probe_range_support};
use tain::core::fetch::sink::{SinkError, tmp_path_for};
use tain::core::fetch::watchdog::WatchdogConfig;
use tain::core::types::{Digest, DigestAlgo, DigestSet};

mod common;
use common::TempDir;

type Handler = dyn Fn(usize, &HeaderMap) -> Response<Body> + Send + Sync;

/// axum server whose every request goes to `handler(hit, headers)`; `hit`
/// counts from 1.
struct FaultServer {
    addr: SocketAddr,
    hits: Arc<AtomicUsize>,
    _shutdown: tokio::sync::oneshot::Sender<()>,
}

impl FaultServer {
    async fn spawn(
        handler: impl Fn(usize, &HeaderMap) -> Response<Body> + Send + Sync + 'static,
    ) -> Self {
        let handler: Arc<Handler> = Arc::new(handler);
        let hits = Arc::new(AtomicUsize::new(0));
        let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let hits_c = Arc::clone(&hits);
        let router: Router = Router::new().fallback(any(move |headers: HeaderMap| {
            let handler = Arc::clone(&handler);
            let hit = hits_c.fetch_add(1, Ordering::SeqCst) + 1;
            async move { handler(hit, &headers) }
        }));
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            let _ = axum::serve(listener, router)
                .with_graceful_shutdown(async move {
                    let _ = rx.await;
                })
                .await;
        });
        Self {
            addr,
            hits,
            _shutdown: tx,
        }
    }

    fn url(&self, path: &str) -> url::Url {
        url::Url::parse(&format!("http://{}/{path}", self.addr)).unwrap()
    }

    fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }
}

fn sha256_set(bytes: &[u8]) -> DigestSet {
    let mut s = DigestSet::new();
    s.push(Digest::new(DigestAlgo::Sha256, Sha256::digest(bytes).to_vec()).unwrap())
        .unwrap();
    s
}

fn ok_body(bytes: Vec<u8>) -> Response<Body> {
    Response::builder()
        .status(StatusCode::OK)
        .header("content-length", bytes.len().to_string())
        .body(Body::from(bytes))
        .unwrap()
}

fn status(code: StatusCode) -> Response<Body> {
    Response::builder()
        .status(code)
        .body(Body::empty())
        .unwrap()
}

/// Chunked body: `chunks` pieces of `chunk_len` bytes, `delay` apart.
fn stream_body(chunks: usize, chunk_len: usize, delay: Duration) -> Body {
    let s = futures::stream::unfold(0usize, move |i| async move {
        if i >= chunks {
            return None;
        }
        tokio::time::sleep(delay).await;
        Some((
            Ok::<Bytes, std::io::Error>(Bytes::from(vec![b'z'; chunk_len])),
            i + 1,
        ))
    });
    Body::from_stream(s)
}

fn fast_client(idle: Duration) -> reqwest::Client {
    build_client(&ClientConfig {
        idle_timeout: idle,
        connect_timeout: Duration::from_secs(5),
        ..ClientConfig::default()
    })
    .unwrap()
}

fn watchdog(idle: Duration) -> WatchdogConfig {
    WatchdogConfig {
        idle_timeout: idle,
        ..WatchdogConfig::default()
    }
}

// ---------- response-header timeout ----------

/// Accepts, reads the request, never answers.
async fn spawn_silent_server() -> SocketAddr {
    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                while sock.read(&mut buf).await.is_ok_and(|n| n > 0) {}
            });
        }
    });
    addr
}

#[tokio::test]
async fn silent_server_get_fails_within_idle_timeout() {
    let addr = spawn_silent_server().await;
    let client = fast_client(Duration::from_millis(300));
    let url = url::Url::parse(&format!("http://{addr}/x")).unwrap();
    let start = Instant::now();
    let res = tokio::time::timeout(
        Duration::from_secs(30),
        fetch_get(&client, &url, &CacheValidators::default()),
    )
    .await
    .expect("fetch_get must not hang on a silent server");
    assert!(res.is_err(), "silent server must yield an error");
    assert!(
        start.elapsed() < Duration::from_secs(8),
        "{:?}",
        start.elapsed()
    );
}

#[tokio::test]
async fn silent_server_head_probe_is_bounded() {
    let addr = spawn_silent_server().await;
    let client = fast_client(Duration::from_millis(300));
    let url = url::Url::parse(&format!("http://{addr}/x")).unwrap();
    let res = tokio::time::timeout(Duration::from_secs(30), probe_range_support(&client, &url))
        .await
        .expect("HEAD probe must not hang on a silent server");
    assert!(res.is_err() || res.is_ok_and(|b| !b));
}

// ---------- size enforcement while streaming ----------

#[tokio::test]
async fn content_length_larger_than_expected_is_rejected_before_body() {
    let payload = b"0123456789".to_vec();
    let server = FaultServer::spawn(|_, _| ok_body(vec![b'q'; 1 << 20])).await;
    let dest_dir = TempDir::new("oversize-cl");
    let dest = dest_dir.path().join("f.deb");
    let err = download_verified(
        &Budget::new(BudgetConfig::default()),
        &fast_client(Duration::from_secs(5)),
        &server.url("f.deb"),
        &dest,
        sha256_set(&payload),
        Some(payload.len() as u64),
        0,
        watchdog(Duration::from_secs(5)),
    )
    .await
    .expect_err("oversized Content-Length must fail");
    assert!(
        matches!(
            err,
            AptFlowError::Sink(SinkError::SizeMismatch { .. } | SinkError::TooLarge { .. })
        ),
        "{err:?}"
    );
    assert!(!dest.exists());
    assert!(!tmp_path_for(&dest).exists(), "tmp must not be left behind");
}

#[tokio::test]
async fn endless_chunked_body_aborts_at_expected_size() {
    let payload = vec![b'z'; 64 * 1024];
    // No Content-Length; 100_000 chunks of 64 KiB would take minutes.
    let server = FaultServer::spawn(|_, _| {
        Response::builder()
            .status(StatusCode::OK)
            .body(stream_body(100_000, 64 * 1024, Duration::from_millis(1)))
            .unwrap()
    })
    .await;
    let dest_dir = TempDir::new("oversize-stream");
    let dest = dest_dir.path().join("f.deb");
    let start = Instant::now();
    let err = download_verified(
        &Budget::new(BudgetConfig::default()),
        &fast_client(Duration::from_secs(5)),
        &server.url("f.deb"),
        &dest,
        sha256_set(&payload),
        Some(payload.len() as u64),
        0,
        watchdog(Duration::from_secs(5)),
    )
    .await
    .expect_err("body longer than expected must fail");
    assert!(
        matches!(err, AptFlowError::Sink(SinkError::TooLarge { .. })),
        "{err:?}"
    );
    assert!(
        start.elapsed() < Duration::from_secs(20),
        "{:?}",
        start.elapsed()
    );
    assert!(!tmp_path_for(&dest).exists(), "tmp must be removed");
}

// ---------- segmented download ----------

fn parse_range(headers: &HeaderMap) -> Option<(u64, u64)> {
    let v = headers.get("range")?.to_str().ok()?;
    let (a, b) = v.strip_prefix("bytes=")?.split_once('-')?;
    Some((a.parse().ok()?, b.parse().ok()?))
}

fn partial(start: u64, end: u64, total: &str, body: Body) -> Response<Body> {
    Response::builder()
        .status(StatusCode::PARTIAL_CONTENT)
        .header("content-range", format!("bytes {start}-{end}/{total}"))
        .body(body)
        .unwrap()
}

fn seg_cfg() -> SegmentedConfig {
    SegmentedConfig {
        min_size: 1,
        segments: 4,
        segment_min_size: 1,
        watchdog: watchdog(Duration::from_secs(5)),
    }
}

/// Segment 1 fails at once; the others trickle garbage slowly. The failure
/// must abort and await the others so none writes into the tmp inode later.
#[tokio::test]
async fn segment_failure_aborts_siblings_and_releases_permits() {
    let content: Arc<Vec<u8>> = Arc::new((0..64 * 1024u32).map(|i| (i % 251) as u8).collect());
    let size = content.len() as u64;
    let c = Arc::clone(&content);
    let server = FaultServer::spawn(move |_, headers| {
        let Some((start, end)) = parse_range(headers) else {
            return ok_body(c.to_vec());
        };
        if start == 0 {
            // Garbage, slowly: 16 chunks × 1 KiB, 1 s apart.
            return partial(
                start,
                end,
                &c.len().to_string(),
                stream_body(16, 1024, Duration::from_secs(1)),
            );
        }
        if start == size / 4 {
            return status(StatusCode::INTERNAL_SERVER_ERROR);
        }
        let body = Body::from(c[start as usize..=end as usize].to_vec());
        partial(start, end, &c.len().to_string(), body)
    })
    .await;
    let budget = Budget::new(BudgetConfig {
        global_parallel: 8,
        host_connections: 8,
    });
    let client = fast_client(Duration::from_secs(5));
    let dest_dir = TempDir::new("seg-abort");
    let dest = dest_dir.path().join("big.iso");
    let url = server.url("big.iso");

    let start = Instant::now();
    let err = download_segmented(
        &client,
        &budget,
        &url,
        &dest,
        size,
        &sha256_set(&content),
        &seg_cfg(),
    )
    .await
    .expect_err("a failed segment fails the download");
    assert!(
        start.elapsed() < Duration::from_secs(8),
        "must not wait for slow siblings: {:?}",
        start.elapsed()
    );
    let _ = err;
    // Every sibling has been awaited: all permits are back with no yield.
    assert_eq!(budget.global_available(), 8);
    assert_eq!(budget.host_available("127.0.0.1"), Some(8));

    // Single-connection fallback into the same dest.
    download_verified(
        &budget,
        &client,
        &url,
        &dest,
        sha256_set(&content),
        Some(size),
        0,
        watchdog(Duration::from_secs(5)),
    )
    .await
    .expect("fallback download");
    // Give an un-aborted sibling time to write; nothing may scribble on dest.
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(
        std::fs::read(&dest).unwrap(),
        *content,
        "verified file was modified after rename"
    );
}

#[tokio::test]
async fn segment_content_range_total_mismatch_is_rejected() {
    let content: Arc<Vec<u8>> = Arc::new(vec![7u8; 4096]);
    let c = Arc::clone(&content);
    let server = FaultServer::spawn(move |_, headers| {
        let (start, end) = parse_range(headers).unwrap();
        let body = Body::from(c[start as usize..=end as usize].to_vec());
        partial(start, end, "999999", body)
    })
    .await;
    let budget = Budget::new(BudgetConfig::default());
    let dest_dir = TempDir::new("seg-total");
    let dest = dest_dir.path().join("x.iso");
    let res = download_segmented(
        &fast_client(Duration::from_secs(5)),
        &budget,
        &server.url("x.iso"),
        &dest,
        content.len() as u64,
        &sha256_set(&content),
        &seg_cfg(),
    )
    .await;
    assert!(
        res.is_err(),
        "Content-Range total != expected size must fail"
    );
    assert!(!dest.exists());
    assert!(
        !tmp_path_for(&dest).exists(),
        "failed segmented download leaves no tmp"
    );
}

/// A segment streaming past its range (no Content-Length) fails as soon as
/// it overruns, not after the whole body.
#[tokio::test]
async fn overlong_segment_aborts_early() {
    let content: Arc<Vec<u8>> = Arc::new(vec![1u8; 4096]);
    let c = Arc::clone(&content);
    let server = FaultServer::spawn(move |_, headers| {
        let (start, end) = parse_range(headers).unwrap();
        partial(
            start,
            end,
            &c.len().to_string(),
            stream_body(100_000, 1024, Duration::from_millis(1)),
        )
    })
    .await;
    let dest_dir = TempDir::new("seg-overlong");
    let dest = dest_dir.path().join("x.iso");
    let start = Instant::now();
    let res = download_segmented(
        &fast_client(Duration::from_secs(5)),
        &Budget::new(BudgetConfig::default()),
        &server.url("x.iso"),
        &dest,
        content.len() as u64,
        &sha256_set(&content),
        &seg_cfg(),
    )
    .await;
    assert!(res.is_err());
    assert!(
        start.elapsed() < Duration::from_secs(20),
        "{:?}",
        start.elapsed()
    );
}

// ---------- retry of transient failures ----------

async fn run_retry_case(
    payload: Vec<u8>,
    retry_count: u32,
    idle: Duration,
    handler: impl Fn(usize, &HeaderMap) -> Response<Body> + Send + Sync + 'static,
) -> (Result<(), AptFlowError>, usize, Vec<u8>) {
    let server = FaultServer::spawn(handler).await;
    let dest_dir = TempDir::new("retry");
    let dest = dest_dir.path().join("p.deb");
    let res = download_verified(
        &Budget::new(BudgetConfig::default()),
        &fast_client(idle),
        &server.url("p.deb"),
        &dest,
        sha256_set(&payload),
        Some(payload.len() as u64),
        retry_count,
        watchdog(idle),
    )
    .await;
    let on_disk = std::fs::read(&dest).unwrap_or_default();
    assert!(!tmp_path_for(&dest).exists(), "no tmp left behind");
    (res, server.hits(), on_disk)
}

fn payload() -> Vec<u8> {
    b"the real package bytes".to_vec()
}

#[tokio::test]
async fn transient_502_is_retried() {
    let p = payload();
    let pc = p.clone();
    let (res, hits, disk) = run_retry_case(p.clone(), 3, Duration::from_secs(5), move |hit, _| {
        if hit == 1 {
            status(StatusCode::BAD_GATEWAY)
        } else {
            ok_body(pc.clone())
        }
    })
    .await;
    res.expect("retry rides through a 502");
    assert_eq!(hits, 2);
    assert_eq!(disk, p);
}

#[tokio::test]
async fn transient_body_error_is_retried() {
    let p = payload();
    let pc = p.clone();
    let (res, hits, disk) = run_retry_case(p.clone(), 3, Duration::from_secs(5), move |hit, _| {
        if hit == 1 {
            // Content-Length promises more than the stream yields, then errors.
            let s = futures::stream::iter(vec![
                Ok::<Bytes, std::io::Error>(Bytes::from_static(b"the")),
                Err(std::io::Error::other("reset")),
            ]);
            Response::builder()
                .status(StatusCode::OK)
                .header("content-length", pc.len().to_string())
                .body(Body::from_stream(s))
                .unwrap()
        } else {
            ok_body(pc.clone())
        }
    })
    .await;
    res.expect("retry rides through a body read error");
    assert_eq!(hits, 2);
    assert_eq!(disk, p);
}

#[tokio::test]
async fn corrupt_once_is_retried() {
    let p = payload();
    let pc = p.clone();
    let (res, hits, disk) = run_retry_case(p.clone(), 3, Duration::from_secs(5), move |hit, _| {
        if hit == 1 {
            ok_body(vec![b'X'; pc.len()])
        } else {
            ok_body(pc.clone())
        }
    })
    .await;
    res.expect("retry rides through a digest mismatch");
    assert_eq!(hits, 2);
    assert_eq!(disk, p);
}

#[tokio::test]
async fn stall_once_is_retried() {
    let p = payload();
    let pc = p.clone();
    let (res, hits, disk) =
        run_retry_case(p.clone(), 3, Duration::from_millis(300), move |hit, _| {
            if hit == 1 {
                Response::builder()
                    .status(StatusCode::OK)
                    .body(Body::from_stream(futures::stream::pending::<
                        Result<Bytes, std::io::Error>,
                    >()))
                    .unwrap()
            } else {
                ok_body(pc.clone())
            }
        })
        .await;
    res.expect("retry rides through a stalled body");
    assert_eq!(hits, 2);
    assert_eq!(disk, p);
}

#[tokio::test]
async fn persistent_500_fails_after_count_plus_one_attempts() {
    let (res, hits, _) = run_retry_case(payload(), 2, Duration::from_secs(5), |_, _| {
        status(StatusCode::INTERNAL_SERVER_ERROR)
    })
    .await;
    assert!(
        matches!(res, Err(AptFlowError::UpstreamStatus { status, .. }) if status == StatusCode::INTERNAL_SERVER_ERROR),
        "{res:?}"
    );
    assert_eq!(hits, 3);
}

#[tokio::test]
async fn not_found_is_not_retried() {
    let (res, hits, _) = run_retry_case(payload(), 3, Duration::from_secs(5), |_, _| {
        status(StatusCode::NOT_FOUND)
    })
    .await;
    assert!(
        matches!(res, Err(AptFlowError::UpstreamStatus { status, .. }) if status == StatusCode::NOT_FOUND),
        "{res:?}"
    );
    assert_eq!(hits, 1);
}

/// A connect failure stays transient even when the URL mentions certificates.
#[tokio::test]
async fn connect_refused_for_ca_certificates_url_stays_retryable() {
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let url = url::Url::parse(&format!(
        "http://127.0.0.1:{port}/debian/pool/main/c/ca-certificates/ca-certificates_20240203_all.deb"
    ))
    .unwrap();
    let dest_dir = TempDir::new("ca-certs");
    let res = download_verified(
        &Budget::new(BudgetConfig::default()),
        &fast_client(Duration::from_secs(5)),
        &url,
        &dest_dir.path().join("ca.deb"),
        sha256_set(b"x"),
        Some(1),
        0,
        watchdog(Duration::from_secs(5)),
    )
    .await;
    assert!(
        matches!(res, Err(AptFlowError::Client(ClientError::Request(_)))),
        "{res:?}"
    );
}

/// TLS server presenting the committed self-signed certificate; counts
/// accepted connections. Plain rustls on a thread: no extra dependency.
fn spawn_selfsigned_tls_server() -> (SocketAddr, Arc<AtomicUsize>) {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/tls");
    let cert = CertificateDer::from(std::fs::read(dir.join("selfsigned.cert.der")).unwrap());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        std::fs::read(dir.join("selfsigned.key.der")).unwrap(),
    ));
    let config = Arc::new(
        rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap(),
    );
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let accepted = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&accepted);
    std::thread::spawn(move || {
        for sock in listener.incoming() {
            let Ok(mut sock) = sock else { return };
            counter.fetch_add(1, Ordering::SeqCst);
            let _ = sock.set_read_timeout(Some(Duration::from_secs(5)));
            let mut conn = rustls::ServerConnection::new(Arc::clone(&config)).unwrap();
            // Runs until the client aborts on the untrusted certificate.
            while conn.is_handshaking() && conn.complete_io(&mut sock).is_ok() {}
        }
    });
    (addr, accepted)
}

/// An untrusted certificate is permanent: one connection, no retry.
#[tokio::test]
async fn untrusted_certificate_is_refused_and_not_retried() {
    let (addr, accepted) = spawn_selfsigned_tls_server();
    let url = url::Url::parse(&format!("https://127.0.0.1:{}/p.deb", addr.port())).unwrap();
    let dest_dir = TempDir::new("tls");
    let res = download_verified(
        &Budget::new(BudgetConfig::default()),
        &fast_client(Duration::from_secs(5)),
        &url,
        &dest_dir.path().join("p.deb"),
        sha256_set(b"x"),
        Some(1),
        3,
        watchdog(Duration::from_secs(5)),
    )
    .await;
    assert!(
        matches!(res, Err(AptFlowError::Client(ClientError::Refused(_)))),
        "{res:?}"
    );
    assert_eq!(accepted.load(Ordering::SeqCst), 1);
}

/// A redirect the policy refuses is permanent: no backoff, no second try.
#[tokio::test]
async fn refused_redirect_is_not_retried() {
    let (res, hits, _) = run_retry_case(payload(), 3, Duration::from_secs(5), |_, _| {
        Response::builder()
            .status(StatusCode::FOUND)
            .header("location", "ftp://127.0.0.1/p.deb")
            .body(Body::empty())
            .unwrap()
    })
    .await;
    assert!(
        matches!(res, Err(AptFlowError::Client(ClientError::Refused(_)))),
        "{res:?}"
    );
    assert_eq!(hits, 1);
}
