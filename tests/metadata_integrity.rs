//! Metadata-phase integrity: Date monotonicity across crashes and Release-only
//! upstreams, sibling root-file vetting, manifest rollback scoping, 4xx
//! fallbacks, weak-digest policy, PGP downgrade memory, change-token
//! canonicalisation and bounded root-file reads.
//!
//! The upstream is a tiny axum server without conditional-GET support, so
//! every run really re-reads the bodies; per-path faults are injected.

use std::collections::HashMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::Router;
use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, Response, StatusCode, Uri};
use sha2::{Digest as _, Sha256};
use tokio::net::TcpListener;

use tain::config::model::{
    AptOptions, BackendKind, BackendOptions, GcConfig, GlobalConfig, I18nSelection, IndexSelection,
    MirrorConfig, PgpMode, RetryConfig, VerifyConfig,
};
use tain::core::engine::apt_flow::{AptFlowError, ApttSyncOutcome, FetchTuning, sync_apt_suite};
use tain::core::engine::sync_mirror;
use tain::core::fetch::budget::{Budget, BudgetConfig};
use tain::core::fetch::client::{ClientConfig, build_client};
use tain::core::store::manifest::{self, GenerationManifest};
use tain::core::store::state;

mod common;
use common::{SyntheticRepo, TempDir};

const NEW_DATE: &str = "Sat, 03 Feb 2024 09:15:38 UTC";
const NEWER_DATE: &str = "Sun, 04 Feb 2024 09:15:38 UTC";
const OLD_DATE: &str = "Fri, 02 Feb 2024 09:15:38 UTC";
const OLDEST_DATE: &str = "Mon, 01 Jan 2024 00:00:00 UTC";

// ---------- fault-injecting upstream ----------

#[derive(Clone)]
enum Fault {
    Status(u16),
    Body(Vec<u8>),
    /// 200 with an infinite fast body.
    Endless,
    /// 200 headers, then silence.
    StallBody,
    /// Never answers.
    StallHeaders,
    /// File bytes plus a per-hit comment line (upstream refreshing forever).
    Nonce,
    /// `status` (with `Retry-After: 1`) for the first `times` hits, then the file.
    Flaky {
        status: u16,
        times: usize,
    },
    /// The file for the first `times` hits, then `body`.
    #[cfg_attr(not(feature = "pgp"), allow(dead_code))]
    After {
        times: usize,
        body: Vec<u8>,
    },
    /// 302 to this location.
    Redirect(String),
}

struct Upstream {
    root: PathBuf,
    faults: Mutex<HashMap<String, Fault>>,
    hits: AtomicUsize,
    requests: Mutex<Vec<String>>,
    last_modified_only: AtomicBool,
}

impl Upstream {
    fn fault(&self, path: &str, fault: Fault) {
        self.faults.lock().unwrap().insert(path.to_owned(), fault);
    }
    fn clear(&self, path: &str) {
        self.faults.lock().unwrap().remove(path);
    }
    fn requested(&self, path: &str) -> usize {
        self.requests
            .lock()
            .unwrap()
            .iter()
            .filter(|p| *p == path)
            .count()
    }
}

async fn spawn_upstream(root: PathBuf) -> (url::Url, Arc<Upstream>) {
    let up = Arc::new(Upstream {
        root,
        faults: Mutex::new(HashMap::new()),
        hits: AtomicUsize::new(0),
        requests: Mutex::new(Vec::new()),
        last_modified_only: AtomicBool::new(false),
    });
    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    let router: Router = Router::new().fallback(handler).with_state(up.clone());
    tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    (url::Url::parse(&format!("http://{addr}/")).unwrap(), up)
}

fn respond(status: StatusCode, body: Body) -> Response<Body> {
    Response::builder().status(status).body(body).unwrap()
}

async fn handler(State(up): State<Arc<Upstream>>, uri: Uri, headers: HeaderMap) -> Response<Body> {
    let path = uri.path().to_owned();
    let seen = {
        let mut log = up.requests.lock().unwrap();
        log.push(path.clone());
        log.iter().filter(|p| **p == path).count()
    };
    let fault = up.faults.lock().unwrap().get(&path).cloned();
    let disk = up.root.join(path.trim_start_matches('/'));
    match fault {
        Some(Fault::Status(code)) => respond(StatusCode::from_u16(code).unwrap(), Body::empty()),
        Some(Fault::Body(bytes)) => respond(StatusCode::OK, Body::from(bytes)),
        Some(Fault::Endless) => {
            let chunk = bytes::Bytes::from(vec![b'A'; 64 * 1024]);
            let stream = futures::stream::repeat_with(move || Ok::<_, Infallible>(chunk.clone()));
            respond(StatusCode::OK, Body::from_stream(stream))
        }
        Some(Fault::StallBody) => {
            let stream = futures::stream::pending::<Result<bytes::Bytes, Infallible>>();
            respond(StatusCode::OK, Body::from_stream(stream))
        }
        Some(Fault::StallHeaders) => {
            std::future::pending::<()>().await;
            unreachable!()
        }
        Some(Fault::Nonce) => {
            let hit = up.hits.fetch_add(1, Ordering::SeqCst);
            let mut bytes = std::fs::read(&disk).unwrap();
            bytes.extend_from_slice(format!("\n# nonce={hit}\n").as_bytes());
            respond(StatusCode::OK, Body::from(bytes))
        }
        Some(Fault::Flaky { status, times }) if seen <= times => Response::builder()
            .status(StatusCode::from_u16(status).unwrap())
            .header("retry-after", "1")
            .body(Body::empty())
            .unwrap(),
        Some(Fault::After { times, body }) if seen > times => {
            respond(StatusCode::OK, Body::from(body))
        }
        Some(Fault::Redirect(location)) => Response::builder()
            .status(StatusCode::FOUND)
            .header("location", location)
            .body(Body::empty())
            .unwrap(),
        Some(Fault::Flaky { .. } | Fault::After { .. }) | None => serve_file(
            &disk,
            up.last_modified_only.load(Ordering::SeqCst),
            &headers,
        ),
    }
}

/// Last-Modified-only mode: every file claims the same old mtime and any
/// conditional request is answered 304 — mtime(InRelease) ≤ mtime(Release).
fn serve_file(disk: &Path, last_modified_only: bool, headers: &HeaderMap) -> Response<Body> {
    let Ok(bytes) = std::fs::read(disk) else {
        return respond(StatusCode::NOT_FOUND, Body::empty());
    };
    if !last_modified_only {
        return respond(StatusCode::OK, Body::from(bytes));
    }
    if headers.contains_key("if-modified-since") {
        return respond(StatusCode::NOT_MODIFIED, Body::empty());
    }
    Response::builder()
        .status(StatusCode::OK)
        .header("last-modified", "Sat, 01 Jan 2000 00:00:00 GMT")
        .body(Body::from(bytes))
        .unwrap()
}

// ---------- config + helpers ----------

fn build_mirror(base: url::Url, suites: &[&str], verify: VerifyConfig) -> MirrorConfig {
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
        create_suite_symlinks: false,
    };
    MirrorConfig {
        name: "up".to_owned(),
        backend: BackendKind::Apt,
        url: base,
        path: PathBuf::from("up"),
        verify,
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

fn pgp_off() -> VerifyConfig {
    VerifyConfig::default()
}

/// Run one suite like the engine does (state prior, fresh manifest) but
/// return the flow's own error so tests can match its variant.
async fn sync_suite_direct(
    global: &GlobalConfig,
    mirror: &MirrorConfig,
    suite: &str,
) -> Result<ApttSyncOutcome, AptFlowError> {
    let mirror_root = global.target.join(&mirror.path);
    std::fs::create_dir_all(&mirror_root).unwrap();
    let prior = state::load(&mirror_root)
        .unwrap()
        .and_then(|s| s.suites.get(suite).cloned())
        .unwrap_or_default();
    let client = build_client(&ClientConfig::from(global)).unwrap();
    let budget = Budget::new(BudgetConfig::from(global));
    let mut manifest = GenerationManifest::new(1_000);
    let BackendOptions::Apt(apt) = &mirror.backend_options;
    sync_apt_suite(
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
    )
    .await
}

fn set_date(path: &Path, date: &str) {
    let text = std::fs::read_to_string(path).unwrap();
    let out: String = text
        .split_inclusive('\n')
        .map(|l| {
            if l.starts_with("Date: ") {
                format!("Date: {date}\n")
            } else {
                l.to_owned()
            }
        })
        .collect();
    std::fs::write(path, out).unwrap();
}

fn published_date(path: &Path) -> String {
    let text = std::fs::read_to_string(path).unwrap();
    text.lines()
        .find_map(|l| l.strip_prefix("Date: "))
        .unwrap()
        .to_owned()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn copy_tree(src: &Path, dst: &Path) {
    std::fs::create_dir_all(dst).unwrap();
    for entry in std::fs::read_dir(src).unwrap().flatten() {
        let to = dst.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &to);
        } else {
            std::fs::copy(entry.path(), to).unwrap();
        }
    }
}

fn signed_fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/pgp/signed-repo")
}

fn signed_upstream(serve: &Path) {
    copy_tree(&signed_fixture(), serve);
    std::fs::remove_file(serve.join("keyring.asc")).unwrap();
    std::fs::remove_dir_all(serve.join("next")).unwrap();
}

/// Upstream publishes the fixture's second signed generation.
#[cfg(feature = "pgp")]
fn publish_next_generation(serve: &Path) {
    for name in ["Release", "InRelease", "Release.gpg"] {
        std::fs::copy(
            signed_fixture().join("next").join(name),
            serve.join("dists/bookworm").join(name),
        )
        .unwrap();
    }
}

#[cfg(feature = "pgp")]
fn assert_clearsigned_inrelease(path: &Path) {
    let text = std::fs::read_to_string(path).unwrap();
    assert!(
        text.starts_with("-----BEGIN PGP SIGNED MESSAGE-----"),
        "published InRelease must be clearsigned"
    );
}

#[cfg(feature = "pgp")]
fn verify_with(mode: PgpMode) -> VerifyConfig {
    VerifyConfig {
        pgp: mode,
        keyring: Some(signed_fixture().join("keyring.asc")),
        allow_weak_hash: false,
    }
}

/// Synthetic `bookworm` repo with one package at `serve`.
fn synthetic(serve: &Path) {
    SyntheticRepo::new(serve.to_path_buf(), "bookworm")
        .add_package("nginx", b"nginx bytes".to_vec())
        .write();
}

// ---------- Release-only upstreams + Date floor ----------

#[tokio::test]
async fn release_only_upstream_second_run_is_unchanged() {
    let serve = TempDir::new("mi-relonly-serve");
    synthetic(serve.path());
    std::fs::remove_file(serve.path().join("dists/bookworm/InRelease")).unwrap();
    let (base, _up) = spawn_upstream(serve.path().to_path_buf()).await;
    let target = TempDir::new("mi-relonly-target");
    let global = build_global(target.path());
    let mirror = build_mirror(base, &["bookworm"], pgp_off());

    let first = sync_mirror(&global, &mirror, &global.target).await.unwrap();
    assert_eq!(first.suites_succeeded, vec!["bookworm".to_owned()]);
    let second = sync_mirror(&global, &mirror, &global.target).await.unwrap();
    assert_eq!(
        second.suites_unchanged,
        vec!["bookworm".to_owned()],
        "Release-only upstream must hit the Unchanged path: {second:?}"
    );
    assert_eq!(second.new_generation, first.new_generation);
}

#[tokio::test]
async fn release_only_older_date_is_rejected() {
    let serve = TempDir::new("mi-relonly-date-serve");
    synthetic(serve.path());
    let release = serve.path().join("dists/bookworm/Release");
    std::fs::remove_file(serve.path().join("dists/bookworm/InRelease")).unwrap();
    let (base, _up) = spawn_upstream(serve.path().to_path_buf()).await;
    let target = TempDir::new("mi-relonly-date-target");
    let global = build_global(target.path());
    let mirror = build_mirror(base, &["bookworm"], pgp_off());

    let first = sync_mirror(&global, &mirror, &global.target).await.unwrap();
    assert!(first.is_success());

    set_date(&release, OLD_DATE);
    let err = sync_suite_direct(&global, &mirror, "bookworm")
        .await
        .expect_err("older Date must be refused");
    assert!(matches!(err, AptFlowError::DateRegressed { .. }), "{err:?}");
    let published = target.path().join("up/dists/bookworm/Release");
    assert_eq!(published_date(&published), NEW_DATE);
}

#[tokio::test]
async fn older_date_after_state_loss_is_rejected() {
    let serve = TempDir::new("mi-stateloss-serve");
    synthetic(serve.path());
    let (base, _up) = spawn_upstream(serve.path().to_path_buf()).await;
    let target = TempDir::new("mi-stateloss-target");
    let global = build_global(target.path());
    let mirror = build_mirror(base, &["bookworm"], pgp_off());
    assert!(
        sync_mirror(&global, &mirror, &global.target)
            .await
            .unwrap()
            .is_success()
    );

    // Crash right after the swap of a first-ever publish: no state at all.
    std::fs::remove_file(state::state_path(&target.path().join("up"))).unwrap();
    for name in ["InRelease", "Release"] {
        set_date(&serve.path().join("dists/bookworm").join(name), OLD_DATE);
    }
    let err = sync_suite_direct(&global, &mirror, "bookworm")
        .await
        .expect_err("published Date is the floor even without state");
    assert!(matches!(err, AptFlowError::DateRegressed { .. }), "{err:?}");

    let outcome = sync_mirror(&global, &mirror, &global.target).await.unwrap();
    assert_eq!(outcome.suites_failed, vec!["bookworm".to_owned()]);
    let published = target.path().join("up/dists/bookworm/InRelease");
    assert_eq!(published_date(&published), NEW_DATE);
}

#[tokio::test]
async fn stale_state_after_crash_keeps_disk_date_floor() {
    let serve = TempDir::new("mi-stalestate-serve");
    synthetic(serve.path());
    let dists = serve.path().join("dists/bookworm");
    for name in ["InRelease", "Release"] {
        set_date(&dists.join(name), OLDEST_DATE);
    }
    let (base, _up) = spawn_upstream(serve.path().to_path_buf()).await;
    let target = TempDir::new("mi-stalestate-target");
    let mirror_root = target.path().join("up");
    let global = build_global(target.path());
    let mirror = build_mirror(base, &["bookworm"], pgp_off());
    assert!(
        sync_mirror(&global, &mirror, &global.target)
            .await
            .unwrap()
            .is_success()
    );
    let stale_state = std::fs::read(state::state_path(&mirror_root)).unwrap();

    for name in ["InRelease", "Release"] {
        set_date(&dists.join(name), NEWER_DATE);
    }
    assert!(
        sync_mirror(&global, &mirror, &global.target)
            .await
            .unwrap()
            .is_success()
    );
    // Crash between swap and state save: disk is ahead of state.
    std::fs::write(state::state_path(&mirror_root), stale_state).unwrap();

    for name in ["InRelease", "Release"] {
        set_date(&dists.join(name), OLD_DATE);
    }
    let err = sync_suite_direct(&global, &mirror, "bookworm")
        .await
        .expect_err("Date between state and disk must be refused");
    assert!(matches!(err, AptFlowError::DateRegressed { .. }), "{err:?}");
    assert_eq!(
        published_date(&mirror_root.join("dists/bookworm/InRelease")),
        NEWER_DATE
    );
}

// ---------- sibling root files ----------

#[tokio::test]
async fn stale_sibling_release_is_not_published() {
    let serve = TempDir::new("mi-stalesib-serve");
    synthetic(serve.path());
    set_date(&serve.path().join("dists/bookworm/Release"), OLD_DATE);
    let (base, _up) = spawn_upstream(serve.path().to_path_buf()).await;
    let target = TempDir::new("mi-stalesib-target");
    let global = build_global(target.path());
    let mirror = build_mirror(base, &["bookworm"], pgp_off());

    let outcome = sync_mirror(&global, &mirror, &global.target).await.unwrap();
    assert!(outcome.is_success(), "{outcome:?}");
    let dist = target.path().join("up/dists/bookworm");
    assert!(dist.join("InRelease").exists());
    assert!(
        !dist.join("Release").exists(),
        "a Release that differs from the InRelease body must not be published"
    );
}

#[tokio::test]
async fn matching_sibling_release_is_published() {
    let serve = TempDir::new("mi-goodsib-serve");
    synthetic(serve.path());
    let (base, _up) = spawn_upstream(serve.path().to_path_buf()).await;
    let target = TempDir::new("mi-goodsib-target");
    let global = build_global(target.path());
    let mirror = build_mirror(base, &["bookworm"], pgp_off());
    assert!(
        sync_mirror(&global, &mirror, &global.target)
            .await
            .unwrap()
            .is_success()
    );
    let dist = target.path().join("up/dists/bookworm");
    assert_eq!(
        std::fs::read(dist.join("Release")).unwrap(),
        std::fs::read(serve.path().join("dists/bookworm/Release")).unwrap()
    );
}

#[cfg(feature = "pgp")]
#[tokio::test]
async fn genuine_signed_siblings_are_published_under_required() {
    let serve = TempDir::new("mi-signed-serve");
    signed_upstream(serve.path());
    let (base, _up) = spawn_upstream(serve.path().to_path_buf()).await;
    let target = TempDir::new("mi-signed-target");
    let global = build_global(target.path());
    let mirror = build_mirror(base, &["bookworm"], verify_with(PgpMode::Required));

    let outcome = sync_mirror(&global, &mirror, &global.target).await.unwrap();
    assert!(outcome.is_success(), "{outcome:?}");
    let dist = target.path().join("up/dists/bookworm");
    for name in ["InRelease", "Release", "Release.gpg"] {
        assert_eq!(
            std::fs::read(dist.join(name)).unwrap(),
            std::fs::read(serve.path().join("dists/bookworm").join(name)).unwrap(),
            "{name} must be published verbatim"
        );
    }
}

#[cfg(feature = "pgp")]
#[tokio::test]
async fn mitm_sibling_garbage_is_not_published_under_required() {
    let serve = TempDir::new("mi-mitm-serve");
    signed_upstream(serve.path());
    let (base, up) = spawn_upstream(serve.path().to_path_buf()).await;
    up.fault(
        "/dists/bookworm/Release",
        Fault::Body(b"Suite: evil\nDate: Sun, 01 Jan 2034 00:00:00 UTC\n".to_vec()),
    );
    up.fault(
        "/dists/bookworm/Release.gpg",
        Fault::Body(b"not a signature".to_vec()),
    );
    let target = TempDir::new("mi-mitm-target");
    let global = build_global(target.path());
    let mirror = build_mirror(base, &["bookworm"], verify_with(PgpMode::Required));

    let outcome = sync_mirror(&global, &mirror, &global.target).await.unwrap();
    assert!(outcome.is_success(), "{outcome:?}");
    let dist = target.path().join("up/dists/bookworm");
    assert!(dist.join("InRelease").exists());
    assert!(!dist.join("Release").exists(), "garbage Release published");
    assert!(
        !dist.join("Release.gpg").exists(),
        "garbage Release.gpg published"
    );
}

#[cfg(feature = "pgp")]
#[tokio::test]
async fn release_gpg_that_does_not_verify_is_dropped() {
    let serve = TempDir::new("mi-badgpg-serve");
    signed_upstream(serve.path());
    let (base, up) = spawn_upstream(serve.path().to_path_buf()).await;
    let foreign = std::fs::read(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/pgp/expired/Release.gpg"),
    )
    .unwrap();
    up.fault("/dists/bookworm/Release.gpg", Fault::Body(foreign));
    let target = TempDir::new("mi-badgpg-target");
    let global = build_global(target.path());
    let mirror = build_mirror(base, &["bookworm"], verify_with(PgpMode::Required));

    let outcome = sync_mirror(&global, &mirror, &global.target).await.unwrap();
    assert!(outcome.is_success(), "{outcome:?}");
    let dist = target.path().join("up/dists/bookworm");
    assert!(dist.join("Release").exists());
    assert!(!dist.join("Release.gpg").exists());
}

#[cfg(feature = "pgp")]
#[tokio::test]
async fn release_mode_publishes_the_verified_signature() {
    let serve = TempDir::new("mi-relmode-serve");
    signed_upstream(serve.path());
    std::fs::remove_file(serve.path().join("dists/bookworm/InRelease")).unwrap();
    let (base, _up) = spawn_upstream(serve.path().to_path_buf()).await;
    let target = TempDir::new("mi-relmode-target");
    let global = build_global(target.path());
    let mirror = build_mirror(base, &["bookworm"], verify_with(PgpMode::Required));

    let outcome = sync_mirror(&global, &mirror, &global.target).await.unwrap();
    assert!(outcome.is_success(), "{outcome:?}");
    let dist = target.path().join("up/dists/bookworm");
    assert!(dist.join("Release").exists());
    assert!(dist.join("Release.gpg").exists());
    assert!(!dist.join("InRelease").exists());
}

// ---------- refold rollback scope ----------

#[tokio::test]
async fn refold_rollback_keeps_other_suites_shared_key() {
    let serve = TempDir::new("mi-shared-serve");
    for suite in ["bookworm", "trixie"] {
        SyntheticRepo::new(serve.path().to_path_buf(), suite)
            .add_package("nginx", b"shared nginx".to_vec())
            .write();
    }
    let (base, up) = spawn_upstream(serve.path().to_path_buf()).await;
    up.fault("/dists/trixie/InRelease", Fault::Nonce);
    let target = TempDir::new("mi-shared-target");
    let global = build_global(target.path());
    let mirror = build_mirror(base, &["bookworm", "trixie"], pgp_off());

    let outcome = sync_mirror(&global, &mirror, &global.target).await.unwrap();
    assert_eq!(outcome.suites_succeeded, vec!["bookworm".to_owned()]);
    assert_eq!(outcome.suites_failed, vec!["trixie".to_owned()]);
    let m = manifest::load(&target.path().join("up"), outcome.new_generation).unwrap();
    assert!(
        m.files
            .contains_key("pool/main/n/nginx/nginx_1.0_amd64.deb"),
        "trixie's rollback removed bookworm's pool entry: {:?}",
        m.files.keys().collect::<Vec<_>>()
    );
}

// ---------- 4xx on optional root files ----------

#[tokio::test]
async fn inrelease_403_falls_back_to_release() {
    let serve = TempDir::new("mi-403-serve");
    synthetic(serve.path());
    let (base, up) = spawn_upstream(serve.path().to_path_buf()).await;
    up.fault("/dists/bookworm/InRelease", Fault::Status(403));
    up.fault("/dists/bookworm/Release.gpg", Fault::Status(403));
    let target = TempDir::new("mi-403-target");
    let global = build_global(target.path());
    let mirror = build_mirror(base, &["bookworm"], pgp_off());

    let outcome = sync_mirror(&global, &mirror, &global.target).await.unwrap();
    assert!(outcome.is_success(), "{outcome:?}");
    assert!(target.path().join("up/dists/bookworm/Release").exists());
}

#[tokio::test]
async fn sibling_403_is_treated_as_absent() {
    let serve = TempDir::new("mi-sib403-serve");
    synthetic(serve.path());
    let (base, up) = spawn_upstream(serve.path().to_path_buf()).await;
    up.fault("/dists/bookworm/Release", Fault::Status(403));
    up.fault("/dists/bookworm/Release.gpg", Fault::Status(403));
    let target = TempDir::new("mi-sib403-target");
    let global = build_global(target.path());
    let mirror = build_mirror(base, &["bookworm"], pgp_off());

    let outcome = sync_mirror(&global, &mirror, &global.target).await.unwrap();
    assert!(outcome.is_success(), "{outcome:?}");
    assert!(target.path().join("up/dists/bookworm/InRelease").exists());
}

#[tokio::test]
async fn inrelease_5xx_fails_the_suite_instead_of_downgrading() {
    let serve = TempDir::new("mi-500-serve");
    synthetic(serve.path());
    let (base, up) = spawn_upstream(serve.path().to_path_buf()).await;
    up.fault("/dists/bookworm/InRelease", Fault::Status(500));
    let target = TempDir::new("mi-500-target");
    let global = build_global(target.path());
    let mirror = build_mirror(base, &["bookworm"], pgp_off());

    let outcome = sync_mirror(&global, &mirror, &global.target).await.unwrap();
    assert_eq!(outcome.suites_failed, vec!["bookworm".to_owned()]);
    assert_eq!(
        up.requested("/dists/bookworm/Release"),
        0,
        "a 5xx InRelease must not fall back to Release"
    );
}

// ---------- M-c: transient failures on root files ----------

fn retrying_global(target: &Path) -> GlobalConfig {
    let mut g = build_global(target);
    g.retry.count = 2;
    g
}

#[tokio::test]
async fn transient_inrelease_and_recheck_failures_are_retried() {
    let serve = TempDir::new("mi-flaky-serve");
    synthetic(serve.path());
    let (base, up) = spawn_upstream(serve.path().to_path_buf()).await;
    // Hit 1 (probe) and hit 3 (recheck) fail once each.
    up.fault(
        "/dists/bookworm/InRelease",
        Fault::Flaky {
            status: 503,
            times: 1,
        },
    );
    let target = TempDir::new("mi-flaky-target");
    let global = retrying_global(target.path());
    let mirror = build_mirror(base, &["bookworm"], pgp_off());

    let outcome = sync_mirror(&global, &mirror, &global.target).await.unwrap();
    assert!(outcome.is_success(), "{outcome:?}");
    assert!(up.requested("/dists/bookworm/InRelease") >= 3);
}

#[tokio::test]
async fn persistent_429_is_bounded_by_retry_count() {
    let serve = TempDir::new("mi-429-serve");
    synthetic(serve.path());
    let (base, up) = spawn_upstream(serve.path().to_path_buf()).await;
    up.fault(
        "/dists/bookworm/InRelease",
        Fault::Flaky {
            status: 429,
            times: 100,
        },
    );
    let target = TempDir::new("mi-429-target");
    let global = retrying_global(target.path());
    let mirror = build_mirror(base, &["bookworm"], pgp_off());

    let outcome = sync_mirror(&global, &mirror, &global.target).await.unwrap();
    assert_eq!(outcome.suites_failed, vec!["bookworm".to_owned()]);
    assert_eq!(up.requested("/dists/bookworm/InRelease"), 3);
    assert_eq!(
        up.requested("/dists/bookworm/Release"),
        0,
        "429 is not absence"
    );
}

#[tokio::test]
async fn failing_optional_sibling_is_dropped_not_fatal() {
    let serve = TempDir::new("mi-sib5xx-serve");
    synthetic(serve.path());
    let (base, up) = spawn_upstream(serve.path().to_path_buf()).await;
    up.fault("/dists/bookworm/Release", Fault::Status(502));
    let target = TempDir::new("mi-sib5xx-target");
    let global = build_global(target.path());
    let mirror = build_mirror(base, &["bookworm"], pgp_off());

    let outcome = sync_mirror(&global, &mirror, &global.target).await.unwrap();
    assert!(outcome.is_success(), "{outcome:?}");
    let dist = target.path().join("up/dists/bookworm");
    assert!(dist.join("InRelease").exists());
    assert!(!dist.join("Release").exists());
}

// ---------- M-b: Date floor must not fail open ----------

fn strip_date(path: &Path) {
    let text = std::fs::read_to_string(path).unwrap();
    let out: String = text
        .split_inclusive('\n')
        .filter(|l| !l.starts_with("Date: "))
        .collect();
    std::fs::write(path, out).unwrap();
}

#[tokio::test]
async fn release_without_date_is_refused_once_a_floor_exists() {
    let serve = TempDir::new("mi-nodate-serve");
    synthetic(serve.path());
    let (base, _up) = spawn_upstream(serve.path().to_path_buf()).await;
    let target = TempDir::new("mi-nodate-target");
    let global = build_global(target.path());
    let mirror = build_mirror(base, &["bookworm"], pgp_off());
    assert!(
        sync_mirror(&global, &mirror, &global.target)
            .await
            .unwrap()
            .is_success()
    );

    for name in ["InRelease", "Release"] {
        strip_date(&serve.path().join("dists/bookworm").join(name));
    }
    let err = sync_suite_direct(&global, &mirror, "bookworm")
        .await
        .expect_err("a Date-less Release must not erase the floor");
    assert!(matches!(err, AptFlowError::DateMissing { .. }), "{err:?}");
}

#[tokio::test]
async fn unparseable_state_date_fails_closed() {
    let serve = TempDir::new("mi-baddate-serve");
    synthetic(serve.path());
    let (base, _up) = spawn_upstream(serve.path().to_path_buf()).await;
    let target = TempDir::new("mi-baddate-target");
    let mirror_root = target.path().join("up");
    let global = build_global(target.path());
    let mirror = build_mirror(base, &["bookworm"], pgp_off());
    assert!(
        sync_mirror(&global, &mirror, &global.target)
            .await
            .unwrap()
            .is_success()
    );
    let mut st = state::load(&mirror_root).unwrap().unwrap();
    st.suites.get_mut("bookworm").unwrap().date_raw = Some("not a date".to_owned());
    state::save(&mirror_root, &st).unwrap();

    for name in ["InRelease", "Release"] {
        set_date(&serve.path().join("dists/bookworm").join(name), NEWER_DATE);
    }
    let err = sync_suite_direct(&global, &mirror, "bookworm")
        .await
        .expect_err("an unreadable floor must not be skipped");
    assert!(matches!(err, AptFlowError::BadDate { .. }), "{err:?}");
}

#[tokio::test]
async fn unverified_future_sibling_does_not_freeze_the_suite() {
    let serve = TempDir::new("mi-future-serve");
    synthetic(serve.path());
    let (base, _up) = spawn_upstream(serve.path().to_path_buf()).await;
    let target = TempDir::new("mi-future-target");
    let global = build_global(target.path());
    let mirror = build_mirror(base, &["bookworm"], pgp_off());
    assert!(
        sync_mirror(&global, &mirror, &global.target)
            .await
            .unwrap()
            .is_success()
    );

    // A v0.1.0-era unvetted sibling with a far-future Date.
    let published_release = target.path().join("up/dists/bookworm/Release");
    set_date(&published_release, "Fri, 01 Jan 2100 00:00:00 UTC");
    for name in ["InRelease", "Release"] {
        set_date(&serve.path().join("dists/bookworm").join(name), NEWER_DATE);
    }
    let outcome = sync_mirror(&global, &mirror, &global.target).await.unwrap();
    assert_eq!(
        outcome.suites_succeeded,
        vec!["bookworm".to_owned()],
        "{outcome:?}"
    );
}

// ---------- weak-digest-only pool entries ----------

/// Plain repo whose Packages carries one strong and one MD5-only entry.
fn weak_repo(serve: &Path) {
    let strong = b"strong deb".to_vec();
    let weak = b"weak deb".to_vec();
    let dists = serve.join("dists/bookworm");
    std::fs::create_dir_all(dists.join("main/binary-amd64")).unwrap();
    for (name, bytes) in [("strong", &strong), ("weak", &weak)] {
        let p = serve.join(format!("pool/main/{0}/{0}.deb", name));
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, bytes).unwrap();
    }
    let md5 = {
        use md5::Digest as _;
        hex(&md5::Md5::digest(&weak))
    };
    let packages = format!(
        "Package: strong\nFilename: pool/main/strong/strong.deb\nSize: {}\nSHA256: {}\n\n\
         Package: weak\nFilename: pool/main/weak/weak.deb\nSize: {}\nMD5sum: {md5}\n\n",
        strong.len(),
        hex(&Sha256::digest(&strong)),
        weak.len(),
    );
    std::fs::write(dists.join("main/binary-amd64/Packages"), &packages).unwrap();
    let release = format!(
        "Suite: bookworm\nCodename: bookworm\nArchitectures: amd64\nComponents: main\n\
         Date: {NEW_DATE}\nSHA256:\n {} {} main/binary-amd64/Packages\n",
        hex(&Sha256::digest(packages.as_bytes())),
        packages.len(),
    );
    std::fs::write(dists.join("Release"), &release).unwrap();
    std::fs::write(dists.join("InRelease"), &release).unwrap();
}

#[tokio::test]
async fn weak_only_entry_fails_suite_by_default() {
    let serve = TempDir::new("mi-weak-serve");
    weak_repo(serve.path());
    let (base, _up) = spawn_upstream(serve.path().to_path_buf()).await;
    let target = TempDir::new("mi-weak-target");
    let global = build_global(target.path());
    let mirror = build_mirror(base, &["bookworm"], pgp_off());

    let err = sync_suite_direct(&global, &mirror, "bookworm")
        .await
        .expect_err("weak-only entry must fail the suite");
    let msg = err.to_string();
    assert!(
        matches!(err, AptFlowError::WeakDigestOnlyEntries { count: 1, .. }),
        "{err:?}"
    );
    assert!(msg.contains("weak"), "names the package: {msg}");
    assert!(msg.contains("allow_weak_hash"), "points at the knob: {msg}");
    assert!(!target.path().join("up/dists/bookworm").exists());
}

#[tokio::test]
async fn weak_only_entry_is_mirrored_when_allowed() {
    let serve = TempDir::new("mi-weakok-serve");
    weak_repo(serve.path());
    let (base, _up) = spawn_upstream(serve.path().to_path_buf()).await;
    let target = TempDir::new("mi-weakok-target");
    let global = build_global(target.path());
    let verify = VerifyConfig {
        allow_weak_hash: true,
        ..VerifyConfig::default()
    };
    let mirror = build_mirror(base, &["bookworm"], verify);

    let outcome = sync_mirror(&global, &mirror, &global.target).await.unwrap();
    assert!(outcome.is_success(), "{outcome:?}");
    assert!(target.path().join("up/pool/main/weak/weak.deb").exists());
}

// ---------- if-present downgrade memory ----------

#[cfg(feature = "pgp")]
#[tokio::test]
async fn if_present_signature_strip_is_refused() {
    let serve = TempDir::new("mi-strip-serve");
    signed_upstream(serve.path());
    let (base, _up) = spawn_upstream(serve.path().to_path_buf()).await;
    let target = TempDir::new("mi-strip-target");
    let global = build_global(target.path());
    let mirror = build_mirror(base, &["bookworm"], verify_with(PgpMode::IfPresent));
    let first = sync_mirror(&global, &mirror, &global.target).await.unwrap();
    assert!(first.is_success(), "{first:?}");

    // On-path attacker: unsigned, newer InRelease; Release.gpg gone.
    let dists = serve.path().join("dists/bookworm");
    set_date(&dists.join("Release"), NEWER_DATE);
    std::fs::copy(dists.join("Release"), dists.join("InRelease")).unwrap();
    std::fs::remove_file(dists.join("Release.gpg")).unwrap();

    let err = sync_suite_direct(&global, &mirror, "bookworm")
        .await
        .expect_err("Verified → Absent must be refused");
    assert!(matches!(err, AptFlowError::PgpDowngrade { .. }), "{err:?}");
    let published = target.path().join("up/dists/bookworm/InRelease");
    assert_eq!(published_date(&published), NEW_DATE);
}

/// Release-only upstream, verified and published; an on-path attacker then
/// answers the (previously 404) InRelease URL with an unsigned body.
#[cfg(feature = "pgp")]
#[tokio::test]
async fn if_present_unsigned_inrelease_over_detached_tree_is_refused() {
    let serve = TempDir::new("mi-strip2-serve");
    signed_upstream(serve.path());
    let dists = serve.path().join("dists/bookworm");
    std::fs::remove_file(dists.join("InRelease")).unwrap();
    let (base, up) = spawn_upstream(serve.path().to_path_buf()).await;
    let target = TempDir::new("mi-strip2-target");
    let global = build_global(target.path());
    let mirror = build_mirror(base, &["bookworm"], verify_with(PgpMode::IfPresent));
    let first = sync_mirror(&global, &mirror, &global.target).await.unwrap();
    assert!(first.is_success(), "{first:?}");
    assert!(target.path().join("up/dists/bookworm/Release.gpg").exists());

    let release = std::fs::read_to_string(dists.join("Release")).unwrap();
    let forged = release.replace(NEW_DATE, NEWER_DATE);
    // An unsigned InRelease alone is unusable under PGP: ignored.
    up.fault(
        "/dists/bookworm/InRelease",
        Fault::Body(forged.clone().into_bytes()),
    );
    let ignored = sync_suite_direct(&global, &mirror, "bookworm").await;
    assert!(
        matches!(ignored, Ok(ApttSyncOutcome::Unchanged)),
        "{ignored:?}"
    );

    // Forged Release with the detached signature withheld: a downgrade.
    up.fault("/dists/bookworm/Release", Fault::Body(forged.into_bytes()));
    up.fault("/dists/bookworm/Release.gpg", Fault::Status(404));
    let err = sync_suite_direct(&global, &mirror, "bookworm")
        .await
        .expect_err("unsigned Release over a signed tree must be refused");
    assert!(matches!(err, AptFlowError::PgpDowngrade { .. }), "{err:?}");
    assert_eq!(
        published_date(&target.path().join("up/dists/bookworm/Release")),
        NEW_DATE
    );
}

/// Unsigned InRelease next to a verifying Release + Release.gpg: the round
/// drives the round as Release + Release.gpg, like apt does — the unsigned
/// InRelease is never published (apt rejects it without falling back).
#[cfg(feature = "pgp")]
#[tokio::test]
async fn if_present_plain_inrelease_with_verified_detached_signature_is_verified() {
    let serve = TempDir::new("mi-plainin-serve");
    signed_upstream(serve.path());
    let dists = serve.path().join("dists/bookworm");
    std::fs::copy(dists.join("Release"), dists.join("InRelease")).unwrap();
    let (base, _up) = spawn_upstream(serve.path().to_path_buf()).await;
    let target = TempDir::new("mi-plainin-target");
    let global = build_global(target.path());
    let mirror = build_mirror(base, &["bookworm"], verify_with(PgpMode::IfPresent));

    let outcome = sync_mirror(&global, &mirror, &global.target).await.unwrap();
    assert!(outcome.is_success(), "{outcome:?}");
    assert_eq!(
        outcome.pgp_by_suite,
        vec![(
            "bookworm".to_owned(),
            tain::backends::apt::pgp::VerifyOutcome::Verified
        )]
    );
    let dist = target.path().join("up/dists/bookworm");
    assert!(dist.join("Release").exists());
    assert!(dist.join("Release.gpg").exists());
    assert!(
        !dist.join("InRelease").exists(),
        "an unsigned InRelease must not be published under PGP"
    );
}

/// The "not clearsigned" warning fires on the run that publishes, not on
/// every later Unchanged run (which re-fetches the same InRelease).
#[cfg(feature = "pgp")]
#[tokio::test(flavor = "multi_thread")]
async fn unsigned_inrelease_warning_only_on_publishing_run() {
    let serve = TempDir::new("mi-warnonce-serve");
    signed_upstream(serve.path());
    let dists = serve.path().join("dists/bookworm");
    std::fs::copy(dists.join("Release"), dists.join("InRelease")).unwrap();
    let (base, _up) = spawn_upstream(serve.path().to_path_buf()).await;
    let target = TempDir::new("mi-warnonce-target");
    let config = target.path().join("tain.toml");
    std::fs::write(
        &config,
        format!(
            "[global]\ntarget = \"{target}\"\n\n[[mirror]]\nname = \"up\"\nurl = \"{base}\"\n\
             suites = [\"bookworm\"]\ncomponents = [\"main\"]\narchitectures = [\"amd64\"]\n\n\
             [mirror.indexes]\ncontents = false\ni18n = false\ndep11 = false\ncnf = false\n\n\
             [mirror.verify]\npgp = \"required\"\nkeyring = \"{keyring}\"\n",
            target = target.path().join("t").display(),
            keyring = signed_fixture().join("keyring.asc").display(),
        ),
    )
    .unwrap();
    let run = || {
        let config = config.clone();
        tokio::task::spawn_blocking(move || {
            std::process::Command::new(env!("CARGO_BIN_EXE_tain"))
                .env_clear()
                .arg("--config")
                .arg(&config)
                .arg("sync")
                .output()
                .unwrap()
        })
    };
    let warned = |out: &std::process::Output| {
        String::from_utf8_lossy(&out.stderr).contains("not clearsigned")
    };

    let first = run().await.unwrap();
    assert_eq!(first.status.code(), Some(0), "{first:?}");
    assert!(warned(&first), "publishing run must warn: {first:?}");
    let second = run().await.unwrap();
    assert_eq!(second.status.code(), Some(0), "{second:?}");
    let stderr = String::from_utf8_lossy(&second.stderr);
    assert!(stderr.contains("suite unchanged"), "{stderr}");
    assert!(!warned(&second), "unchanged run must not warn: {stderr}");
}

/// A MITM strips the signature from upstream's next InRelease. Nothing
/// unsigned may be published, and once the MITM leaves the next run must
/// restore the clearsigned InRelease.
#[cfg(feature = "pgp")]
#[tokio::test]
async fn stripped_inrelease_signature_never_publishes_unsigned_inrelease() {
    for mode in [PgpMode::IfPresent, PgpMode::Required] {
        let serve = TempDir::new("mi-mitmstrip-serve");
        signed_upstream(serve.path());
        let (base, up) = spawn_upstream(serve.path().to_path_buf()).await;
        let target = TempDir::new("mi-mitmstrip-target");
        let global = build_global(target.path());
        let mirror = build_mirror(base, &["bookworm"], verify_with(mode));
        let dist = target.path().join("up/dists/bookworm");
        let first = sync_mirror(&global, &mirror, &global.target).await.unwrap();
        assert!(first.is_success(), "{mode:?}: {first:?}");

        publish_next_generation(serve.path());
        let next_release = std::fs::read(serve.path().join("dists/bookworm/Release")).unwrap();
        up.fault("/dists/bookworm/InRelease", Fault::Body(next_release));
        let second = sync_mirror(&global, &mirror, &global.target).await.unwrap();
        assert!(second.is_success(), "{mode:?}: {second:?}");
        if dist.join("InRelease").exists() {
            assert_clearsigned_inrelease(&dist.join("InRelease"));
        }
        assert_eq!(published_date(&dist.join("Release")), NEWER_DATE);

        up.clear("/dists/bookworm/InRelease");
        let third = sync_mirror(&global, &mirror, &global.target).await.unwrap();
        assert!(third.is_success(), "{mode:?}: {third:?}");
        assert_eq!(
            std::fs::read(dist.join("InRelease")).unwrap(),
            std::fs::read(serve.path().join("dists/bookworm/InRelease")).unwrap(),
            "{mode:?}: the signed InRelease must come back once the MITM is gone"
        );
    }
}

/// A tree already broken by an earlier release (unsigned InRelease next to
/// Release.gpg) is drift: the next run repairs it although upstream is
/// unchanged.
#[cfg(feature = "pgp")]
#[tokio::test]
async fn published_unsigned_inrelease_is_repaired() {
    let serve = TempDir::new("mi-heal-serve");
    signed_upstream(serve.path());
    let (base, _up) = spawn_upstream(serve.path().to_path_buf()).await;
    let target = TempDir::new("mi-heal-target");
    let global = build_global(target.path());
    let mirror = build_mirror(base, &["bookworm"], verify_with(PgpMode::IfPresent));
    assert!(
        sync_mirror(&global, &mirror, &global.target)
            .await
            .unwrap()
            .is_success()
    );
    let dist = target.path().join("up/dists/bookworm");
    std::fs::copy(dist.join("Release"), dist.join("InRelease")).unwrap();

    let second = sync_mirror(&global, &mirror, &global.target).await.unwrap();
    assert_eq!(
        second.suites_succeeded,
        vec!["bookworm".to_owned()],
        "{second:?}"
    );
    assert_clearsigned_inrelease(&dist.join("InRelease"));
}

/// The real InRelease on the probe, a stripped one at recheck time: the
/// refold round must not publish it (first sync, nothing signed yet).
#[cfg(feature = "pgp")]
#[tokio::test]
async fn unsigned_inrelease_at_recheck_is_never_published() {
    let serve = TempDir::new("mi-recheckstrip-serve");
    signed_upstream(serve.path());
    let (base, up) = spawn_upstream(serve.path().to_path_buf()).await;
    let next_release = std::fs::read(signed_fixture().join("next/Release")).unwrap();
    up.fault(
        "/dists/bookworm/InRelease",
        Fault::After {
            times: 1,
            body: next_release,
        },
    );
    let target = TempDir::new("mi-recheckstrip-target");
    let global = build_global(target.path());
    let mirror = build_mirror(base, &["bookworm"], verify_with(PgpMode::IfPresent));

    let err = sync_suite_direct(&global, &mirror, "bookworm")
        .await
        .expect_err("a stripped InRelease must never drive a round under PGP");
    assert!(
        matches!(err, AptFlowError::UnsignedInRelease { .. }),
        "{err:?}"
    );
    assert!(!target.path().join("up/dists/bookworm").exists());
}

/// Validators from a Release-driven round must not be sent to InRelease:
/// a Last-Modified-only server would answer 304 for the wrong file and
/// force a fresh generation on every run.
#[cfg(feature = "pgp")]
#[tokio::test]
async fn release_driven_validators_do_not_cause_perpetual_resync() {
    let serve = TempDir::new("mi-lm-serve");
    signed_upstream(serve.path());
    let dists = serve.path().join("dists/bookworm");
    std::fs::copy(dists.join("Release"), dists.join("InRelease")).unwrap();
    let (base, up) = spawn_upstream(serve.path().to_path_buf()).await;
    up.last_modified_only.store(true, Ordering::SeqCst);
    let target = TempDir::new("mi-lm-target");
    let global = build_global(target.path());
    let mirror = build_mirror(base, &["bookworm"], verify_with(PgpMode::IfPresent));

    let first = sync_mirror(&global, &mirror, &global.target).await.unwrap();
    assert_eq!(first.suites_succeeded, vec!["bookworm".to_owned()]);
    for run in 2..=3 {
        let o = sync_mirror(&global, &mirror, &global.target).await.unwrap();
        assert_eq!(
            o.suites_unchanged,
            vec!["bookworm".to_owned()],
            "run {run}: {o:?}"
        );
        assert_eq!(o.new_generation, first.new_generation, "run {run}");
    }
}

#[tokio::test]
async fn if_present_unsigned_upstream_still_syncs() {
    let serve = TempDir::new("mi-unsigned-serve");
    synthetic(serve.path());
    let (base, _up) = spawn_upstream(serve.path().to_path_buf()).await;
    let target = TempDir::new("mi-unsigned-target");
    let global = build_global(target.path());
    let verify = VerifyConfig {
        pgp: PgpMode::IfPresent,
        keyring: Some(signed_fixture().join("keyring.asc")),
        allow_weak_hash: false,
    };
    let mirror = build_mirror(base, &["bookworm"], verify);
    for _ in 0..2 {
        let o = sync_mirror(&global, &mirror, &global.target).await.unwrap();
        assert!(o.is_success(), "{o:?}");
    }
}

// ---------- canonical change token ----------

#[tokio::test]
async fn trailing_whitespace_inrelease_variant_is_unchanged() {
    let serve = TempDir::new("mi-ws-serve");
    signed_upstream(serve.path());
    let (base, up) = spawn_upstream(serve.path().to_path_buf()).await;
    let target = TempDir::new("mi-ws-target");
    let global = build_global(target.path());
    let mirror = build_mirror(base, &["bookworm"], pgp_off());
    let first = sync_mirror(&global, &mirror, &global.target).await.unwrap();
    assert!(first.is_success(), "{first:?}");

    // Whitespace a clearsign signature ignores: body line ends, an armor
    // header, and blank lines after the frame.
    let original = std::fs::read_to_string(serve.path().join("dists/bookworm/InRelease")).unwrap();
    let (head, rest) = original.split_once("\n\n").unwrap();
    let (body, sig) = rest.split_once("-----BEGIN PGP SIGNATURE-----").unwrap();
    let padded_body: String = body
        .split_inclusive('\n')
        .map(|l| format!("{}  \t\n", l.trim_end_matches('\n')))
        .collect();
    let sig = sig.replacen("\n\n", "\nComment: injected\n\n", 1);
    let padded = format!("{head}\n\n{padded_body}-----BEGIN PGP SIGNATURE-----{sig}\n\n");
    assert_ne!(padded, original);
    up.fault(
        "/dists/bookworm/InRelease",
        Fault::Body(padded.into_bytes()),
    );

    let second = sync_mirror(&global, &mirror, &global.target).await.unwrap();
    assert_eq!(
        second.suites_unchanged,
        vec!["bookworm".to_owned()],
        "{second:?}"
    );
    up.clear("/dists/bookworm/InRelease");
}

#[tokio::test]
async fn legacy_raw_token_in_state_is_still_unchanged() {
    let serve = TempDir::new("mi-legacy-serve");
    signed_upstream(serve.path());
    let (base, _up) = spawn_upstream(serve.path().to_path_buf()).await;
    let target = TempDir::new("mi-legacy-target");
    let mirror_root = target.path().join("up");
    let global = build_global(target.path());
    let mirror = build_mirror(base, &["bookworm"], pgp_off());
    assert!(
        sync_mirror(&global, &mirror, &global.target)
            .await
            .unwrap()
            .is_success()
    );

    // State written by v0.1.0: sha256 of the raw InRelease bytes.
    let raw = std::fs::read(serve.path().join("dists/bookworm/InRelease")).unwrap();
    let mut st = state::load(&mirror_root).unwrap().unwrap();
    st.suites.get_mut("bookworm").unwrap().token_sha256 = hex(&Sha256::digest(&raw));
    state::save(&mirror_root, &st).unwrap();

    let second = sync_mirror(&global, &mirror, &global.target).await.unwrap();
    assert_eq!(
        second.suites_unchanged,
        vec!["bookworm".to_owned()],
        "{second:?}"
    );
}

// ---------- bounded root-file reads ----------

fn fast_global(target: &Path) -> GlobalConfig {
    let mut g = build_global(target);
    g.timeout.read_idle = Duration::from_secs(2);
    g
}

async fn assert_fails_fast(fault: Fault, path: &str) {
    let serve = TempDir::new("mi-bounded-serve");
    synthetic(serve.path());
    let (base, up) = spawn_upstream(serve.path().to_path_buf()).await;
    up.fault(path, fault);
    let target = TempDir::new("mi-bounded-target");
    let global = fast_global(target.path());
    let mirror = build_mirror(base, &["bookworm"], pgp_off());

    let started = Instant::now();
    let outcome = tokio::time::timeout(
        Duration::from_secs(30),
        sync_mirror(&global, &mirror, &global.target),
    )
    .await
    .expect("root-file read must be bounded in time")
    .unwrap();
    assert_eq!(outcome.suites_failed, vec!["bookworm".to_owned()]);
    assert!(started.elapsed() < Duration::from_secs(30));
    assert!(!target.path().join("up/dists/bookworm").exists());
}

#[tokio::test]
async fn endless_inrelease_is_rejected() {
    assert_fails_fast(Fault::Endless, "/dists/bookworm/InRelease").await;
}

#[tokio::test]
async fn stalled_inrelease_body_is_rejected() {
    assert_fails_fast(Fault::StallBody, "/dists/bookworm/InRelease").await;
}

#[tokio::test]
async fn silent_inrelease_server_is_rejected() {
    assert_fails_fast(Fault::StallHeaders, "/dists/bookworm/InRelease").await;
}

#[tokio::test]
async fn endless_sibling_release_gpg_is_rejected() {
    assert_fails_fast(Fault::Endless, "/dists/bookworm/Release.gpg").await;
}

#[tokio::test]
async fn oversized_inrelease_error_names_the_cap() {
    let serve = TempDir::new("mi-cap-serve");
    synthetic(serve.path());
    let (base, up) = spawn_upstream(serve.path().to_path_buf()).await;
    up.fault("/dists/bookworm/InRelease", Fault::Endless);
    let target = TempDir::new("mi-cap-target");
    let global = fast_global(target.path());
    let mirror = build_mirror(base, &["bookworm"], pgp_off());
    let err = sync_suite_direct(&global, &mirror, "bookworm")
        .await
        .expect_err("endless body must be capped");
    assert!(
        matches!(err, AptFlowError::MetadataTooLarge { .. }),
        "{err:?}"
    );
}

/// A refused redirect (here to an unsupported scheme) on an optional
/// sibling drops that sibling instead of failing the suite.
#[tokio::test]
async fn refused_sibling_redirect_drops_the_sibling() {
    let serve = TempDir::new("mi-refused-sibling-serve");
    synthetic(serve.path());
    let (base, up) = spawn_upstream(serve.path().to_path_buf()).await;
    up.fault(
        "/dists/bookworm/Release",
        Fault::Redirect("ftp://mirror.invalid/dists/bookworm/Release".to_owned()),
    );
    let target = TempDir::new("mi-refused-sibling-target");
    let global = build_global(target.path());
    let mirror = build_mirror(base, &["bookworm"], pgp_off());

    let outcome = sync_mirror(&global, &mirror, &global.target).await.unwrap();
    assert!(outcome.is_success(), "{outcome:?}");
    let dist = target.path().join("up/dists/bookworm");
    assert!(dist.join("InRelease").exists());
    assert!(!dist.join("Release").exists(), "refused sibling published");
}

// ---------- pool specs must not overwrite verified metadata ----------

#[tokio::test]
async fn pool_entry_naming_inrelease_fails_suite() {
    let serve = TempDir::new("mi-pool-root-file-serve");
    SyntheticRepo::new(serve.path().to_path_buf(), "bookworm")
        .add_package("nginx", b"nginx bytes".to_vec())
        .add_package_at("evil", "dists/bookworm/InRelease", b"forged".to_vec())
        .write();
    let (base, _up) = spawn_upstream(serve.path().to_path_buf()).await;
    let target = TempDir::new("mi-pool-root-file-target");
    let global = build_global(target.path());
    let mirror = build_mirror(base, &["bookworm"], pgp_off());

    let err = sync_suite_direct(&global, &mirror, "bookworm")
        .await
        .expect_err("a Filename naming InRelease must fail the suite");
    assert!(
        matches!(err, AptFlowError::PoolPathConflict { .. }),
        "{err:?}"
    );
    assert!(!target.path().join("up/dists/bookworm").exists());
}

#[tokio::test]
async fn pool_entry_in_other_suite_tree_fails_only_that_suite() {
    let serve = TempDir::new("mi-pool-other-suite-serve");
    SyntheticRepo::new(serve.path().to_path_buf(), "trixie")
        .add_package("curl", b"curl bytes".to_vec())
        .write();
    SyntheticRepo::new(serve.path().to_path_buf(), "bookworm")
        .add_package_at(
            "evil",
            "dists/trixie/main/binary-amd64/evil.deb",
            b"forged".to_vec(),
        )
        .write();
    let (base, _up) = spawn_upstream(serve.path().to_path_buf()).await;
    let target = TempDir::new("mi-pool-other-suite-target");
    let global = build_global(target.path());
    let mirror = build_mirror(base, &["trixie", "bookworm"], pgp_off());

    let outcome = sync_mirror(&global, &mirror, &global.target).await.unwrap();
    assert_eq!(
        outcome.suites_succeeded,
        vec!["trixie".to_owned()],
        "{outcome:?}"
    );
    assert_eq!(
        outcome.suites_failed,
        vec!["bookworm".to_owned()],
        "{outcome:?}"
    );
    assert!(
        !target
            .path()
            .join("up/dists/trixie/main/binary-amd64/evil.deb")
            .exists()
    );
}

/// `dists/stable -> bookworm` (suite alias symlink) must not let another
/// suite's index write through it into bookworm's published tree.
#[tokio::test]
async fn pool_entry_through_suite_alias_symlink_fails_suite() {
    let serve = TempDir::new("mi-alias-serve");
    SyntheticRepo::new(serve.path().to_path_buf(), "bookworm")
        .with_suite_alias("stable")
        .add_package("nginx", b"nginx bytes".to_vec())
        .write();
    SyntheticRepo::new(serve.path().to_path_buf(), "trixie")
        .add_package_at(
            "evil",
            "dists/stable/main/binary-amd64/evil.deb",
            b"forged".to_vec(),
        )
        .write();
    let (base, _up) = spawn_upstream(serve.path().to_path_buf()).await;
    let target = TempDir::new("mi-alias-target");
    let global = build_global(target.path());
    let mut mirror = build_mirror(base, &["bookworm", "trixie"], pgp_off());
    let BackendOptions::Apt(apt) = &mut mirror.backend_options;
    apt.create_suite_symlinks = true;

    let outcome = sync_mirror(&global, &mirror, &global.target).await.unwrap();
    let root = target.path().join("up");
    assert!(
        std::fs::symlink_metadata(root.join("dists/stable"))
            .unwrap()
            .file_type()
            .is_symlink(),
        "alias symlink expected"
    );
    assert_eq!(
        outcome.suites_failed,
        vec!["trixie".to_owned()],
        "{outcome:?}"
    );
    assert!(
        !root
            .join("dists/bookworm/main/binary-amd64/evil.deb")
            .exists()
    );
}

#[tokio::test]
async fn pool_file_inside_own_suite_dir_still_syncs() {
    let serve = TempDir::new("mi-pool-in-suite-serve");
    SyntheticRepo::new(serve.path().to_path_buf(), "bookworm")
        .add_package_in_suite("pve-fake", b"in-suite package".to_vec())
        .write();
    let (base, _up) = spawn_upstream(serve.path().to_path_buf()).await;
    let target = TempDir::new("mi-pool-in-suite-target");
    let global = build_global(target.path());
    let mirror = build_mirror(base, &["bookworm"], pgp_off());

    let outcome = sync_mirror(&global, &mirror, &global.target).await.unwrap();
    assert_eq!(
        outcome.suites_succeeded,
        vec!["bookworm".to_owned()],
        "{outcome:?}"
    );
    let deb = target
        .path()
        .join("up/dists/bookworm/main/binary-amd64/pve-fake_1.0_amd64.deb");
    assert_eq!(std::fs::read(deb).unwrap(), b"in-suite package");
}
