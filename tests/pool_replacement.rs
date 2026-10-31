//! Pool replacement and wanted-set shape: a pool file whose upstream content
//! changes at the same path is only swapped in together with the indexes
//! that reference it; a path listed by several indexes is fetched once; and
//! the manifest records the size actually written.
//!
//! The upstream is a tiny axum server that logs every request and can serve
//! a scripted sequence of bodies for a path (one per hit, the last repeats).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::Body;
use axum::extract::State;
use axum::http::{Response, StatusCode, Uri};
use sha2::{Digest as _, Sha256, Sha512};
use tokio::net::TcpListener;

use tain::config::model::{
    AptOptions, BackendKind, BackendOptions, GcConfig, GlobalConfig, I18nSelection, IndexSelection,
    MirrorConfig, RetryConfig, VerifyConfig,
};
use tain::core::engine::apt_flow::SuiteVerdict;
use tain::core::engine::verify::scrub_latest;
use tain::core::engine::{MirrorOutcome, SyncOverrides, sync_mirror, sync_mirror_with};
use tain::core::store::manifest;

mod common;
use common::TempDir;

const SUITE: &str = "trixie";
const DATE_1: &str = "Sat, 03 Feb 2024 09:15:38 UTC";
const DATE_2: &str = "Sun, 04 Feb 2024 09:15:38 UTC";
const DATE_3: &str = "Mon, 05 Feb 2024 09:15:38 UTC";
const DI_IMAGES: &str = "main/installer-amd64/20250803/images";

// ---------- scripted, logging upstream ----------

#[derive(Default)]
struct Upstream {
    root: PathBuf,
    scripted: Mutex<HashMap<String, Vec<Vec<u8>>>>,
    log: Mutex<Vec<String>>,
}

impl Upstream {
    /// Forget past requests: hit counts and scripts restart from here.
    fn reset_log(&self) {
        self.log.lock().unwrap().clear();
    }

    /// Serve `bodies` for `path` in order, one per hit; the last repeats.
    fn script(&self, path: &str, bodies: Vec<Vec<u8>>) {
        self.scripted
            .lock()
            .unwrap()
            .insert(format!("/{path}"), bodies);
    }

    fn hits(&self, path: &str) -> usize {
        let want = format!("/{path}");
        self.log
            .lock()
            .unwrap()
            .iter()
            .filter(|p| **p == want)
            .count()
    }
}

async fn spawn_upstream(root: PathBuf) -> (url::Url, Arc<Upstream>) {
    let up = Arc::new(Upstream {
        root,
        ..Upstream::default()
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

async fn handler(State(up): State<Arc<Upstream>>, uri: Uri) -> Response<Body> {
    let path = uri.path().to_owned();
    let seen = {
        let mut log = up.log.lock().unwrap();
        log.push(path.clone());
        log.iter().filter(|p| **p == path).count()
    };
    let scripted = up
        .scripted
        .lock()
        .unwrap()
        .get(&path)
        .map(|bodies| bodies[(seen - 1).min(bodies.len() - 1)].clone());
    let body = scripted.or_else(|| std::fs::read(up.root.join(path.trim_start_matches('/'))).ok());
    let (status, body) = match body {
        Some(bytes) => (StatusCode::OK, Body::from(bytes)),
        None => (StatusCode::NOT_FOUND, Body::empty()),
    };
    Response::builder().status(status).body(body).unwrap()
}

// ---------- synthetic repository ----------

struct Deb {
    name: String,
    bytes: Vec<u8>,
}

fn deb(name: &str, bytes: &[u8]) -> Deb {
    Deb {
        name: name.to_owned(),
        bytes: bytes.to_vec(),
    }
}

impl Deb {
    fn filename(&self) -> String {
        format!("pool/main/p/{0}/{0}_1.0_all.deb", self.name)
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

fn packages_body(debs: &[Deb]) -> Vec<u8> {
    debs.iter()
        .map(|d| {
            format!(
                "Package: {}\nVersion: 1.0\nArchitecture: all\nFilename: {}\nSize: {}\nSHA256: {}\nSHA512: {}\n\n",
                d.name,
                d.filename(),
                d.bytes.len(),
                sha256_hex(&d.bytes),
                hex(&Sha512::digest(&d.bytes)),
            )
        })
        .collect::<String>()
        .into_bytes()
}

/// Release-relative index files: one `Packages` per architecture.
fn indexes(arches: &[(&str, &[Deb])]) -> Vec<(String, Vec<u8>)> {
    arches
        .iter()
        .map(|(arch, debs)| (format!("main/binary-{arch}/Packages"), packages_body(debs)))
        .collect()
}

fn release_body(date: &str, arches: &[&str], listed: &[(String, Vec<u8>)]) -> Vec<u8> {
    let block = |digest: fn(&[u8]) -> String| -> String {
        listed
            .iter()
            .map(|(path, bytes)| format!(" {} {} {path}\n", digest(bytes), bytes.len()))
            .collect()
    };
    format!(
        "Suite: {SUITE}\nCodename: {SUITE}\nArchitectures: {}\nComponents: main\nDate: {date}\n\
         SHA256:\n{}SHA512:\n{}",
        arches.join(" "),
        block(sha256_hex),
        block(|b| hex(&Sha512::digest(b))),
    )
    .into_bytes()
}

/// Write the whole upstream tree; `di_images` adds a d-i `SHA256SUMS`.
fn write_repo(root: &Path, date: &str, arches: &[(&str, &[Deb])], di_images: &[(&str, &[u8])]) {
    for d in arches.iter().flat_map(|(_, debs)| debs.iter()) {
        write_file(&root.join(d.filename()), &d.bytes);
    }
    let dists = root.join("dists").join(SUITE);
    let mut listed = indexes(arches);
    if !di_images.is_empty() {
        let mut sums = String::new();
        for (rel, bytes) in di_images {
            write_file(&dists.join(DI_IMAGES).join(rel), bytes);
            sums.push_str(&format!("{}  ./{rel}\n", sha256_hex(bytes)));
        }
        listed.push((format!("{DI_IMAGES}/SHA256SUMS"), sums.into_bytes()));
    }
    for (path, bytes) in &listed {
        write_file(&dists.join(path), bytes);
    }
    let names: Vec<&str> = arches.iter().map(|(a, _)| *a).collect();
    let release = release_body(date, &names, &listed);
    write_file(&dists.join("Release"), &release);
    write_file(&dists.join("InRelease"), &release);
}

fn write_file(path: &Path, bytes: &[u8]) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, bytes).unwrap();
}

// ---------- config + helpers ----------

fn build_mirror(base: url::Url, arches: &[&str], debian_installer: bool) -> MirrorConfig {
    MirrorConfig {
        name: "m".to_owned(),
        backend: BackendKind::Apt,
        url: base,
        path: PathBuf::from("m"),
        verify: VerifyConfig::default(),
        gc: GcConfig::default(),
        force_http1: false,
        backend_options: BackendOptions::Apt(AptOptions {
            suites: vec![SUITE.to_owned()],
            components: vec!["main".to_owned()],
            architectures: arches.iter().map(|a| (*a).to_owned()).collect(),
            indexes: IndexSelection {
                packages: true,
                contents: false,
                i18n: I18nSelection::None,
                dep11: false,
                cnf: false,
                sources: false,
                debian_installer,
            },
            create_suite_symlinks: false,
        }),
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

async fn dry_run(global: &GlobalConfig, mirror: &MirrorConfig) -> MirrorOutcome {
    let overrides = SyncOverrides {
        dry_run: true,
        ..SyncOverrides::default()
    };
    sync_mirror_with(global, mirror, &global.target, overrides)
        .await
        .unwrap()
}

/// SHA256 the published `Packages` records for `filename`.
fn published_sha256(mirror_root: &Path, arch: &str, filename: &str) -> String {
    let path = mirror_root
        .join("dists")
        .join(SUITE)
        .join(format!("main/binary-{arch}/Packages"));
    let text = std::fs::read_to_string(path).unwrap();
    text.split("\n\n")
        .find(|p| p.lines().any(|l| l == format!("Filename: {filename}")))
        .and_then(|p| p.lines().find_map(|l| l.strip_prefix("SHA256: ")))
        .unwrap_or_else(|| panic!("{filename} not in published index"))
        .to_owned()
}

fn on_disk_sha256(path: &Path) -> String {
    sha256_hex(&std::fs::read(path).unwrap())
}

fn files_under(dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    entries
        .flatten()
        .flat_map(|e| {
            let path = e.path();
            if e.file_type().unwrap().is_dir() {
                files_under(&path)
            } else {
                vec![path]
            }
        })
        .collect()
}

fn assert_no_pending(mirror_root: &Path) {
    let left = files_under(&mirror_root.join(".tain/pending"));
    assert!(
        left.is_empty(),
        "pending replacements left behind: {left:?}"
    );
}

fn assert_verify_clean(mirror_root: &Path) {
    let report = scrub_latest(mirror_root).unwrap();
    assert!(report.is_clean(), "verify problems: {:?}", report.problems);
}

// ---------- same-path replacement ----------

#[tokio::test]
async fn failed_round_keeps_published_bytes_of_a_replaced_pool_file() {
    let serve = TempDir::new("pool-repl-fail-serve");
    let target = TempDir::new("pool-repl-fail-target");
    let v1 = [deb("pkg00", b"first content"), deb("pkg01", b"steady")];
    write_repo(serve.path(), DATE_1, &[("amd64", &v1)], &[]);
    let (base, _up) = spawn_upstream(serve.path().to_path_buf()).await;
    let global = build_global(target.path());
    let mirror = build_mirror(base, &["amd64"], false);
    assert!(sync(&global, &mirror).await.is_success());

    // Upstream rebuilds pkg00 in place and lists a file it never serves.
    let v2 = [
        deb("pkg00", b"rebuilt content"),
        deb("pkg01", b"steady"),
        deb("zzmissing", b"never served"),
    ];
    write_repo(serve.path(), DATE_2, &[("amd64", &v2)], &[]);
    std::fs::remove_file(serve.path().join(v2[2].filename())).unwrap();
    let outcome = sync(&global, &mirror).await;
    assert!(!outcome.is_success(), "{outcome:?}");

    let root = target.path().join("m");
    let published = published_sha256(&root, "amd64", &v1[0].filename());
    assert_eq!(published, sha256_hex(b"first content"));
    assert_eq!(on_disk_sha256(&root.join(v1[0].filename())), published);
    assert_no_pending(&root);
    assert_verify_clean(&root);
}

#[tokio::test]
async fn successful_round_swaps_in_a_replaced_pool_file() {
    let serve = TempDir::new("pool-repl-ok-serve");
    let target = TempDir::new("pool-repl-ok-target");
    let v1 = [deb("pkg00", b"first content")];
    write_repo(serve.path(), DATE_1, &[("amd64", &v1)], &[]);
    let (base, _up) = spawn_upstream(serve.path().to_path_buf()).await;
    let global = build_global(target.path());
    let mirror = build_mirror(base, &["amd64"], false);
    assert!(sync(&global, &mirror).await.is_success());

    let v2 = [deb("pkg00", b"rebuilt content")];
    write_repo(serve.path(), DATE_2, &[("amd64", &v2)], &[]);
    let outcome = sync(&global, &mirror).await;
    assert!(outcome.is_success(), "{outcome:?}");

    let root = target.path().join("m");
    let published = published_sha256(&root, "amd64", &v2[0].filename());
    assert_eq!(published, sha256_hex(b"rebuilt content"));
    assert_eq!(on_disk_sha256(&root.join(v2[0].filename())), published);
    let m = manifest::load(&root, outcome.new_generation).unwrap();
    let entry = &m.files[&v2[0].filename()];
    assert_eq!(entry.sha256_hex.as_deref(), Some(published.as_str()));
    assert_no_pending(&root);
    assert_verify_clean(&root);
}

#[tokio::test]
async fn refold_discards_a_pending_replacement() {
    let serve = TempDir::new("pool-repl-refold-serve");
    let target = TempDir::new("pool-repl-refold-target");
    let v1 = [deb("pkg00", b"first content")];
    write_repo(serve.path(), DATE_1, &[("amd64", &v1)], &[]);
    let (base, up) = spawn_upstream(serve.path().to_path_buf()).await;
    let global = build_global(target.path());
    let mirror = build_mirror(base, &["amd64"], false);
    assert!(sync(&global, &mirror).await.is_success());

    // Round 1 sees pkg00 rebuilt; before it publishes, upstream rolls the
    // rebuild back under a newer Release. Round 2 must publish the original
    // bytes, so round 1's fetched replacement may not land.
    let v2 = [deb("pkg00", b"rebuilt content")];
    write_repo(serve.path(), DATE_2, &[("amd64", &v2)], &[]);
    let rebuilt = indexes(&[("amd64", &v2)]);
    let rolled_back = indexes(&[("amd64", &v1)]);
    let release_rebuilt = release_body(DATE_2, &["amd64"], &rebuilt);
    let release_rolled_back = release_body(DATE_3, &["amd64"], &rolled_back);
    let dists = format!("dists/{SUITE}");
    up.reset_log();
    for name in ["InRelease", "Release"] {
        up.script(
            &format!("{dists}/{name}"),
            vec![release_rebuilt.clone(), release_rolled_back.clone()],
        );
    }
    up.script(
        &format!("{dists}/main/binary-amd64/Packages"),
        vec![rebuilt[0].1.clone(), rolled_back[0].1.clone()],
    );

    let outcome = sync(&global, &mirror).await;
    assert!(outcome.is_success(), "{outcome:?}");
    assert_eq!(up.hits(&format!("{dists}/InRelease")), 3, "one refold");

    let root = target.path().join("m");
    let published = published_sha256(&root, "amd64", &v1[0].filename());
    assert_eq!(published, sha256_hex(b"first content"));
    assert_eq!(on_disk_sha256(&root.join(v1[0].filename())), published);
    assert_no_pending(&root);
    assert_verify_clean(&root);
}

// ---------- wanted-set dedup ----------

#[tokio::test]
async fn arch_all_files_shared_by_two_architectures_are_handled_once() {
    let serve = TempDir::new("pool-dedup-serve");
    let target = TempDir::new("pool-dedup-target");
    let v1 = [deb("a", b"aaaa"), deb("b", b"bbbb"), deb("c", b"cccc")];
    write_repo(serve.path(), DATE_1, &[("amd64", &v1), ("arm64", &v1)], &[]);
    let (base, up) = spawn_upstream(serve.path().to_path_buf()).await;
    let global = build_global(target.path());
    let mirror = build_mirror(base, &["amd64", "arm64"], false);
    let outcome = sync(&global, &mirror).await;
    assert!(outcome.is_success(), "{outcome:?}");
    for d in &v1 {
        assert_eq!(up.hits(&d.filename()), 1, "{} fetched once", d.name);
    }

    let v2 = [
        deb("a", b"aaaa"),
        deb("b", b"bbbb"),
        deb("c", b"cccc"),
        deb("d", &[b'd'; 1000]),
    ];
    write_repo(serve.path(), DATE_2, &[("amd64", &v2), ("arm64", &v2)], &[]);
    let report = dry_run(&global, &mirror).await.dry_run.unwrap();
    let plan = &report.suites[0];
    assert_eq!(plan.pool_would_download.len(), 1, "{plan:?}");
    assert_eq!(plan.pool_already_present, 3, "{plan:?}");
    assert_eq!(plan.bytes_estimate, 1000, "{plan:?}");
}

#[tokio::test]
async fn conflicting_entries_within_one_suite_fail_it() {
    let serve = TempDir::new("pool-conflict-serve");
    let target = TempDir::new("pool-conflict-target");
    let amd64 = [deb("pkg", b"amd64 view")];
    let arm64 = [deb("pkg", b"arm64 view")];
    write_repo(
        serve.path(),
        DATE_1,
        &[("amd64", &amd64), ("arm64", &arm64)],
        &[],
    );
    let (base, _up) = spawn_upstream(serve.path().to_path_buf()).await;
    let global = build_global(target.path());
    let mirror = build_mirror(base, &["amd64", "arm64"], false);

    let report = dry_run(&global, &mirror).await.dry_run.unwrap();
    let SuiteVerdict::Failed(msg) = &report.suites[0].verdict else {
        panic!("conflict not detected: {report:?}");
    };
    assert!(msg.contains(&amd64[0].filename()), "{msg}");
    assert!(msg.contains("main/binary-amd64/Packages"), "{msg}");
    assert!(msg.contains("main/binary-arm64/Packages"), "{msg}");

    let outcome = sync(&global, &mirror).await;
    assert!(!outcome.is_success(), "{outcome:?}");
    let root = target.path().join("m");
    assert!(!root.join("dists").join(SUITE).exists(), "suite published");
}

// ---------- recorded size ----------

#[tokio::test]
async fn installer_images_are_recorded_with_their_real_size() {
    let serve = TempDir::new("pool-di-size-serve");
    let target = TempDir::new("pool-di-size-target");
    let image: &[u8] = b"mini iso body content";
    write_repo(
        serve.path(),
        DATE_1,
        &[("amd64", &[])],
        &[("netboot/mini.iso", image)],
    );
    let (base, _up) = spawn_upstream(serve.path().to_path_buf()).await;
    let global = build_global(target.path());
    let mirror = build_mirror(base, &["amd64"], true);
    let outcome = sync(&global, &mirror).await;
    assert!(outcome.is_success(), "{outcome:?}");

    let root = target.path().join("m");
    let m = manifest::load(&root, outcome.new_generation).unwrap();
    let rel = format!("dists/{SUITE}/{DI_IMAGES}/netboot/mini.iso");
    assert_eq!(m.files[&rel].size, image.len() as u64);
    assert_verify_clean(&root);
}
