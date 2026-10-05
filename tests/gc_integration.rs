//! GC fault injection: orphan deletion after grace, circuit breaker on an
//! emptied index, migration-boot dry-run guard.

use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use tain::config::model::{
    AptOptions, BackendKind, BackendOptions, GcConfig, GlobalConfig, I18nSelection, IndexSelection,
    MirrorConfig, VerifyConfig,
};
use tain::core::engine::gc::{self, GcOptions};
use tain::core::engine::sync_mirror;

mod common;
use common::{PackagesVariantKind, StaticServer, SyntheticRepo, TempDir};

fn build_mirror(base_url: &url::Url) -> MirrorConfig {
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
        name: "upstream".to_owned(),
        backend: BackendKind::Apt,
        url: base_url.clone(),
        path: PathBuf::from("upstream"),
        verify: VerifyConfig::default(),
        gc: GcConfig::default(),
        force_http1: false,
        backend_options: BackendOptions::Apt(apt),
    }
}

fn build_global(target: PathBuf) -> GlobalConfig {
    GlobalConfig {
        target,
        parallel: 4,
        host_connections: 2,
        ..GlobalConfig::default()
    }
}

/// A package dropped upstream is deleted by `run_gc` once the grace period passes.
#[tokio::test]
async fn upstream_drop_becomes_gc_candidate_after_grace() {
    let target = TempDir::new("gc-drop-target");
    let global = build_global(target.path().to_path_buf());

    let serve1 = TempDir::new("gc-drop-serve1");
    SyntheticRepo::new(serve1.path().to_path_buf(), "bookworm")
        .add_package("nginx", b"nginx bytes".to_vec())
        .add_package("curl", b"curl bytes".to_vec())
        .with_compressed_variant(PackagesVariantKind::Xz)
        .write();
    let server1 = StaticServer::spawn(serve1.path().to_path_buf()).await;
    let mirror1 = build_mirror(&server1.base_url());
    sync_mirror(&global, &mirror1, &global.target)
        .await
        .unwrap();
    drop(server1);

    // Round 2 drops curl.
    let serve2 = TempDir::new("gc-drop-serve2");
    SyntheticRepo::new(serve2.path().to_path_buf(), "bookworm")
        .add_package("nginx", b"nginx v2 bytes".to_vec())
        .with_compressed_variant(PackagesVariantKind::Xz)
        .write();
    let server2 = StaticServer::spawn(serve2.path().to_path_buf()).await;
    let mirror2 = build_mirror(&server2.base_url());
    sync_mirror(&global, &mirror2, &global.target)
        .await
        .unwrap();

    let curl_deb = target
        .path()
        .join("upstream/pool/main/c/curl/curl_1.0_amd64.deb");
    assert!(curl_deb.exists(), "curl.deb still on disk pre-GC");

    // keep_generations = 1 orphans curl; a future "now" clears the grace period.
    let opts = GcOptions {
        enabled: true,
        grace_period: Duration::from_secs(3600),
        max_delete_ratio: 0.95,
        max_delete_byte_ratio: 0.95,
        keep_generations: 1,
        dry_run: false,
    };
    let future = SystemTime::now() + Duration::from_secs(100 * 24 * 3600);
    let mirror_root = target.path().join("upstream");
    let r = gc::run_gc(&mirror_root, &opts, future).unwrap();
    assert!(
        r.deleted.iter().any(|p| p.ends_with("curl_1.0_amd64.deb")),
        "curl should be deleted; report: {r:?}"
    );
    assert!(!curl_deb.exists());
}

/// Wipe protection: an upstream empty index trips the circuit breaker; nothing is deleted.
#[tokio::test]
async fn empty_index_publish_trips_circuit_breaker() {
    let target = TempDir::new("gc-fuse-target");
    let global = build_global(target.path().to_path_buf());

    let serve = TempDir::new("gc-fuse-serve");
    let mut builder = SyntheticRepo::new(serve.path().to_path_buf(), "bookworm")
        .with_compressed_variant(PackagesVariantKind::Xz);
    for i in 0..20 {
        builder = builder.add_package(format!("pkg{i}"), b"body".to_vec());
    }
    builder.write();
    let server = StaticServer::spawn(serve.path().to_path_buf()).await;
    let mirror = build_mirror(&server.base_url());
    sync_mirror(&global, &mirror, &global.target).await.unwrap();
    drop(server);

    let serve2 = TempDir::new("gc-fuse-serve2");
    SyntheticRepo::new(serve2.path().to_path_buf(), "bookworm")
        .with_compressed_variant(PackagesVariantKind::Xz)
        .write();
    let server2 = StaticServer::spawn(serve2.path().to_path_buf()).await;
    let mirror2 = build_mirror(&server2.base_url());
    sync_mirror(&global, &mirror2, &global.target)
        .await
        .unwrap();

    let opts = GcOptions {
        enabled: true,
        grace_period: Duration::from_secs(1),
        max_delete_ratio: 0.3,
        max_delete_byte_ratio: 0.3,
        keep_generations: 1,
        dry_run: false,
    };
    let future = SystemTime::now() + Duration::from_secs(100 * 24 * 3600);
    let mirror_root = target.path().join("upstream");
    let r = gc::run_gc(&mirror_root, &opts, future).unwrap();
    assert!(r.circuit_broken, "circuit must break: {r:?}");
    assert!(r.deleted.is_empty());
    let pool = mirror_root.join("pool/main");
    let remaining: usize = walk_count(&pool);
    assert!(remaining >= 20, "circuit-broken GC left files: {remaining}");
}

/// Migration guard: the first sync over a pre-existing tree forces GC dry-run,
/// so legacy pool files survive until the operator can `tain verify`.
#[tokio::test]
async fn migration_boot_first_sync_forces_gc_dry_run() {
    let serve = TempDir::new("migrate-serve");
    SyntheticRepo::new(serve.path().to_path_buf(), "bookworm")
        .add_package("nginx", b"nginx bytes".to_vec())
        .with_compressed_variant(PackagesVariantKind::Xz)
        .write();
    let server = StaticServer::spawn(serve.path().to_path_buf()).await;

    let target = TempDir::new("migrate-target");
    let mirror_root = target.path().join("upstream");
    std::fs::create_dir_all(&mirror_root).unwrap();
    // Legacy pool file that upstream does not advertise.
    let legacy_dir = mirror_root.join("pool/main/l/legacy-tool");
    std::fs::create_dir_all(&legacy_dir).unwrap();
    let legacy_deb = legacy_dir.join("legacy-tool_1.0_amd64.deb");
    std::fs::write(&legacy_deb, b"legacy binary").unwrap();

    let global = build_global(target.path().to_path_buf());
    let mut mirror = build_mirror(&server.base_url());
    mirror.gc.enabled = true;
    mirror.gc.grace_period = Duration::from_secs(0);
    mirror.gc.keep_generations = 1;
    // Loose fuse so the second sync tests the guard, not the circuit breaker.
    mirror.gc.max_delete_ratio = tain::config::model::FloatRatio::new(0.95).expect("valid ratio");

    let past = SystemTime::UNIX_EPOCH + Duration::from_secs(60 * 60 * 24 * 365);
    let f = std::fs::OpenOptions::new()
        .write(true)
        .open(&legacy_deb)
        .unwrap();
    f.set_modified(past).unwrap();
    drop(f);

    let outcome = sync_mirror(&global, &mirror, &global.target).await.unwrap();
    assert!(outcome.is_success(), "migration-boot sync must succeed");

    assert!(
        legacy_deb.exists(),
        "migration guard must not delete legacy pool file on first sync"
    );
    let gc_result = outcome.gc.expect("gc report present on successful sync");
    assert!(
        gc_result.dry_run,
        "gc must be dry-run on migration boot: {gc_result:?}"
    );
    assert!(
        gc_result.deleted.is_empty(),
        "dry-run must not delete anything: {gc_result:?}"
    );

    // The guard applies only to the first pass.
    let second = sync_mirror(&global, &mirror, &global.target).await.unwrap();
    assert!(second.is_success());
    let gc2 = second.gc.expect("gc on second sync");
    assert!(
        !gc2.dry_run,
        "migration guard must not persist past the first sync: {gc2:?}"
    );
    assert!(
        !legacy_deb.exists(),
        "legacy file should be GCed on the second pass now that manifest is stable"
    );
}

fn walk_count(dir: &std::path::Path) -> usize {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return 0;
    };
    rd.flatten()
        .map(|e| {
            let p = e.path();
            if e.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                walk_count(&p)
            } else {
                1
            }
        })
        .sum()
}
