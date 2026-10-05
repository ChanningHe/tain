//! Crash recovery, lock contention, and fatal-I/O (exit-code contract) tests.
//! Disk-full and kill -9 timing scenarios need a dedicated host and are not here.

use std::path::PathBuf;
use std::time::Duration;

use tain::config::model::{
    AptOptions, BackendKind, BackendOptions, GcConfig, GlobalConfig, I18nSelection, IndexSelection,
    MirrorConfig, VerifyConfig,
};
use tain::core::engine::{self, EngineError, sync_mirror};
use tain::core::store::{lock, manifest, state};

mod common;
use common::{StaticServer, SyntheticRepo, TempDir};

fn build_mirror(base_url: &url::Url, name: &str) -> MirrorConfig {
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
        url: base_url.clone(),
        path: PathBuf::from(name),
        verify: VerifyConfig::default(),
        gc: GcConfig::default(),
        force_http1: false,
        backend_options: BackendOptions::Apt(apt),
    }
}

fn build_global(target_root: PathBuf) -> GlobalConfig {
    GlobalConfig {
        target: target_root,
        parallel: 4,
        host_connections: 2,
        ..GlobalConfig::default()
    }
}

/// Staging leftovers from an interrupted run must not block the next sync.
#[tokio::test]
async fn staging_leftovers_do_not_break_next_sync() {
    let serve = TempDir::new("recover-serve");
    SyntheticRepo::new(serve.path().to_path_buf(), "bookworm")
        .add_package("nginx", b"real nginx".to_vec())
        .write();
    let server = StaticServer::spawn(serve.path().to_path_buf()).await;

    let target = TempDir::new("recover-target");
    let global = build_global(target.path().to_path_buf());
    let mirror = build_mirror(&server.base_url(), "upstream");
    let mirror_root = target.path().join("upstream");

    // Killed-mid-sync leftovers: staging garbage plus a stray `.tmp~` in pool.
    let staging = mirror_root.join(".tain/staging/bookworm");
    std::fs::create_dir_all(staging.join("main/binary-amd64")).unwrap();
    std::fs::write(staging.join("main/binary-amd64/Packages"), b"garbage").unwrap();
    std::fs::write(staging.join("stale-thing"), b"zzz").unwrap();
    let tmp_junk = mirror_root.join("pool/main/n/nginx/nginx_1.0_amd64.deb.tmp~");
    std::fs::create_dir_all(tmp_junk.parent().unwrap()).unwrap();
    std::fs::write(&tmp_junk, b"half-written").unwrap();

    let outcome = sync_mirror(&global, &mirror, &global.target).await.unwrap();
    assert!(
        outcome.is_success(),
        "sync must recover from staging leftovers: {outcome:?}"
    );

    let pool = mirror_root.join("pool/main/n/nginx/nginx_1.0_amd64.deb");
    assert_eq!(std::fs::read(&pool).unwrap(), b"real nginx");
    assert!(
        !tmp_junk.exists(),
        "sink cleaned or overwrote the stray .tmp~"
    );

    let published_bin = mirror_root.join("dists/bookworm/main/binary-amd64");
    assert!(published_bin.join("Packages").exists());
    let published_bytes = std::fs::read(published_bin.join("Packages")).unwrap();
    assert!(
        published_bytes.starts_with(b"Package: nginx"),
        "published Packages is the fresh one, not the leftover garbage"
    );
}

/// Failure neutrality: a failed sync leaves the published state, manifest, and files intact.
#[tokio::test]
async fn prior_published_state_survives_upstream_failure() {
    let serve = TempDir::new("neutral-serve");
    let target = TempDir::new("neutral-target");
    let global = build_global(target.path().to_path_buf());
    let mirror = build_mirror(&url::Url::parse("http://127.0.0.1:1/").unwrap(), "upstream");

    SyntheticRepo::new(serve.path().to_path_buf(), "bookworm")
        .add_package("nginx", b"good nginx".to_vec())
        .write();
    let server = StaticServer::spawn(serve.path().to_path_buf()).await;
    let mirror = MirrorConfig {
        url: server.base_url(),
        ..mirror
    };
    let first = sync_mirror(&global, &mirror, &global.target).await.unwrap();
    assert!(first.is_success(), "first sync sets baseline");
    let mirror_root = target.path().join("upstream");
    let baseline_state = state::load(&mirror_root).unwrap().unwrap();
    let baseline_gen = baseline_state.generation;
    let baseline_manifest = manifest::load(&mirror_root, baseline_gen).unwrap();
    let baseline_pool =
        std::fs::read(mirror_root.join("pool/main/n/nginx/nginx_1.0_amd64.deb")).unwrap();
    let baseline_release = std::fs::read(mirror_root.join("dists/bookworm/Release")).unwrap();

    // No InRelease and no Release upstream: the whole run fails.
    std::fs::remove_file(serve.path().join("dists/bookworm/InRelease")).unwrap();
    std::fs::remove_file(serve.path().join("dists/bookworm/Release")).unwrap();

    let second = sync_mirror(&global, &mirror, &global.target).await.unwrap();
    assert!(
        !second.is_success(),
        "second sync must fail after upstream drops Release: {second:?}"
    );

    let after_state = state::load(&mirror_root).unwrap().unwrap();
    assert_eq!(
        after_state.generation, baseline_gen,
        "state.json generation must not advance"
    );
    let after_manifest = manifest::load(&mirror_root, baseline_gen).unwrap();
    assert_eq!(after_manifest.files, baseline_manifest.files);
    assert_eq!(
        std::fs::read(mirror_root.join("pool/main/n/nginx/nginx_1.0_amd64.deb")).unwrap(),
        baseline_pool,
    );
    assert_eq!(
        std::fs::read(mirror_root.join("dists/bookworm/Release")).unwrap(),
        baseline_release,
    );
}

/// Exit 3: a second sync on a locked mirror root gets `LockContended` (`lock_timeout = 0s`).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_second_sync_gets_lock_contention() {
    let serve = TempDir::new("lock-serve");
    SyntheticRepo::new(serve.path().to_path_buf(), "bookworm")
        .add_package("nginx", b"nginx bytes".to_vec())
        .write();
    let server = StaticServer::spawn(serve.path().to_path_buf()).await;

    let target = TempDir::new("lock-target");
    let global = build_global(target.path().to_path_buf());
    let mirror = build_mirror(&server.base_url(), "upstream");
    let mirror_root = target.path().join("upstream");
    std::fs::create_dir_all(&mirror_root).unwrap();

    // Hold the lock on a plain thread so the guard's Drop is deterministic.
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let root_clone = mirror_root.clone();
    let holder = std::thread::spawn(move || {
        let _g = lock::acquire(&root_clone, Duration::ZERO).unwrap();
        release_rx.recv().unwrap();
    });
    // Let the holder's flock() land first.
    tokio::time::sleep(Duration::from_millis(80)).await;

    let err = sync_mirror(&global, &mirror, &global.target)
        .await
        .expect_err("second sync must not acquire the lock");
    assert!(
        matches!(err, EngineError::LockContended(_)),
        "expected LockContended, got {err:?}"
    );

    release_tx.send(()).unwrap();
    holder.join().unwrap();
}

/// Exit 4: an unwritable target root yields an error `is_fatal_io` accepts.
/// The exact `EngineError` variant is deliberately not asserted.
#[cfg(unix)]
#[tokio::test]
async fn unwritable_target_maps_to_fatal_io() {
    use std::os::unix::fs::PermissionsExt;

    // Needs an unprivileged uid: root ignores DAC permission bits.
    // SAFETY: geteuid is thread-safe on all supported platforms.
    if unsafe { libc::geteuid() } == 0 {
        eprintln!(
            "skipping unwritable_target_maps_to_fatal_io: running as root; \
             DAC perms don't apply — this test needs an unprivileged uid to be meaningful"
        );
        return;
    }

    let serve = TempDir::new("readonly-serve");
    SyntheticRepo::new(serve.path().to_path_buf(), "bookworm")
        .add_package("nginx", b"nginx bytes".to_vec())
        .write();
    let server = StaticServer::spawn(serve.path().to_path_buf()).await;

    let target = TempDir::new("readonly-target");
    let target_root = target.path().to_path_buf();
    std::fs::set_permissions(&target_root, std::fs::Permissions::from_mode(0o555)).unwrap();

    let global = build_global(target_root.clone());
    let mirror = build_mirror(&server.base_url(), "upstream");

    let err = sync_mirror(&global, &mirror, &global.target)
        .await
        .expect_err("readonly target must fail");
    assert!(
        engine::is_fatal_io(&err),
        "is_fatal_io should classify readonly-target error, got {err:?}"
    );

    // Restore perms so TempDir cleanup works.
    std::fs::set_permissions(&target_root, std::fs::Permissions::from_mode(0o755)).ok();
}

/// Crash between `publish_suite` and `manifest::save`/`state::save`: the next
/// sync must detect the drift via spot-check and fully resync, and GC must
/// not delete files belonging to the recovered dists.
#[tokio::test]
async fn crash_between_publish_and_manifest_save_recovers_without_data_loss() {
    let serve = TempDir::new("crash-publish-serve");
    let v1_root = serve.path().to_path_buf();
    SyntheticRepo::new(v1_root.clone(), "bookworm")
        .add_package("nginx", b"v1 nginx".to_vec())
        .add_package("curl", b"v1 curl".to_vec())
        .write();
    let server = StaticServer::spawn(v1_root.clone()).await;

    let target = TempDir::new("crash-publish-target");
    // Aggressive GC makes a missed drift observable as deleted pool files.
    let global = build_global(target.path().to_path_buf());
    let mut mirror = build_mirror(&server.base_url(), "upstream");
    mirror.gc.enabled = true;
    mirror.gc.keep_generations = 1;
    let mirror_root = target.path().join("upstream");

    let first = sync_mirror(&global, &mirror, &global.target).await.unwrap();
    assert!(first.is_success(), "baseline sync must succeed");
    let baseline_state = state::load(&mirror_root).unwrap().unwrap();
    assert_eq!(baseline_state.generation, 1);
    assert!(manifest::load(&mirror_root, 1).is_ok());
    let v1_inrelease_bytes = std::fs::read(mirror_root.join("dists/bookworm/InRelease")).unwrap();

    // Simulate the crash: on-disk InRelease no longer matches state's token,
    // state.json stays at gen 1, and manifest/2.json is absent.
    let mut mutated_inrelease = v1_inrelease_bytes.clone();
    mutated_inrelease.extend_from_slice(b"\n# crash simulation: publish ran, save did not\n");
    std::fs::write(
        mirror_root.join("dists/bookworm/InRelease"),
        &mutated_inrelease,
    )
    .unwrap();
    assert!(manifest::load(&mirror_root, 2).is_err());
    assert_eq!(state::load(&mirror_root).unwrap().unwrap().generation, 1);

    // Upstream is unchanged, so only the spot-check can force the resync.
    let second = sync_mirror(&global, &mirror, &global.target).await.unwrap();
    assert!(
        second.is_success(),
        "recovery sync must succeed: {second:?}"
    );
    assert!(
        second.suites_unchanged.is_empty(),
        "must NOT return Unchanged when disk drifted mid-publish: {second:?}"
    );
    assert_eq!(
        second.suites_succeeded,
        vec!["bookworm".to_owned()],
        "suite must land in succeeded (fresh sync ran)"
    );

    let recovered_state = state::load(&mirror_root).unwrap().unwrap();
    assert!(
        recovered_state.generation > 1,
        "state generation must advance past rollback"
    );
    assert!(
        manifest::load(&mirror_root, recovered_state.generation).is_ok(),
        "manifest for recovered generation must exist"
    );
    let recovered_inrelease = std::fs::read(mirror_root.join("dists/bookworm/InRelease")).unwrap();
    assert_eq!(
        recovered_inrelease, v1_inrelease_bytes,
        "recovered InRelease must match upstream (mutation reverted)"
    );
    for (pkg, want) in [("nginx", &b"v1 nginx"[..]), ("curl", &b"v1 curl"[..])] {
        let pool = mirror_root.join(format!("pool/main/{}/{pkg}/{pkg}_1.0_amd64.deb", &pkg[..1]));
        assert!(pool.exists(), "GC must not delete recovered pool {pkg}");
        assert_eq!(
            std::fs::read(&pool).unwrap(),
            want,
            "recovered pool {pkg} content survives"
        );
    }
}

/// Spot-check: with the published InRelease deleted but state.json intact,
/// the unchanged-upstream fast path must not return Unchanged.
#[tokio::test]
async fn state_ahead_of_disk_forces_fresh_sync() {
    let serve = TempDir::new("spot-check-serve");
    SyntheticRepo::new(serve.path().to_path_buf(), "bookworm")
        .add_package("nginx", b"nginx bytes".to_vec())
        .write();
    let server = StaticServer::spawn(serve.path().to_path_buf()).await;

    let target = TempDir::new("spot-check-target");
    let global = build_global(target.path().to_path_buf());
    let mirror = build_mirror(&server.base_url(), "upstream");
    let mirror_root = target.path().join("upstream");

    let first = sync_mirror(&global, &mirror, &global.target).await.unwrap();
    assert!(first.is_success(), "baseline sync must succeed");
    let baseline_state = state::load(&mirror_root).unwrap().unwrap();
    let baseline_gen = baseline_state.generation;

    let published_inrelease = mirror_root.join("dists/bookworm/InRelease");
    std::fs::remove_file(&published_inrelease).unwrap();
    assert!(!published_inrelease.exists());

    let second = sync_mirror(&global, &mirror, &global.target).await.unwrap();
    assert!(
        second.is_success(),
        "spot-check sync must succeed: {second:?}"
    );
    assert!(
        second.suites_unchanged.is_empty(),
        "suite must NOT be Unchanged when disk drifted: {second:?}"
    );
    assert_eq!(
        second.suites_succeeded,
        vec!["bookworm".to_owned()],
        "suite must land in succeeded (fresh sync path)"
    );

    assert!(
        published_inrelease.exists(),
        "spot-check must re-publish the missing InRelease"
    );
    let after_state = state::load(&mirror_root).unwrap().unwrap();
    assert!(
        after_state.generation > baseline_gen,
        "state.json generation must advance: {} → {}",
        baseline_gen,
        after_state.generation
    );
    assert!(
        manifest::load(&mirror_root, after_state.generation).is_ok(),
        "manifest for new generation must exist"
    );
}
