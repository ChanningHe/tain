//! `sync --dry-run` planner: never mutates the mirror, report counts match a
//! real sync, verdict routing, `--gc-dry-run` preview, staging cleanup.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use tain::config::model::{
    AptOptions, BackendKind, BackendOptions, GcConfig, GlobalConfig, I18nSelection, IndexSelection,
    MirrorConfig, VerifyConfig,
};
use tain::core::engine::apt_flow::SuiteVerdict;
use tain::core::engine::{SyncOverrides, sync_mirror, sync_mirror_with};

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

fn build_global(target: PathBuf) -> GlobalConfig {
    GlobalConfig {
        target,
        parallel: 4,
        host_connections: 2,
        ..GlobalConfig::default()
    }
}

/// Relative path -> (size, SHA-256 hex) for every file under `root`;
/// symlinks are recorded by link target.
fn snapshot(root: &Path) -> BTreeMap<PathBuf, (u64, String)> {
    use sha2::{Digest, Sha256};
    let mut out = BTreeMap::new();
    if !root.exists() {
        return out;
    }
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for e in entries.flatten() {
            let path = e.path();
            let meta = match std::fs::symlink_metadata(&path) {
                Ok(m) => m,
                Err(_) => continue,
            };
            if meta.file_type().is_dir() {
                stack.push(path);
                continue;
            }
            let rel = path.strip_prefix(root).unwrap().to_path_buf();
            if meta.file_type().is_symlink() {
                let link = std::fs::read_link(&path).unwrap_or_default();
                let key = format!("SYMLINK::{}", link.display());
                out.insert(rel, (0, key));
                continue;
            }
            let bytes = match std::fs::read(&path) {
                Ok(b) => b,
                Err(_) => continue,
            };
            let sha = hex::encode(Sha256::digest(&bytes));
            out.insert(rel, (bytes.len() as u64, sha));
        }
    }
    out
}

mod hex {
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(bytes.as_ref().len() * 2);
        for &b in bytes.as_ref() {
            out.push(HEX[(b >> 4) as usize] as char);
            out.push(HEX[(b & 0x0F) as usize] as char);
        }
        out
    }
}

fn dry_run_overrides() -> SyncOverrides {
    SyncOverrides {
        dry_run: true,
        gc_dry_run: false,
    }
}

fn combined_overrides() -> SyncOverrides {
    SyncOverrides {
        dry_run: true,
        gc_dry_run: true,
    }
}

/// Dry-run after a real sync leaves the mirror tree byte-identical.
#[tokio::test]
async fn dry_run_leaves_published_state_byte_identical() {
    let serve = TempDir::new("dryrun-i1-serve");
    SyntheticRepo::new(serve.path().to_path_buf(), "bookworm")
        .add_package("nginx", b"nginx bytes".to_vec())
        .add_package("curl", b"curl bytes".to_vec())
        .write();
    let server = StaticServer::spawn(serve.path().to_path_buf()).await;

    let target = TempDir::new("dryrun-i1-target");
    let global = build_global(target.path().to_path_buf());
    let mirror = build_mirror(&server.base_url(), "upstream");

    let real = sync_mirror(&global, &mirror, &global.target).await.unwrap();
    assert!(real.is_success(), "priming sync should succeed");

    let mirror_root = target.path().join("upstream");
    let before = snapshot(&mirror_root);
    assert!(!before.is_empty(), "priming sync should leave files behind");
    assert!(
        before
            .iter()
            .any(|(k, _)| k.to_string_lossy().starts_with("dists/bookworm/InRelease")),
        "priming should have written dists/bookworm/InRelease"
    );

    let dry = sync_mirror_with(&global, &mirror, &global.target, dry_run_overrides())
        .await
        .unwrap();
    assert!(dry.dry_run.is_some(), "dry-run outcome should carry report");

    let after = snapshot(&mirror_root);
    assert_eq!(
        before,
        after,
        "dry-run modified {} disk entries",
        before
            .iter()
            .zip(after.iter())
            .filter(|(a, b)| a != b)
            .count()
    );
}

/// Fresh verdict: `pool_would_download` must equal the pool file count of a real sync.
#[tokio::test]
async fn fresh_verdict_matches_real_sync_pool_count() {
    let serve = TempDir::new("dryrun-fresh-serve");
    SyntheticRepo::new(serve.path().to_path_buf(), "bookworm")
        .add_package("nginx", b"nginx bytes".to_vec())
        .add_package("curl", b"curl bytes".to_vec())
        .add_package("apt", b"apt bytes".to_vec())
        .write();
    let server = StaticServer::spawn(serve.path().to_path_buf()).await;

    let dry_target = TempDir::new("dryrun-fresh-target-dry");
    let mut mirror = build_mirror(&server.base_url(), "upstream");
    let global_dry = build_global(dry_target.path().to_path_buf());
    let dry_outcome = sync_mirror_with(
        &global_dry,
        &mirror,
        &global_dry.target,
        dry_run_overrides(),
    )
    .await
    .unwrap();
    let report = dry_outcome.dry_run.expect("dry-run report");
    assert_eq!(report.suites.len(), 1);
    let suite = &report.suites[0];
    assert_eq!(suite.verdict, SuiteVerdict::Fresh);
    assert_eq!(suite.pool_already_present, 0, "no priors → nothing present");
    assert_eq!(suite.pool_would_download.len(), 3, "3 packages upstream");

    // Separate target so the real sync can't mask planner writes.
    let real_target = TempDir::new("dryrun-fresh-target-real");
    mirror.path = PathBuf::from("upstream");
    let global_real = build_global(real_target.path().to_path_buf());
    let real = sync_mirror(&global_real, &mirror, &global_real.target)
        .await
        .unwrap();
    assert!(real.is_success());

    let mut real_pool = 0usize;
    let pool_root = real_target.path().join("upstream/pool");
    let mut stack = vec![pool_root];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap().flatten() {
            let p = e.path();
            if e.file_type().unwrap().is_dir() {
                stack.push(p);
            } else {
                real_pool += 1;
            }
        }
    }
    assert_eq!(
        real_pool,
        suite.pool_would_download.len(),
        "planner would-download count must match ground-truth pool count"
    );
    assert_eq!(real_pool, 3);
}

/// Unchanged verdict: byte-identical InRelease after a real sync short-circuits.
#[tokio::test]
async fn unchanged_verdict_when_prior_state_matches_upstream() {
    let serve = TempDir::new("dryrun-unchanged-serve");
    SyntheticRepo::new(serve.path().to_path_buf(), "bookworm")
        .add_package("nginx", b"nginx bytes".to_vec())
        .write();
    let server = StaticServer::spawn(serve.path().to_path_buf()).await;

    let target = TempDir::new("dryrun-unchanged-target");
    let global = build_global(target.path().to_path_buf());
    let mirror = build_mirror(&server.base_url(), "upstream");

    let real = sync_mirror(&global, &mirror, &global.target).await.unwrap();
    assert!(real.is_success());

    let outcome = sync_mirror_with(&global, &mirror, &global.target, dry_run_overrides())
        .await
        .unwrap();
    let report = outcome.dry_run.expect("dry-run report");
    let suite = &report.suites[0];
    assert_eq!(suite.verdict, SuiteVerdict::Unchanged);
    assert!(suite.pool_would_download.is_empty());
    assert!(suite.indexes_would_download.is_empty());
    assert_eq!(suite.bytes_estimate, 0);
}

/// Incremental verdict: only the newly added upstream package is planned.
/// One server for both rounds keeps the URL-keyed `state.json` valid.
#[tokio::test]
async fn incremental_verdict_spots_only_new_upstream_packages() {
    let target = TempDir::new("dryrun-incr-target");
    let global = build_global(target.path().to_path_buf());
    let serve = TempDir::new("dryrun-incr-serve");

    SyntheticRepo::new(serve.path().to_path_buf(), "bookworm")
        .add_package("nginx", b"nginx bytes".to_vec())
        .write();
    let server = StaticServer::spawn(serve.path().to_path_buf()).await;
    let mirror = build_mirror(&server.base_url(), "upstream");
    let real = sync_mirror(&global, &mirror, &global.target).await.unwrap();
    assert!(real.is_success());

    // Sleep past 1s so ServeDir's Last-Modified (second granularity)
    // changes and the validator probe gets 200, not 304.
    tokio::time::sleep(std::time::Duration::from_millis(1200)).await;
    std::fs::remove_dir_all(serve.path()).unwrap();
    std::fs::create_dir_all(serve.path()).unwrap();
    SyntheticRepo::new(serve.path().to_path_buf(), "bookworm")
        .add_package("nginx", b"nginx bytes".to_vec())
        .add_package("curl", b"curl bytes".to_vec())
        .write();

    let outcome = sync_mirror_with(&global, &mirror, &global.target, dry_run_overrides())
        .await
        .unwrap();
    let report = outcome.dry_run.expect("dry-run report");
    let suite = &report.suites[0];
    assert_eq!(suite.verdict, SuiteVerdict::Incremental);
    assert_eq!(
        suite.pool_would_download.len(),
        1,
        "only curl is new; nginx bytes unchanged: {:?}",
        suite.pool_would_download,
    );
    assert!(
        suite.pool_would_download[0]
            .rel_path
            .ends_with("curl_1.0_amd64.deb")
    );
    assert_eq!(suite.pool_already_present, 1);
}

/// `--dry-run` + `--gc-dry-run`: report carries a GC preview, disk untouched.
#[tokio::test]
async fn combined_dry_run_flags_produce_gc_preview() {
    let target = TempDir::new("dryrun-gc-target");
    let global = build_global(target.path().to_path_buf());

    let serve1 = TempDir::new("dryrun-gc-serve1");
    SyntheticRepo::new(serve1.path().to_path_buf(), "bookworm")
        .add_package("nginx", b"nginx bytes".to_vec())
        .add_package("curl", b"curl bytes".to_vec())
        .write();
    let server1 = StaticServer::spawn(serve1.path().to_path_buf()).await;
    let mut mirror = build_mirror(&server1.base_url(), "upstream");
    mirror.gc.enabled = true;
    mirror.gc.grace_period = std::time::Duration::from_secs(0);
    let real = sync_mirror(&global, &mirror, &global.target).await.unwrap();
    assert!(real.is_success());
    drop(server1);

    // Round 2 drops curl, making it a GC candidate.
    let serve2 = TempDir::new("dryrun-gc-serve2");
    SyntheticRepo::new(serve2.path().to_path_buf(), "bookworm")
        .add_package("nginx", b"nginx bytes".to_vec())
        .write();
    let server2 = StaticServer::spawn(serve2.path().to_path_buf()).await;
    let mirror2 = MirrorConfig {
        url: server2.base_url(),
        ..mirror.clone()
    };

    let mirror_root = target.path().join("upstream");
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let _ = SystemTime::now();

    let before = snapshot(&mirror_root);
    let outcome = sync_mirror_with(&global, &mirror2, &global.target, combined_overrides())
        .await
        .unwrap();
    let after = snapshot(&mirror_root);
    assert_eq!(before, after, "combined dry-run must not touch disk");

    let report = outcome.dry_run.expect("dry-run report");
    let suite = &report.suites[0];
    assert_eq!(suite.pool_would_download.len(), 0);
    assert!(
        suite.gc_candidates.is_some(),
        "combined --dry-run + --gc-dry-run should carry a gc preview"
    );
}

/// Dry-run must wipe its staging dir so index bytes don't leak into the next sync.
#[tokio::test]
async fn dry_run_wipes_staging_directory() {
    let serve = TempDir::new("dryrun-staging-serve");
    SyntheticRepo::new(serve.path().to_path_buf(), "bookworm")
        .add_package("nginx", b"nginx bytes".to_vec())
        .write();
    let server = StaticServer::spawn(serve.path().to_path_buf()).await;

    let target = TempDir::new("dryrun-staging-target");
    let global = build_global(target.path().to_path_buf());
    let mirror = build_mirror(&server.base_url(), "upstream");

    let _ = sync_mirror_with(&global, &mirror, &global.target, dry_run_overrides())
        .await
        .unwrap();

    let staging = target.path().join("upstream/.tain/staging/bookworm");
    assert!(
        !staging.exists(),
        "staging must be wiped at dry-run exit — found {}",
        staging.display()
    );
}

/// Failure neutrality: an empty upstream yields `Failed` and writes nothing.
#[tokio::test]
async fn failure_neutrality_dry_run_never_writes_on_missing_upstream() {
    let empty = TempDir::new("dryrun-fail-serve");
    let server = StaticServer::spawn(empty.path().to_path_buf()).await;

    let target = TempDir::new("dryrun-fail-target");
    let global = build_global(target.path().to_path_buf());
    let mirror = build_mirror(&server.base_url(), "upstream");

    let outcome = sync_mirror_with(&global, &mirror, &global.target, dry_run_overrides())
        .await
        .unwrap();
    let report = outcome.dry_run.expect("dry-run report");
    assert_eq!(report.suites.len(), 1);
    assert!(matches!(report.suites[0].verdict, SuiteVerdict::Failed(_)));

    let mirror_root = target.path().join("upstream");
    assert!(!mirror_root.join(".tain/state.json").exists());
    assert!(!mirror_root.join("pool").exists());
    assert!(!mirror_root.join("dists").exists());
    // An empty manifest dir is tolerated; files are not.
    if let Ok(manifests) = std::fs::read_dir(mirror_root.join(".tain/manifest")) {
        assert_eq!(
            manifests.count(),
            0,
            "no manifest files may be written on a failed dry-run"
        );
    }
}
