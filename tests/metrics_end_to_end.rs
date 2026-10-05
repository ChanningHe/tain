//! `--metrics-file` end to end: real sync outcome -> Prometheus textfile.
//! A failed sync still writes the file, minus `tain_last_success_seconds`.

use std::path::PathBuf;

use tain::config::model::{
    AptOptions, BackendKind, BackendOptions, GcConfig, GlobalConfig, I18nSelection, IndexSelection,
    MirrorConfig, VerifyConfig,
};
use tain::core::engine::sync_mirror;
use tain::observe::metrics::{GcMetrics, PgpMetric, SyncMetrics, write_textfile};

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

/// Copy of `main.rs::build_metrics`'s outcome-to-metrics translation.
fn from_outcome(mirror: &MirrorConfig, o: &tain::core::engine::MirrorOutcome) -> SyncMetrics {
    use tain::backends::apt::pgp::VerifyOutcome;
    let pgp_by_suite = o
        .pgp_by_suite
        .iter()
        .map(|(suite, out)| {
            (
                suite.clone(),
                match out {
                    VerifyOutcome::Verified => PgpMetric::Verified,
                    VerifyOutcome::Skipped => PgpMetric::Skipped,
                    VerifyOutcome::AbsentInIfPresent => PgpMetric::Absent,
                },
            )
        })
        .collect();
    let gc = o.gc.as_ref().map(|g| GcMetrics {
        deleted_files: g.deleted.len() as u64,
        circuit_broken: g.circuit_broken,
    });
    SyncMetrics {
        mirror: mirror.name.clone(),
        backend: mirror.backend.name().to_owned(),
        pool_files: o.pool_files,
        pool_bytes: o.pool_bytes,
        last_success_unix: o.last_success_unix,
        gc,
        sync_duration_secs: o.sync_duration.as_secs_f64(),
        pgp_by_suite,
    }
}

#[tokio::test]
async fn successful_sync_produces_populated_textfile() {
    let serve_dir = TempDir::new("metrics-happy-serve");
    let _repo = SyntheticRepo::new(serve_dir.path().to_path_buf(), "bookworm")
        .add_package("nginx", b"nginx bytes for metrics".to_vec())
        .add_package("apt", b"apt bytes for metrics".to_vec())
        .write();
    let server = StaticServer::spawn(serve_dir.path().to_path_buf()).await;

    let target = TempDir::new("metrics-happy-target");
    let global = build_global(target.path().to_path_buf());
    let mirror = build_mirror(&server.base_url(), "upstream");

    let outcome = sync_mirror(&global, &mirror, &global.target).await.unwrap();
    assert!(outcome.is_success(), "first sync must succeed: {outcome:?}");

    let metrics_path = target.path().join("tain.prom");
    write_textfile(&metrics_path, &[from_outcome(&mirror, &outcome)]).unwrap();

    let tmp = target.path().join("tain.prom.tain-tmp~");
    assert!(!tmp.exists(), "tmp sidecar must not linger: {tmp:?}");

    let body = std::fs::read_to_string(&metrics_path).unwrap();
    assert!(body.ends_with('\n'), "textfile must end with newline");

    for name in [
        "tain_pool_files",
        "tain_pool_bytes",
        "tain_last_success_seconds",
        "tain_gc_deleted_files_total",
        "tain_gc_circuit_broken",
        "tain_sync_duration_seconds",
        "tain_pgp_verified",
    ] {
        assert!(
            body.contains(&format!("# TYPE {name} ")),
            "missing TYPE for {name}: {body}"
        );
    }

    let pool_files_line = body
        .lines()
        .find(|l| l.starts_with(r#"tain_pool_files{"#))
        .expect("no pool_files data line");
    assert!(pool_files_line.contains(r#"mirror="upstream""#));
    assert!(pool_files_line.contains(r#"backend="apt""#));
    let value: u64 = pool_files_line.rsplit(' ').next().unwrap().parse().unwrap();
    assert!(
        value >= 2,
        "expected at least the two synthetic .debs, got {value}"
    );

    let pb: u64 = body
        .lines()
        .find(|l| l.starts_with(r#"tain_pool_bytes{"#))
        .and_then(|l| l.rsplit(' ').next().and_then(|v| v.parse().ok()))
        .expect("pool_bytes parse");
    assert!(pb > 0);

    let dur: f64 = body
        .lines()
        .find(|l| l.starts_with(r#"tain_sync_duration_seconds{"#))
        .and_then(|l| l.rsplit(' ').next().and_then(|v| v.parse().ok()))
        .expect("duration parse");
    assert!(dur > 0.0);

    // last_success is the upstream Release Date (SyntheticRepo: Sat, 03 Feb 2024 09:15:38 UTC).
    let ls: i64 = body
        .lines()
        .find(|l| l.starts_with(r#"tain_last_success_seconds{"#))
        .and_then(|l| l.rsplit(' ').next().and_then(|v| v.parse().ok()))
        .expect("last_success parse");
    assert_eq!(ls, 1_706_951_738, "unexpected last_success_unix");

    // PGP verification is off by default: 0 = Skipped.
    let pgp_line = body
        .lines()
        .find(|l| l.starts_with(r#"tain_pgp_verified{"#))
        .expect("pgp line missing");
    assert!(pgp_line.contains(r#"suite="bookworm""#));
    assert!(pgp_line.ends_with(" 0"));
}

#[tokio::test]
async fn failed_sync_writes_metrics_without_last_success_line() {
    // Empty upstream: InRelease 404s.
    let serve_dir = TempDir::new("metrics-fail-serve");
    let server = StaticServer::spawn(serve_dir.path().to_path_buf()).await;

    let target = TempDir::new("metrics-fail-target");
    let global = build_global(target.path().to_path_buf());
    let mirror = build_mirror(&server.base_url(), "upstream");

    let outcome = sync_mirror(&global, &mirror, &global.target).await.unwrap();
    assert!(!outcome.is_success());
    assert!(outcome.suites_failed.contains(&"bookworm".to_owned()));

    let metrics_path = target.path().join("tain.prom");
    write_textfile(&metrics_path, &[from_outcome(&mirror, &outcome)]).unwrap();
    let body = std::fs::read_to_string(&metrics_path).unwrap();

    // The mirror row still renders, with zeros.
    assert!(body.contains(r#"tain_pool_files{mirror="upstream",backend="apt"} 0"#));
    assert!(
        !body
            .lines()
            .any(|l| l.starts_with(r#"tain_last_success_seconds{"#)),
        "should not emit last_success line when never synced: {body}"
    );
    // GC is skipped when a suite fails.
    assert!(
        !body
            .lines()
            .any(|l| l.starts_with(r#"tain_gc_deleted_files_total{"#)),
        "no gc line expected when a suite failed: {body}"
    );
    // The suite failed before PGP verification ran.
    assert!(
        !body.lines().any(|l| l.starts_with(r#"tain_pgp_verified{"#)),
        "no pgp line expected when suite failed pre-verify: {body}"
    );
}

#[tokio::test]
async fn write_textfile_creates_parent_directory() {
    // e.g. a node_exporter textfile dir that doesn't exist yet on a fresh install.
    let target = TempDir::new("metrics-mkdir");
    let path = target.path().join("nested/one/tain.prom");
    let sample = SyncMetrics {
        mirror: "any".to_owned(),
        backend: "apt".to_owned(),
        pool_files: 0,
        pool_bytes: 0,
        last_success_unix: None,
        gc: None,
        sync_duration_secs: 0.0,
        pgp_by_suite: vec![],
    };
    write_textfile(&path, &[sample]).unwrap();
    assert!(path.exists());
}
