//! Engine smoke test against a synthetic repo: full publish, state and
//! manifest written, unchanged upstream yields Unchanged.

use std::path::PathBuf;

use tain::config::model::{
    AptOptions, BackendKind, BackendOptions, GcConfig, GlobalConfig, I18nSelection, IndexSelection,
    MirrorConfig, VerifyConfig,
};
use tain::core::engine::sync_mirror;
use tain::core::store::{manifest, state};

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

#[tokio::test]
async fn syncs_synthetic_bookworm_end_to_end() {
    let serve_dir = TempDir::new("engine-serve");
    let _repo = SyntheticRepo::new(serve_dir.path().to_path_buf(), "bookworm")
        .add_package("nginx", b"fake nginx bytes".to_vec())
        .add_package("apt", b"fake apt bytes vary the bytes".to_vec())
        .write();
    let server = StaticServer::spawn(serve_dir.path().to_path_buf()).await;

    let target = TempDir::new("engine-target");
    let global = build_global(target.path().to_path_buf());
    let mirror = build_mirror(&server.base_url(), "upstream");

    let outcome = sync_mirror(&global, &mirror, &global.target).await.unwrap();
    assert!(
        outcome.is_success(),
        "first sync should succeed: {outcome:?}"
    );
    assert_eq!(outcome.suites_succeeded, vec!["bookworm".to_owned()]);
    assert!(outcome.suites_unchanged.is_empty());

    let mirror_root = target.path().join("upstream");

    let dists = mirror_root.join("dists/bookworm");
    assert!(dists.join("InRelease").exists(), "InRelease present");
    assert!(dists.join("Release").exists(), "Release present");
    assert!(
        dists.join("main/binary-amd64/Packages").exists(),
        "Packages index present"
    );

    let nginx = mirror_root.join("pool/main/n/nginx/nginx_1.0_amd64.deb");
    assert!(nginx.exists(), "pool file present");
    let nginx_bytes = std::fs::read(&nginx).unwrap();
    assert_eq!(nginx_bytes, b"fake nginx bytes");

    let st = state::load(&mirror_root).unwrap().unwrap();
    assert_eq!(st.generation, outcome.new_generation);
    assert!(st.suites.contains_key("bookworm"));
    let gens = manifest::list_generations(&mirror_root).unwrap();
    assert_eq!(gens, vec![outcome.new_generation]);

    let m = manifest::load(&mirror_root, outcome.new_generation).unwrap();
    assert!(
        m.files
            .iter()
            .any(|(k, _)| k.starts_with("pool/main/n/nginx/"))
    );
    assert!(m.files.iter().any(|(k, _)| k.ends_with("/InRelease")));
    assert!(m.files.iter().any(|(k, _)| k.ends_with("/Packages")));
}

#[tokio::test]
async fn second_run_is_unchanged() {
    let serve_dir = TempDir::new("engine-serve-noop");
    let _repo = SyntheticRepo::new(serve_dir.path().to_path_buf(), "bookworm")
        .add_package("nginx", b"fake nginx bytes".to_vec())
        .write();
    let server = StaticServer::spawn(serve_dir.path().to_path_buf()).await;

    let target = TempDir::new("engine-target-noop");
    let global = build_global(target.path().to_path_buf());
    let mirror = build_mirror(&server.base_url(), "upstream");

    let first = sync_mirror(&global, &mirror, &global.target).await.unwrap();
    assert!(first.is_success());
    let first_gen = first.new_generation;

    let second = sync_mirror(&global, &mirror, &global.target).await.unwrap();
    assert!(
        second.is_success(),
        "second sync should succeed cleanly: {second:?}"
    );
    assert_eq!(second.suites_unchanged, vec!["bookworm".to_owned()]);
    assert!(second.suites_succeeded.is_empty());
    assert_eq!(second.new_generation, first_gen);
}

#[tokio::test]
async fn missing_upstream_release_fails_cleanly() {
    let serve_dir = TempDir::new("engine-empty");
    let server = StaticServer::spawn(serve_dir.path().to_path_buf()).await;

    let target = TempDir::new("engine-target-empty");
    let global = build_global(target.path().to_path_buf());
    let mirror = build_mirror(&server.base_url(), "upstream");

    let outcome = sync_mirror(&global, &mirror, &global.target).await.unwrap();
    assert!(!outcome.is_success());
    assert_eq!(outcome.suites_failed, vec!["bookworm".to_owned()]);
    assert!(
        state::load(&target.path().join("upstream"))
            .unwrap()
            .is_none()
    );
}
