//! Suite shapes end to end: slash suites, Suite -> Codename symlinks,
//! Release fallback without InRelease.

use std::path::PathBuf;

use tain::config::model::{
    AptOptions, BackendKind, BackendOptions, GcConfig, GlobalConfig, I18nSelection, IndexSelection,
    MirrorConfig, VerifyConfig,
};
use tain::core::engine::sync_mirror;

mod common;
use common::{PackagesVariantKind, StaticServer, SyntheticRepo, TempDir};

fn build_mirror(base_url: &url::Url, suites: Vec<String>, create_symlinks: bool) -> MirrorConfig {
    let apt = AptOptions {
        suites,
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
        create_suite_symlinks: create_symlinks,
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

fn build_global(target_root: PathBuf) -> GlobalConfig {
    GlobalConfig {
        target: target_root,
        parallel: 4,
        host_connections: 2,
        ..GlobalConfig::default()
    }
}

/// Slash suites like `stable/updates` publish to a nested dists dir.
#[tokio::test]
async fn slash_suite_publishes_to_nested_dir() {
    let serve = TempDir::new("slash-serve");
    SyntheticRepo::new(serve.path().to_path_buf(), "stable/updates")
        .add_package("nginx", b"nginx bytes".to_vec())
        .with_compressed_variant(PackagesVariantKind::Xz)
        .write();
    let server = StaticServer::spawn(serve.path().to_path_buf()).await;
    let target = TempDir::new("slash-target");
    let global = build_global(target.path().to_path_buf());
    let mirror = build_mirror(&server.base_url(), vec!["stable/updates".to_owned()], false);

    let outcome = sync_mirror(&global, &mirror, &global.target).await.unwrap();
    assert!(outcome.is_success(), "{outcome:?}");
    let dist = target
        .path()
        .join("upstream/dists/stable/updates/main/binary-amd64");
    assert!(dist.join("Packages.xz").exists(), "nested dist path exists");
    assert!(
        target
            .path()
            .join("upstream/pool/main/n/nginx/nginx_1.0_amd64.deb")
            .exists(),
    );
}

/// Syncing `trixie` whose Release says `Suite: stable` creates `dists/stable -> trixie`.
#[cfg(unix)]
#[tokio::test]
async fn suite_symlink_created_when_flag_on() {
    let serve = TempDir::new("sym-serve");
    SyntheticRepo::new(serve.path().to_path_buf(), "trixie")
        .add_package("nginx", b"nginx bytes".to_vec())
        .with_compressed_variant(PackagesVariantKind::Xz)
        .with_suite_alias("stable")
        .write();
    let server = StaticServer::spawn(serve.path().to_path_buf()).await;
    let target = TempDir::new("sym-target");
    let global = build_global(target.path().to_path_buf());
    let mirror = build_mirror(&server.base_url(), vec!["trixie".to_owned()], true);

    let outcome = sync_mirror(&global, &mirror, &global.target).await.unwrap();
    assert!(outcome.is_success(), "{outcome:?}");

    let link = target.path().join("upstream/dists/stable");
    let meta = std::fs::symlink_metadata(&link).unwrap();
    assert!(meta.file_type().is_symlink(), "stable must be a symlink");
    let target_str = std::fs::read_link(&link).unwrap();
    assert_eq!(target_str, PathBuf::from("trixie"));

    assert!(
        target
            .path()
            .join("upstream/dists/stable/main/binary-amd64/Packages.xz")
            .exists()
    );
}

/// Upstream without InRelease: fall back to Release (+ optional Release.gpg)
/// and publish it verbatim.
#[tokio::test]
async fn sync_falls_back_to_release_when_inrelease_is_absent() {
    let serve = TempDir::new("release-fallback-serve");
    SyntheticRepo::new(serve.path().to_path_buf(), "bookworm")
        .add_package("nginx", b"nginx bytes".to_vec())
        .with_compressed_variant(PackagesVariantKind::Xz)
        .write();
    std::fs::remove_file(serve.path().join("dists/bookworm/InRelease")).unwrap();

    let server = StaticServer::spawn(serve.path().to_path_buf()).await;
    let target = TempDir::new("release-fallback-target");
    let global = build_global(target.path().to_path_buf());
    let mirror = build_mirror(&server.base_url(), vec!["bookworm".to_owned()], false);

    let outcome = sync_mirror(&global, &mirror, &global.target).await.unwrap();
    assert!(
        outcome.is_success(),
        "sync must succeed via Release fallback: {outcome:?}"
    );

    let mirror_root = target.path().join("upstream");
    assert!(mirror_root.join("dists/bookworm/Release").exists());
    assert!(!mirror_root.join("dists/bookworm/InRelease").exists());
    assert!(
        mirror_root
            .join("pool/main/n/nginx/nginx_1.0_amd64.deb")
            .exists(),
        "pool file must land via fallback path"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn suite_symlink_skipped_when_flag_off() {
    let serve = TempDir::new("nosym-serve");
    SyntheticRepo::new(serve.path().to_path_buf(), "trixie")
        .add_package("nginx", b"nginx bytes".to_vec())
        .with_compressed_variant(PackagesVariantKind::Xz)
        .with_suite_alias("stable")
        .write();
    let server = StaticServer::spawn(serve.path().to_path_buf()).await;
    let target = TempDir::new("nosym-target");
    let global = build_global(target.path().to_path_buf());
    let mirror = build_mirror(&server.base_url(), vec!["trixie".to_owned()], false);

    let outcome = sync_mirror(&global, &mirror, &global.target).await.unwrap();
    assert!(outcome.is_success(), "{outcome:?}");

    let link = target.path().join("upstream/dists/stable");
    assert!(
        !link.exists() && std::fs::symlink_metadata(&link).is_err(),
        "no symlink expected when create_suite_symlinks = false"
    );
}
