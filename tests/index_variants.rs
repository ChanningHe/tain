//! Index variants end to end: every compressed Packages variant, legacy
//! `binary-<arch>/Release`, in-suite pool files, and by-hash across swaps.

use std::path::PathBuf;

use tain::config::model::{
    AptOptions, BackendKind, BackendOptions, GcConfig, GlobalConfig, I18nSelection, IndexSelection,
    MirrorConfig, VerifyConfig,
};
use tain::core::engine::sync_mirror;

mod common;
use common::{PackagesVariantKind, StaticServer, SyntheticRepo, TempDir};

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
async fn syncs_all_advertised_compression_variants() {
    let serve = TempDir::new("var-serve-all");
    SyntheticRepo::new(serve.path().to_path_buf(), "bookworm")
        .add_package("nginx", b"fake nginx".to_vec())
        .with_compressed_variant(PackagesVariantKind::Xz)
        .with_compressed_variant(PackagesVariantKind::Gz)
        .with_compressed_variant(PackagesVariantKind::Bz2)
        .write();
    let server = StaticServer::spawn(serve.path().to_path_buf()).await;
    let target = TempDir::new("var-target-all");
    let global = build_global(target.path().to_path_buf());
    let mirror = build_mirror(&server.base_url(), "upstream");

    let outcome = sync_mirror(&global, &mirror, &global.target).await.unwrap();
    assert!(outcome.is_success(), "{outcome:?}");

    let bin = target
        .path()
        .join("upstream/dists/bookworm/main/binary-amd64");
    assert!(
        bin.join("Packages").exists(),
        "uncompressed Packages served"
    );
    assert!(bin.join("Packages.xz").exists(), "xz served");
    assert!(bin.join("Packages.gz").exists(), "gz served");
    assert!(bin.join("Packages.bz2").exists(), "bz2 served");

    assert!(
        target
            .path()
            .join("upstream/pool/main/n/nginx/nginx_1.0_amd64.deb")
            .exists(),
    );
}

#[tokio::test]
async fn tolerates_uncompressed_packages_listed_but_not_served() {
    // Release lists `Packages` but only `Packages.xz` is served.
    let serve = TempDir::new("var-serve-nou");
    SyntheticRepo::new(serve.path().to_path_buf(), "bookworm")
        .add_package("nginx", b"fake nginx".to_vec())
        .with_compressed_variant(PackagesVariantKind::Xz)
        .without_uncompressed_packages()
        .write();
    let server = StaticServer::spawn(serve.path().to_path_buf()).await;
    let target = TempDir::new("var-target-nou");
    let global = build_global(target.path().to_path_buf());
    let mirror = build_mirror(&server.base_url(), "upstream");

    let outcome = sync_mirror(&global, &mirror, &global.target).await.unwrap();
    assert!(
        outcome.is_success(),
        "sync must succeed when a 404 hides a checksum-listed uncompressed variant: {outcome:?}"
    );

    let bin = target
        .path()
        .join("upstream/dists/bookworm/main/binary-amd64");
    assert!(bin.join("Packages.xz").exists());
    assert!(!bin.join("Packages").exists(), "uncompressed never staged");
    assert!(
        target
            .path()
            .join("upstream/pool/main/n/nginx/nginx_1.0_amd64.deb")
            .exists(),
    );
}

#[tokio::test]
async fn parses_pool_set_from_gz_when_xz_missing() {
    let serve = TempDir::new("var-serve-gz");
    SyntheticRepo::new(serve.path().to_path_buf(), "bookworm")
        .add_package("gzpkg", b"gz body bytes".to_vec())
        .with_compressed_variant(PackagesVariantKind::Gz)
        .without_uncompressed_packages()
        .write();
    let server = StaticServer::spawn(serve.path().to_path_buf()).await;
    let target = TempDir::new("var-target-gz");
    let global = build_global(target.path().to_path_buf());
    let mirror = build_mirror(&server.base_url(), "upstream");

    let outcome = sync_mirror(&global, &mirror, &global.target).await.unwrap();
    assert!(outcome.is_success(), "{outcome:?}");

    let bin = target
        .path()
        .join("upstream/dists/bookworm/main/binary-amd64");
    assert!(bin.join("Packages.gz").exists());
    assert!(
        target
            .path()
            .join("upstream/pool/main/g/gzpkg/gzpkg_1.0_amd64.deb")
            .exists(),
    );
}

#[tokio::test]
async fn parses_pool_set_from_bz2() {
    let serve = TempDir::new("var-serve-bz2");
    SyntheticRepo::new(serve.path().to_path_buf(), "bookworm")
        .add_package("bzpkg", b"bz body bytes".to_vec())
        .with_compressed_variant(PackagesVariantKind::Bz2)
        .without_uncompressed_packages()
        .write();
    let server = StaticServer::spawn(serve.path().to_path_buf()).await;
    let target = TempDir::new("var-target-bz2");
    let global = build_global(target.path().to_path_buf());
    let mirror = build_mirror(&server.base_url(), "upstream");

    let outcome = sync_mirror(&global, &mirror, &global.target).await.unwrap();
    assert!(outcome.is_success(), "{outcome:?}");

    let bin = target
        .path()
        .join("upstream/dists/bookworm/main/binary-amd64");
    assert!(bin.join("Packages.bz2").exists());
    assert!(
        target
            .path()
            .join("upstream/pool/main/b/bzpkg/bzpkg_1.0_amd64.deb")
            .exists(),
    );
}

/// Proxmox-style `Filename` inside `dists/<suite>/`: such files must go through
/// staging, or the atomic swap leaves them on the old side and clients 404.
#[tokio::test]
async fn pool_files_inside_suite_survive_atomic_swap() {
    let serve = TempDir::new("insuite-serve");
    SyntheticRepo::new(serve.path().to_path_buf(), "bookworm")
        .add_package_in_suite("proxmox-fake", b"pkg body inside suite".to_vec())
        .with_compressed_variant(PackagesVariantKind::Xz)
        .write();
    let server = StaticServer::spawn(serve.path().to_path_buf()).await;

    let target = TempDir::new("insuite-target");
    let global = build_global(target.path().to_path_buf());
    let mirror = build_mirror(&server.base_url(), "upstream");

    let outcome = sync_mirror(&global, &mirror, &global.target).await.unwrap();
    assert!(outcome.is_success(), "{outcome:?}");

    let deb = target
        .path()
        .join("upstream/dists/bookworm/main/binary-amd64/proxmox-fake_1.0_amd64.deb");
    assert!(
        deb.exists(),
        "pool file at Filename must be visible AFTER the swap"
    );
    let bytes = std::fs::read(&deb).unwrap();
    assert_eq!(bytes, b"pkg body inside suite");
}

/// After a second publish, by-hash serves both the previous and current
/// Packages.xz, so a client holding the old InRelease gets no Hash Sum Mismatch.
#[tokio::test]
async fn by_hash_survives_generation_swap_zero_hash_mismatch() {
    use sha2::{Digest as _, Sha256};

    let target = TempDir::new("race-target");
    let global = build_global(target.path().to_path_buf());

    let serve1 = TempDir::new("race-serve1");
    SyntheticRepo::new(serve1.path().to_path_buf(), "bookworm")
        .add_package("nginx", b"nginx v1 bytes".to_vec())
        .with_compressed_variant(PackagesVariantKind::Xz)
        .write();
    let server1 = StaticServer::spawn(serve1.path().to_path_buf()).await;
    let mirror1 = build_mirror(&server1.base_url(), "upstream");

    sync_mirror(&global, &mirror1, &global.target)
        .await
        .unwrap();
    let bin = target
        .path()
        .join("upstream/dists/bookworm/main/binary-amd64");
    let gen1_xz = std::fs::read(bin.join("Packages.xz")).unwrap();
    let gen1_hex = hex_encode(&Sha256::digest(&gen1_xz));
    drop(server1);

    let serve2 = TempDir::new("race-serve2");
    SyntheticRepo::new(serve2.path().to_path_buf(), "bookworm")
        .add_package("nginx", b"nginx v2 bytes".to_vec())
        .add_package("curl", b"curl v1 bytes".to_vec())
        .with_compressed_variant(PackagesVariantKind::Xz)
        .write();
    let server2 = StaticServer::spawn(serve2.path().to_path_buf()).await;
    let mirror2 = build_mirror(&server2.base_url(), "upstream");

    sync_mirror(&global, &mirror2, &global.target)
        .await
        .unwrap();
    let gen2_xz = std::fs::read(bin.join("Packages.xz")).unwrap();
    let gen2_hex = hex_encode(&Sha256::digest(&gen2_xz));
    assert_ne!(
        gen1_hex, gen2_hex,
        "different content must hash differently"
    );

    let sha256_dir = bin.join("by-hash/SHA256");
    let gen2_link = sha256_dir.join(&gen2_hex);
    let gen1_link = sha256_dir.join(&gen1_hex);
    assert!(
        gen2_link.exists(),
        "current gen's by-hash SHA256 must exist"
    );
    assert!(
        gen1_link.exists(),
        "prior gen's by-hash SHA256 must survive the swap (zero Hash Sum Mismatch invariant)"
    );

    assert_eq!(std::fs::read(&gen1_link).unwrap(), gen1_xz);
    assert_eq!(std::fs::read(&gen2_link).unwrap(), gen2_xz);
}

/// Every published index has a `by-hash/SHA256/<hex>` link to the same bytes.
#[tokio::test]
async fn publish_writes_by_hash_hardlinks_for_indexes() {
    use sha2::{Digest as _, Sha256};
    let serve = TempDir::new("byhash-serve");
    SyntheticRepo::new(serve.path().to_path_buf(), "bookworm")
        .add_package("nginx", b"nginx bytes".to_vec())
        .with_compressed_variant(PackagesVariantKind::Xz)
        .write();
    let server = StaticServer::spawn(serve.path().to_path_buf()).await;

    let target = TempDir::new("byhash-target");
    let global = build_global(target.path().to_path_buf());
    let mirror = build_mirror(&server.base_url(), "upstream");

    let outcome = sync_mirror(&global, &mirror, &global.target).await.unwrap();
    assert!(outcome.is_success(), "{outcome:?}");

    let bin = target
        .path()
        .join("upstream/dists/bookworm/main/binary-amd64");
    let by_hash = bin.join("by-hash");
    assert!(by_hash.exists(), "by-hash dir must exist");
    let sha256_dir = by_hash.join("SHA256");
    assert!(sha256_dir.exists(), "SHA256 by-hash dir must exist");

    for variant in ["Packages", "Packages.xz"] {
        let file = bin.join(variant);
        if !file.exists() {
            continue;
        }
        let bytes = std::fs::read(&file).unwrap();
        let hex = hex_encode(&Sha256::digest(&bytes));
        let link = sha256_dir.join(&hex);
        assert!(link.exists(), "SHA256/{hex} link for {variant} missing");
        assert_eq!(std::fs::read(&link).unwrap(), bytes);
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0F) as usize] as char);
    }
    out
}

#[tokio::test]
async fn stages_legacy_binary_arch_release() {
    let serve = TempDir::new("var-serve-legacy");
    SyntheticRepo::new(serve.path().to_path_buf(), "bookworm")
        .add_package("nginx", b"fake nginx".to_vec())
        .with_compressed_variant(PackagesVariantKind::Xz)
        .with_legacy_binary_release()
        .write();
    let server = StaticServer::spawn(serve.path().to_path_buf()).await;
    let target = TempDir::new("var-target-legacy");
    let global = build_global(target.path().to_path_buf());
    let mirror = build_mirror(&server.base_url(), "upstream");

    let outcome = sync_mirror(&global, &mirror, &global.target).await.unwrap();
    assert!(outcome.is_success(), "{outcome:?}");

    let legacy = target
        .path()
        .join("upstream/dists/bookworm/main/binary-amd64/Release");
    assert!(
        legacy.exists(),
        "legacy binary-<arch>/Release is checksum-block-driven and must ship"
    );

    let bytes = std::fs::read(&legacy).unwrap();
    let head = std::str::from_utf8(&bytes[..bytes.len().min(64)]).unwrap();
    assert!(head.starts_with("Archive:"), "byte-verbatim legacy body");
}
