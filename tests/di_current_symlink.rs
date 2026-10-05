//! debian-installer sync: SHA256SUMS and its images published verbatim,
//! `current` symlink to the max version, hash mismatch fails the suite.
//! Uses its own repo builder; `common::SyntheticRepo` is Packages-only.

use std::path::PathBuf;

use sha2::{Digest, Sha256, Sha512};
use tain::config::model::{
    AptOptions, BackendKind, BackendOptions, GcConfig, GlobalConfig, I18nSelection, IndexSelection,
    MirrorConfig, VerifyConfig,
};
use tain::core::engine::sync_mirror;

mod common;
use common::{StaticServer, TempDir};

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0F) as usize] as char);
    }
    out
}

struct DiImage {
    /// Path relative to `images/` (goes into SHA256SUMS as `./<path>`).
    rel_path: String,
    bytes: Vec<u8>,
}

/// Synthetic d-i repo: images, their SHA256SUMS, and an unsigned Release/InRelease.
struct DiRepo {
    root: PathBuf,
    suite: String,
    component: String,
    arch: String,
    version: String,
    images: Vec<DiImage>,
    /// Path whose SHA256SUMS entry gets a bogus hash.
    tamper_hash_for: Option<String>,
}

impl DiRepo {
    fn new(root: PathBuf) -> Self {
        Self {
            root,
            suite: "trixie".to_owned(),
            component: "main".to_owned(),
            arch: "amd64".to_owned(),
            version: "20250803+deb13u5".to_owned(),
            images: Vec::new(),
            tamper_hash_for: None,
        }
    }

    fn add_image(mut self, rel_path: impl Into<String>, bytes: Vec<u8>) -> Self {
        self.images.push(DiImage {
            rel_path: rel_path.into(),
            bytes,
        });
        self
    }

    fn tamper_sha256sums_for(mut self, rel_path: impl Into<String>) -> Self {
        self.tamper_hash_for = Some(rel_path.into());
        self
    }

    fn images_dir_rel(&self) -> String {
        format!(
            "{comp}/installer-{arch}/{ver}/images",
            comp = self.component,
            arch = self.arch,
            ver = self.version,
        )
    }

    fn write(self) -> Self {
        let dists_dir = self.root.join(format!("dists/{}", self.suite));
        let images_rel = self.images_dir_rel();
        let images_dir = dists_dir.join(&images_rel);
        std::fs::create_dir_all(&images_dir).unwrap();

        for img in &self.images {
            let p = images_dir.join(&img.rel_path);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(&p, &img.bytes).unwrap();
        }

        // GNU coreutils format: `<hex>  ./<path>`.
        let mut sums = String::new();
        for img in &self.images {
            let hex = if self
                .tamper_hash_for
                .as_deref()
                .is_some_and(|p| p == img.rel_path)
            {
                "0".repeat(64)
            } else {
                hex_encode(&Sha256::digest(&img.bytes))
            };
            sums.push_str(&format!("{hex}  ./{}\n", img.rel_path));
        }
        let sums_bytes = sums.into_bytes();
        std::fs::write(images_dir.join("SHA256SUMS"), &sums_bytes).unwrap();

        let sha256_line = format!(
            " {} {} {}/SHA256SUMS\n",
            hex_encode(&Sha256::digest(&sums_bytes)),
            sums_bytes.len(),
            images_rel,
        );
        let sha512_line = format!(
            " {} {} {}/SHA256SUMS\n",
            hex_encode(&Sha512::digest(&sums_bytes)),
            sums_bytes.len(),
            images_rel,
        );
        // Empty Packages: a Packages group must land at least one variant.
        let packages_body = b"";
        let bin_dir = dists_dir.join(format!("{}/binary-{}", self.component, self.arch));
        std::fs::create_dir_all(&bin_dir).unwrap();
        std::fs::write(bin_dir.join("Packages"), packages_body).unwrap();
        let packages_sha256 = format!(
            " {} {} {}/binary-{}/Packages\n",
            hex_encode(&Sha256::digest(packages_body)),
            packages_body.len(),
            self.component,
            self.arch,
        );
        let packages_sha512 = format!(
            " {} {} {}/binary-{}/Packages\n",
            hex_encode(&Sha512::digest(packages_body)),
            packages_body.len(),
            self.component,
            self.arch,
        );
        let release = format!(
            "Suite: {suite}\n\
             Codename: {suite}\n\
             Architectures: {arch}\n\
             Components: {comp}\n\
             Date: Sat, 03 Feb 2024 09:15:38 UTC\n\
             SHA256:\n{sha256_a}{sha256_b}\
             SHA512:\n{sha512_a}{sha512_b}",
            suite = self.suite,
            arch = self.arch,
            comp = self.component,
            sha256_a = packages_sha256,
            sha256_b = sha256_line,
            sha512_a = packages_sha512,
            sha512_b = sha512_line,
        );
        std::fs::write(dists_dir.join("Release"), release.as_bytes()).unwrap();
        std::fs::write(dists_dir.join("InRelease"), release.as_bytes()).unwrap();

        self
    }
}

fn build_mirror(base_url: &url::Url, name: &str) -> MirrorConfig {
    let apt = AptOptions {
        suites: vec!["trixie".to_owned()],
        components: vec!["main".to_owned()],
        architectures: vec!["amd64".to_owned()],
        indexes: IndexSelection {
            packages: true,
            contents: false,
            i18n: I18nSelection::None,
            dep11: false,
            cnf: false,
            sources: false,
            debian_installer: true,
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

/// Happy path. Also guards debmirror LP#1550852: SHA256SUMS itself must be published.
#[tokio::test]
async fn syncs_full_di_tree_with_current_symlink() {
    let serve_dir = TempDir::new("di-e2e-serve");
    let _repo = DiRepo::new(serve_dir.path().to_path_buf())
        .add_image("netboot/mini.iso", b"mini iso body content".to_vec())
        .add_image("cdrom/initrd.gz", b"initrd content".to_vec())
        .add_image("boot.img.gz", b"boot img content".to_vec())
        .write();
    let server = StaticServer::spawn(serve_dir.path().to_path_buf()).await;

    let target = TempDir::new("di-e2e-target");
    let global = build_global(target.path().to_path_buf());
    let mirror = build_mirror(&server.base_url(), "di");
    let outcome = sync_mirror(&global, &mirror, &global.target).await.unwrap();
    assert!(outcome.is_success(), "di sync should succeed: {outcome:?}");
    assert_eq!(outcome.suites_succeeded, vec!["trixie".to_owned()]);

    let mirror_root = target.path().join("di");
    let images = mirror_root.join("dists/trixie/main/installer-amd64/20250803+deb13u5/images");

    assert!(
        images.join("SHA256SUMS").exists(),
        "SHA256SUMS itself must be published (LP#1550852 regression guard)"
    );
    let sums_bytes = std::fs::read(images.join("SHA256SUMS")).unwrap();
    assert!(sums_bytes.contains(&b'\n'), "SHA256SUMS is text");

    for (rel, expected) in [
        ("netboot/mini.iso", b"mini iso body content" as &[u8]),
        ("cdrom/initrd.gz", b"initrd content" as &[u8]),
        ("boot.img.gz", b"boot img content" as &[u8]),
    ] {
        let p = images.join(rel);
        assert!(p.exists(), "image {rel} must be published");
        let got = std::fs::read(&p).unwrap();
        assert_eq!(got, expected, "image {rel} bytes match upstream");
    }

    let current = mirror_root.join("dists/trixie/main/installer-amd64/current");
    let meta = std::fs::symlink_metadata(&current).unwrap();
    assert!(meta.file_type().is_symlink(), "current is a symlink");
    let target_link = std::fs::read_link(&current).unwrap();
    assert_eq!(target_link, PathBuf::from("20250803+deb13u5"));

    // Published-index closure: manifest covers SHA256SUMS and images.
    let m = tain::core::store::manifest::load(&mirror_root, outcome.new_generation).unwrap();
    assert!(
        m.files.keys().any(|k| k.ends_with("/SHA256SUMS")),
        "manifest records SHA256SUMS"
    );
    assert!(
        m.files.keys().any(|k| k.ends_with("/netboot/mini.iso")),
        "manifest records image files"
    );
}

/// An image whose bytes mismatch SHA256SUMS fails the suite; nothing is published.
#[tokio::test]
async fn tampered_image_hash_fails_the_suite() {
    let serve_dir = TempDir::new("di-tamper-serve");
    let _repo = DiRepo::new(serve_dir.path().to_path_buf())
        .add_image("netboot/mini.iso", b"legitimate bytes".to_vec())
        .tamper_sha256sums_for("netboot/mini.iso")
        .write();
    let server = StaticServer::spawn(serve_dir.path().to_path_buf()).await;

    let target = TempDir::new("di-tamper-target");
    let global = build_global(target.path().to_path_buf());
    let mirror = build_mirror(&server.base_url(), "di");
    let outcome = sync_mirror(&global, &mirror, &global.target).await.unwrap();

    assert!(!outcome.is_success(), "tampered sync must fail");
    assert_eq!(outcome.suites_failed, vec!["trixie".to_owned()]);

    let mirror_root = target.path().join("di");
    assert!(
        !mirror_root
            .join("dists/trixie/main/installer-amd64/20250803+deb13u5")
            .exists(),
        "no version dir when the suite failed"
    );
    assert!(
        !mirror_root
            .join("dists/trixie/main/installer-amd64/current")
            .exists(),
        "no current symlink when the suite failed"
    );
}

/// With several version dirs, the max must win the lex sort `current` relies on.
#[test]
fn current_symlink_prefers_max_version_across_generations() {
    let dist = TempDir::new("di-multi-ver");
    let installer_dir = dist.path().join("main/installer-amd64");
    std::fs::create_dir_all(installer_dir.join("20250803")).unwrap();
    std::fs::create_dir_all(installer_dir.join("20250803+deb13u5")).unwrap();
    std::fs::create_dir_all(installer_dir.join("20250901")).unwrap();

    // `rebuild` is pub(super) (covered via sync above); pin the sort order here.
    let mut names: Vec<String> = std::fs::read_dir(&installer_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert_eq!(names.last().unwrap(), "20250901");

    // Same date with a suffix.
    let installer_dir2 = dist.path().join("contrib/installer-amd64");
    std::fs::create_dir_all(installer_dir2.join("20250803")).unwrap();
    std::fs::create_dir_all(installer_dir2.join("20250803+deb13u5")).unwrap();
    let mut names2: Vec<String> = std::fs::read_dir(&installer_dir2)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    names2.sort();
    assert_eq!(names2.last().unwrap(), "20250803+deb13u5");
}
