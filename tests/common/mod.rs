//! Shared test harness: `StaticServer` (axum file server on a random port,
//! stops on drop) and `SyntheticRepo` (minimal on-disk APT repo with
//! matching checksums). Fault-injection tests mutate files after setup.

#![allow(dead_code)]

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::Router;
use sha2::{Digest, Sha256, Sha512};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tower_http::services::ServeDir;

// ---------- TempDir ----------

/// Minimal tempdir; avoids pulling in `tempfile`.
pub struct TempDir {
    path: PathBuf,
}

impl TempDir {
    #[must_use]
    pub fn new(prefix: &str) -> Self {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        let path = std::env::temp_dir().join(format!("tain-{prefix}-{pid}-{n}"));
        std::fs::create_dir_all(&path).expect("mktempdir");
        Self { path }
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

// ---------- StaticServer ----------

/// Serve a directory tree over HTTP on a random port.
pub struct StaticServer {
    addr: SocketAddr,
    handle: Option<JoinHandle<()>>,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    _root: Arc<PathBuf>,
}

impl StaticServer {
    /// Spawn on `127.0.0.1:0` and return once the socket is bound.
    pub async fn spawn(root: PathBuf) -> Self {
        let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .expect("bind 127.0.0.1:0");
        let addr = listener.local_addr().expect("local_addr");

        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let root_arc = Arc::new(root);
        let root_for_service = Arc::clone(&root_arc);
        let router: Router =
            Router::new().fallback_service(ServeDir::new(root_for_service.as_ref()));

        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, router)
                .with_graceful_shutdown(async move {
                    let _ = shutdown_rx.await;
                })
                .await;
        });

        Self {
            addr,
            handle: Some(handle),
            shutdown: Some(shutdown_tx),
            _root: root_arc,
        }
    }

    #[must_use]
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    #[must_use]
    pub fn base_url(&self) -> url::Url {
        url::Url::parse(&format!("http://{}/", self.addr)).expect("valid URL")
    }

    /// Stop and wait for the server task; tests normally just drop it.
    pub async fn shutdown(mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(h) = self.handle.take() {
            let _ = h.await;
        }
    }
}

impl Drop for StaticServer {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
    }
}

// ---------- SyntheticRepo ----------

/// A minimal APT repository on disk:
///
/// ```text
/// <root>/
///   dists/<suite>/InRelease   (unsigned copy of Release)
///   dists/<suite>/Release
///   dists/<suite>/main/binary-amd64/Packages
///   pool/main/n/nginx/<pkgfile>.deb
/// ```
pub struct SyntheticRepo {
    root: PathBuf,
    suite: String,
    packages: Vec<Package>,
    /// Compressed Packages variants to write and list in Release.
    packages_variants: Vec<PackagesVariantKind>,
    /// When false, `Packages` is listed in Release but not served.
    write_uncompressed_packages: bool,
    /// Emit the legacy per-arch `main/binary-amd64/Release`.
    legacy_binary_release: bool,
    codename_override: Option<String>,
    suite_alias: Option<String>,
}

#[derive(Clone, Copy, Debug)]
pub enum PackagesVariantKind {
    Xz,
    Gz,
    Bz2,
}

impl PackagesVariantKind {
    fn suffix(self) -> &'static str {
        match self {
            Self::Xz => ".xz",
            Self::Gz => ".gz",
            Self::Bz2 => ".bz2",
        }
    }
    fn encode(self, plain: &[u8]) -> Vec<u8> {
        use std::io::Write;
        match self {
            Self::Xz => {
                let mut w = xz2::write::XzEncoder::new(Vec::new(), 3);
                w.write_all(plain).unwrap();
                w.finish().unwrap()
            }
            Self::Gz => {
                let mut w =
                    flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
                w.write_all(plain).unwrap();
                w.finish().unwrap()
            }
            Self::Bz2 => {
                let mut w = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::default());
                w.write_all(plain).unwrap();
                w.finish().unwrap()
            }
        }
    }
}

pub struct Package {
    pub name: String,
    pub filename: String,
    pub bytes: Vec<u8>,
}

impl SyntheticRepo {
    #[must_use]
    pub fn new(root: PathBuf, suite: impl Into<String>) -> Self {
        Self {
            root,
            suite: suite.into(),
            packages: Vec::new(),
            packages_variants: Vec::new(),
            write_uncompressed_packages: true,
            legacy_binary_release: false,
            codename_override: None,
            suite_alias: None,
        }
    }

    /// Add a `.deb` (fake bytes) at `pool/main/n/<name>/<filename>`.
    #[must_use]
    pub fn add_package(mut self, name: impl Into<String>, bytes: Vec<u8>) -> Self {
        let name = name.into();
        let letter = name.chars().next().unwrap_or('x');
        let filename = format!("pool/main/{letter}/{name}/{name}_1.0_amd64.deb");
        self.packages.push(Package {
            name,
            filename,
            bytes,
        });
        self
    }

    /// Add a `.deb` inside the suite directory (Proxmox-style layout); such
    /// pool files must be staged to survive the atomic swap.
    #[must_use]
    pub fn add_package_in_suite(mut self, name: impl Into<String>, bytes: Vec<u8>) -> Self {
        let name = name.into();
        let filename = format!(
            "dists/{}/main/binary-amd64/{}_1.0_amd64.deb",
            self.suite, name
        );
        self.packages.push(Package {
            name,
            filename,
            bytes,
        });
        self
    }

    /// Also write a compressed `Packages<suffix>` and list it in Release.
    #[must_use]
    pub fn with_compressed_variant(mut self, kind: PackagesVariantKind) -> Self {
        self.packages_variants.push(kind);
        self
    }

    /// List the uncompressed `Packages` in Release without serving it.
    #[must_use]
    pub fn without_uncompressed_packages(mut self) -> Self {
        self.write_uncompressed_packages = false;
        self
    }

    /// `Suite:` header value (defaults to the synced suite); differing from
    /// the codename exercises the Suite/Codename symlink path.
    #[must_use]
    pub fn with_suite_alias(mut self, suite_name: impl Into<String>) -> Self {
        self.suite_alias = Some(suite_name.into());
        self
    }

    /// Also emit an empty `main/binary-amd64/Release` legacy file.
    #[must_use]
    pub fn with_legacy_binary_release(mut self) -> Self {
        self.legacy_binary_release = true;
        self
    }

    /// Write every file to disk.
    pub fn write(self) -> Self {
        for pkg in &self.packages {
            let pool = self.root.join(&pkg.filename);
            std::fs::create_dir_all(pool.parent().unwrap()).unwrap();
            std::fs::write(&pool, &pkg.bytes).unwrap();
        }

        let packages_body = self.packages_index_body();
        let dists_dir = self.root.join(format!("dists/{}", self.suite));
        let bin_dir = dists_dir.join("main/binary-amd64");
        std::fs::create_dir_all(&bin_dir).unwrap();

        if self.write_uncompressed_packages {
            std::fs::write(bin_dir.join("Packages"), &packages_body).unwrap();
        }

        let mut variant_bodies: Vec<(PackagesVariantKind, Vec<u8>)> = Vec::new();
        for kind in &self.packages_variants {
            let compressed = kind.encode(&packages_body);
            let path = bin_dir.join(format!("Packages{}", kind.suffix()));
            std::fs::write(&path, &compressed).unwrap();
            variant_bodies.push((*kind, compressed));
        }

        let legacy_release_body = if self.legacy_binary_release {
            let body = format!(
                "Archive: {suite}\nComponent: main\nOrigin: SyntheticRepo\nLabel: Synth\nArchitecture: amd64\n",
                suite = self.suite,
            )
            .into_bytes();
            std::fs::write(bin_dir.join("Release"), &body).unwrap();
            Some(body)
        } else {
            None
        };

        let release_body = self.release_body(
            &packages_body,
            &variant_bodies,
            legacy_release_body.as_deref(),
        );
        std::fs::write(dists_dir.join("Release"), &release_body).unwrap();
        std::fs::write(dists_dir.join("InRelease"), &release_body).unwrap();

        self
    }

    fn packages_index_body(&self) -> Vec<u8> {
        let mut out = String::new();
        for pkg in &self.packages {
            let sha256 = hex_encode(&Sha256::digest(&pkg.bytes));
            let sha512 = hex_encode(&Sha512::digest(&pkg.bytes));
            out.push_str(&format!(
                "Package: {}\nVersion: 1.0\nArchitecture: amd64\nFilename: {}\nSize: {}\nSHA256: {}\nSHA512: {}\n\n",
                pkg.name,
                pkg.filename,
                pkg.bytes.len(),
                sha256,
                sha512,
            ));
        }
        out.into_bytes()
    }

    /// Codename to advertise in Release (defaults to the suite).
    #[must_use]
    pub fn with_codename(mut self, codename: impl Into<String>) -> Self {
        self.codename_override = Some(codename.into());
        self
    }

    fn release_body(
        &self,
        packages_body: &[u8],
        variants: &[(PackagesVariantKind, Vec<u8>)],
        legacy_release_body: Option<&[u8]>,
    ) -> Vec<u8> {
        let mut entries: Vec<(String, Vec<u8>)> = Vec::new();
        // Listed even when not served.
        entries.push((
            "main/binary-amd64/Packages".to_owned(),
            packages_body.to_vec(),
        ));
        for (kind, bytes) in variants {
            entries.push((
                format!("main/binary-amd64/Packages{}", kind.suffix()),
                bytes.clone(),
            ));
        }
        if let Some(body) = legacy_release_body {
            entries.push(("main/binary-amd64/Release".to_owned(), body.to_vec()));
        }

        let mut sha256_block = String::new();
        let mut sha512_block = String::new();
        for (path, bytes) in &entries {
            sha256_block.push_str(&format!(
                " {} {} {}\n",
                hex_encode(&Sha256::digest(bytes)),
                bytes.len(),
                path,
            ));
            sha512_block.push_str(&format!(
                " {} {} {}\n",
                hex_encode(&Sha512::digest(bytes)),
                bytes.len(),
                path,
            ));
        }

        let codename = self.codename_override.as_deref().unwrap_or(&self.suite);
        let suite_field = self.suite_alias.as_deref().unwrap_or(&self.suite);
        format!(
            "Suite: {suite_field}\n\
             Codename: {codename}\n\
             Architectures: amd64\n\
             Components: main\n\
             Date: Sat, 03 Feb 2024 09:15:38 UTC\n\
             SHA256:\n{sha256}\
             SHA512:\n{sha512}",
            sha256 = sha256_block,
            sha512 = sha512_block,
        )
        .into_bytes()
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    #[must_use]
    pub fn suite(&self) -> &str {
        &self.suite
    }

    #[must_use]
    pub fn packages(&self) -> &[Package] {
        &self.packages
    }
}

// ---------- Helpers ----------

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0F) as usize] as char);
    }
    out
}
