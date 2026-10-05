//! Plumbing check for the test harness: `StaticServer` serves files,
//! `SyntheticRepo` output round-trips through tain's parsers, `HashingSink`
//! verifies a streamed body.

use std::path::PathBuf;

use tain::backends::apt::deb822::Deb822Reader;
use tain::backends::apt::layout::SuiteLayout;
use tain::backends::apt::packages::paragraph_to_filespec;
use tain::backends::apt::release::parse_release;
use tain::core::fetch::client::{CacheValidators, ClientConfig, build_client, fetch_get};
use tain::core::fetch::sink::HashingSink;
use tain::core::types::DigestAlgo;

mod common;
use common::{StaticServer, SyntheticRepo, TempDir};

fn build_and_serve() -> (TempDir, SyntheticRepo, PathBuf) {
    let tempdir = TempDir::new("harness");
    let repo_root: PathBuf = tempdir.path().join("repo");
    std::fs::create_dir_all(&repo_root).unwrap();
    let repo = SyntheticRepo::new(repo_root.clone(), "bookworm")
        .add_package("nginx", b"fake nginx deb bytes".to_vec())
        .add_package("apt", b"fake apt deb bytes vary the bytes".to_vec())
        .write();
    (tempdir, repo, repo_root)
}

#[tokio::test]
async fn server_serves_the_synthetic_release_bytes() {
    let (_tempdir, _repo, repo_root) = build_and_serve();
    let server = StaticServer::spawn(repo_root.clone()).await;

    let client = build_client(&ClientConfig::default()).unwrap();
    let release_url = server.base_url().join("dists/bookworm/Release").unwrap();
    let resp = fetch_get(&client, &release_url, &CacheValidators::default())
        .await
        .unwrap();
    assert_eq!(resp.status.as_u16(), 200);

    let body = resp.response.bytes().await.unwrap();
    let on_disk = std::fs::read(repo_root.join("dists/bookworm/Release")).unwrap();
    assert_eq!(body.as_ref(), on_disk.as_slice());
}

#[tokio::test]
async fn generated_release_parses_and_lists_packages() {
    let (_tempdir, _repo, repo_root) = build_and_serve();
    let release_bytes = std::fs::read_to_string(repo_root.join("dists/bookworm/Release")).unwrap();
    let (header, checksums) = parse_release(&release_bytes).unwrap();
    assert_eq!(header.suite.as_deref(), Some("bookworm"));
    assert_eq!(header.architectures, vec!["amd64"]);
    assert_eq!(checksums.len(), 1);
    let entry = checksums.get("main/binary-amd64/Packages").unwrap();
    assert!(entry.digests.get(DigestAlgo::Sha512).is_some());
    assert!(entry.digests.get(DigestAlgo::Sha256).is_some());
}

#[tokio::test]
async fn packages_paragraphs_convert_to_filespecs() {
    let (_tempdir, _repo, repo_root) = build_and_serve();
    let pkg_body =
        std::fs::read(repo_root.join("dists/bookworm/main/binary-amd64/Packages")).unwrap();
    let base = url::Url::parse("http://example.com/").unwrap();
    let layout = SuiteLayout::new(&base, "bookworm");
    let cursor = std::io::Cursor::new(pkg_body);
    let mut reader = Deb822Reader::new(cursor);
    let mut count = 0;
    while let Some(p) = reader.read_paragraph().unwrap() {
        let fs = paragraph_to_filespec(&p, &layout, false).unwrap();
        assert!(fs.rel_path.as_str().starts_with("pool/"));
        assert!(fs.digests.get(DigestAlgo::Sha256).is_some());
        count += 1;
    }
    assert_eq!(count, 2);
}

#[tokio::test]
async fn hashing_sink_verifies_body_streamed_from_server() {
    let (_tempdir, repo, repo_root) = build_and_serve();
    let server = StaticServer::spawn(repo_root.clone()).await;

    let pkg = &repo.packages()[0];
    let mut sha256 = tain::core::types::DigestSet::new();
    {
        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(&pkg.bytes);
        sha256
            .push(tain::core::types::Digest::new(DigestAlgo::Sha256, hash.to_vec()).unwrap())
            .unwrap();
    }

    let client = build_client(&ClientConfig::default()).unwrap();
    let url = server.base_url().join(&pkg.filename).unwrap();
    let resp = fetch_get(&client, &url, &CacheValidators::default())
        .await
        .unwrap();
    assert_eq!(resp.status.as_u16(), 200);
    let body = resp.response.bytes().await.unwrap();

    let dest_dir = TempDir::new("harness-dest");
    let final_path = dest_dir.path().join("received.deb");
    let mut sink = HashingSink::new(final_path.clone(), sha256, Some(pkg.bytes.len() as u64))
        .await
        .unwrap();
    sink.write(&body).await.unwrap();
    let report = sink.finish().await.unwrap();
    assert_eq!(report.bytes_written, pkg.bytes.len() as u64);
    assert_eq!(std::fs::read(&final_path).unwrap(), pkg.bytes);
}

#[tokio::test]
async fn server_returns_404_for_missing_path() {
    let (_tempdir, _repo, repo_root) = build_and_serve();
    let server = StaticServer::spawn(repo_root).await;
    let client = build_client(&ClientConfig::default()).unwrap();
    let missing = server.base_url().join("does-not-exist").unwrap();
    let resp = fetch_get(&client, &missing, &CacheValidators::default())
        .await
        .unwrap();
    assert_eq!(resp.status.as_u16(), 404);
}
