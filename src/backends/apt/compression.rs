//! Read-side decompression of staged APT index variants for pool derivation.
//!
//! The published variants stay byte-verbatim; this only produces readers.

use std::fs::File;
use std::io::{self, BufRead, BufReader, Read};
use std::path::{Path, PathBuf};

use bzip2::bufread::BzDecoder;
use flate2::bufread::GzDecoder;
use xz2::bufread::XzDecoder;

use super::index_selector::Compression;

/// Open `path` as a decompressing `BufRead`, choosing the codec by filename suffix.
///
/// # Errors
///
/// I/O errors opening the file; decoder errors surface later as `io::Error` on read.
pub fn open_decompressed(path: &Path) -> io::Result<Box<dyn BufRead>> {
    let compression = Compression::detect_from_path(&path.to_string_lossy());
    open_with(path, compression)
}

/// Same as [`open_decompressed`] but with an explicit compression choice.
///
/// # Errors
///
/// I/O errors opening the file.
pub fn open_with(path: &Path, compression: Compression) -> io::Result<Box<dyn BufRead>> {
    let file = File::open(path).map_err(|e| annotate(e, path))?;
    let reader = BufReader::with_capacity(64 * 1024, file);
    Ok(match compression {
        Compression::Xz => Box::new(BufReader::new(XzDecoder::new(reader))),
        Compression::Gz => Box::new(BufReader::new(GzDecoder::new(reader))),
        Compression::Bz2 => Box::new(BufReader::new(BzDecoder::new(reader))),
        Compression::None => Box::new(reader),
    })
}

fn annotate(err: io::Error, path: &Path) -> io::Error {
    io::Error::new(err.kind(), format!("{}: {}", path.display(), err))
}

/// Decompression-bomb cap. Debian's largest indexes are ~200 MiB uncompressed.
pub const DECOMPRESS_MAX_BYTES: u64 = 1024 * 1024 * 1024;

/// Read a variant fully into memory, capped at [`DECOMPRESS_MAX_BYTES`].
///
/// # Errors
///
/// I/O or decoder errors, or `Other` when the output exceeds the cap.
pub fn read_to_vec(path: &Path) -> io::Result<Vec<u8>> {
    let r = open_decompressed(path)?;
    let mut capped = r.take(DECOMPRESS_MAX_BYTES + 1);
    let mut out = Vec::new();
    capped.read_to_end(&mut out)?;
    if out.len() as u64 > DECOMPRESS_MAX_BYTES {
        return Err(io::Error::other(format!(
            "decompressed size exceeds {} bytes cap (possible compression bomb)",
            DECOMPRESS_MAX_BYTES
        )));
    }
    Ok(out)
}

/// Write the decompressed bytes of `src` to `dest`, capped at [`DECOMPRESS_MAX_BYTES`].
///
/// # Errors
///
/// I/O or decoder errors, or `Other` when the output exceeds the cap (`dest` is removed).
pub fn decompress_to_file(src: &Path, dest: &Path) -> io::Result<()> {
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let r = open_decompressed(src)?;
    let mut capped = r.take(DECOMPRESS_MAX_BYTES + 1);
    let mut w = File::create(dest)?;
    let written = io::copy(&mut capped, &mut w)?;
    if written > DECOMPRESS_MAX_BYTES {
        let _ = std::fs::remove_file(dest);
        return Err(io::Error::other(format!(
            "decompressed size exceeds {} bytes cap (possible compression bomb)",
            DECOMPRESS_MAX_BYTES
        )));
    }
    Ok(())
}

#[must_use]
pub fn extension_for(compression: Compression) -> &'static str {
    match compression {
        Compression::Xz => ".xz",
        Compression::Gz => ".gz",
        Compression::Bz2 => ".bz2",
        Compression::None => "",
    }
}

#[allow(dead_code)]
fn _touch(_: PathBuf) {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn tmp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "tain-comp-{}-{}",
            std::process::id(),
            fastrand::u64(..)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join(name)
    }

    #[test]
    fn plain_passthrough() {
        let p = tmp("Packages");
        std::fs::write(&p, b"hello world").unwrap();
        let out = read_to_vec(&p).unwrap();
        assert_eq!(out, b"hello world");
    }

    #[test]
    fn gz_roundtrip() {
        let p = tmp("Packages.gz");
        let f = File::create(&p).unwrap();
        let mut enc = flate2::write::GzEncoder::new(f, flate2::Compression::default());
        enc.write_all(b"paragraph one\n").unwrap();
        enc.finish().unwrap();
        let out = read_to_vec(&p).unwrap();
        assert_eq!(out, b"paragraph one\n");
    }

    #[test]
    fn xz_roundtrip() {
        let p = tmp("Packages.xz");
        let f = File::create(&p).unwrap();
        let mut enc = xz2::write::XzEncoder::new(f, 6);
        enc.write_all(b"XZ body").unwrap();
        enc.finish().unwrap();
        let out = read_to_vec(&p).unwrap();
        assert_eq!(out, b"XZ body");
    }

    #[test]
    fn bz2_roundtrip() {
        let p = tmp("Packages.bz2");
        let f = File::create(&p).unwrap();
        let mut enc = bzip2::write::BzEncoder::new(f, bzip2::Compression::best());
        enc.write_all(b"BZ body").unwrap();
        enc.finish().unwrap();
        let out = read_to_vec(&p).unwrap();
        assert_eq!(out, b"BZ body");
    }

    #[test]
    fn decompress_to_file_writes_uncompressed() {
        let src = tmp("Packages.gz");
        let f = File::create(&src).unwrap();
        let mut enc = flate2::write::GzEncoder::new(f, flate2::Compression::default());
        enc.write_all(b"copy me\n").unwrap();
        enc.finish().unwrap();
        let dst = tmp("Packages.plain");
        decompress_to_file(&src, &dst).unwrap();
        assert_eq!(std::fs::read(&dst).unwrap(), b"copy me\n");
    }

    #[test]
    fn extension_map() {
        assert_eq!(extension_for(Compression::Xz), ".xz");
        assert_eq!(extension_for(Compression::None), "");
    }
}
