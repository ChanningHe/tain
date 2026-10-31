//! Read-side decompression of staged APT index variants for pool derivation.
//!
//! The published variants stay byte-verbatim; this only produces readers.

use std::fs::File;
use std::io::{self, BufRead, BufReader, Read};
use std::path::Path;

use bzip2::bufread::MultiBzDecoder;
use flate2::bufread::MultiGzDecoder;
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
/// I/O errors opening the file; reading past [`DECOMPRESS_MAX_BYTES`] of
/// output fails with `Other`.
pub fn open_with(path: &Path, compression: Compression) -> io::Result<Box<dyn BufRead>> {
    open_capped(path, compression, DECOMPRESS_MAX_BYTES)
}

fn open_capped(path: &Path, compression: Compression, cap: u64) -> io::Result<Box<dyn BufRead>> {
    let file = File::open(path).map_err(|e| annotate(e, path))?;
    let reader = BufReader::with_capacity(64 * 1024, file);
    // Every concatenated stream / member is decoded (Ubuntu ships two-stream
    // Packages.xz). apt stops after the first xz or bzip2 stream and reads
    // all gzip members, so the entries parsed here are a superset of what
    // clients see: the pool closure can only grow. Trailing bytes that are
    // not a valid stream fail the index, where apt would ignore them.
    let decoded: Box<dyn Read> = match compression {
        Compression::Xz => Box::new(XzDecoder::new_multi_decoder(reader)),
        Compression::Gz => Box::new(MultiGzDecoder::new(reader)),
        Compression::Bz2 => Box::new(MultiBzDecoder::new(reader)),
        Compression::None => Box::new(reader),
    };
    Ok(Box::new(BufReader::new(Capped {
        inner: decoded,
        remaining: cap,
        cap,
    })))
}

fn annotate(err: io::Error, path: &Path) -> io::Error {
    io::Error::new(err.kind(), format!("{}: {}", path.display(), err))
}

/// Decompression-bomb cap. Debian's largest indexes are ~200 MiB uncompressed.
pub const DECOMPRESS_MAX_BYTES: u64 = 1024 * 1024 * 1024;

/// Passes through at most `cap` bytes, then fails instead of reporting EOF
/// when more output follows, so a truncated stream is never mistaken for a
/// complete one.
struct Capped<R> {
    inner: R,
    remaining: u64,
    cap: u64,
}

impl<R: Read> Read for Capped<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.remaining == 0 {
            let mut probe = [0u8; 1];
            return match self.inner.read(&mut probe)? {
                0 => Ok(0),
                _ => Err(io::Error::other(format!(
                    "decompressed size exceeds {} bytes cap (possible compression bomb)",
                    self.cap
                ))),
            };
        }
        let max = usize::try_from(self.remaining).map_or(buf.len(), |r| r.min(buf.len()));
        let n = self.inner.read(&mut buf[..max])?;
        self.remaining -= n as u64;
        Ok(n)
    }
}

/// Read a variant fully into memory, capped at [`DECOMPRESS_MAX_BYTES`].
///
/// # Errors
///
/// I/O or decoder errors, or `Other` when the output exceeds the cap.
pub fn read_to_vec(path: &Path) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    open_decompressed(path)?.read_to_end(&mut out)?;
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
    let mut r = open_decompressed(src)?;
    let mut w = File::create(dest)?;
    if let Err(e) = io::copy(&mut r, &mut w) {
        drop(w);
        let _ = std::fs::remove_file(dest);
        return Err(e);
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::path::PathBuf;

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

    fn xz_file(name: &str, plain: &[u8]) -> PathBuf {
        let p = tmp(name);
        let mut enc = xz2::write::XzEncoder::new(File::create(&p).unwrap(), 9);
        enc.write_all(plain).unwrap();
        enc.finish().unwrap();
        p
    }

    #[test]
    fn streaming_reader_fails_past_the_cap() {
        // ~1 MiB of zeros compresses to a few hundred bytes.
        let p = xz_file("Packages.xz", &vec![0u8; 1024 * 1024]);
        assert!(std::fs::metadata(&p).unwrap().len() < 4096);
        let mut out = Vec::new();
        let err = open_capped(&p, Compression::Xz, 64 * 1024)
            .unwrap()
            .read_to_end(&mut out)
            .unwrap_err();
        assert!(err.to_string().contains("compression bomb"), "{err}");
        assert!(out.len() <= 64 * 1024, "{} bytes", out.len());
    }

    #[test]
    fn streaming_reader_accepts_output_exactly_at_the_cap() {
        let p = xz_file("Packages.xz", b"0123456789");
        let mut out = Vec::new();
        open_capped(&p, Compression::Xz, 10)
            .unwrap()
            .read_to_end(&mut out)
            .unwrap();
        assert_eq!(out, b"0123456789");
    }

    #[test]
    fn concatenated_streams_are_read_to_the_end() {
        // Ubuntu ships Packages.xz with a trailing empty stream; a later
        // stream or member must neither fail nor be dropped.
        fn xz(b: &[u8]) -> Vec<u8> {
            let mut e = xz2::write::XzEncoder::new(Vec::new(), 6);
            e.write_all(b).unwrap();
            e.finish().unwrap()
        }
        fn gz(b: &[u8]) -> Vec<u8> {
            let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            e.write_all(b).unwrap();
            e.finish().unwrap()
        }
        fn bz2(b: &[u8]) -> Vec<u8> {
            let mut e = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::best());
            e.write_all(b).unwrap();
            e.finish().unwrap()
        }
        type Encode = fn(&[u8]) -> Vec<u8>;
        let cases: [(&str, Encode); 3] = [
            ("Packages.xz", xz),
            ("Packages.gz", gz),
            ("Packages.bz2", bz2),
        ];
        for (name, enc) in cases {
            for tail in [&b""[..], &b"second\n"[..]] {
                let p = tmp(name);
                std::fs::write(&p, [enc(b"first\n"), enc(tail)].concat()).unwrap();
                let out = read_to_vec(&p).unwrap_or_else(|e| panic!("{name}: {e}"));
                assert_eq!(out, [&b"first\n"[..], tail].concat(), "{name}");
            }
        }
    }

    #[test]
    fn plain_reader_is_capped_too() {
        let p = tmp("Packages");
        std::fs::write(&p, b"0123456789").unwrap();
        let mut out = Vec::new();
        let res = open_capped(&p, Compression::None, 9)
            .unwrap()
            .read_to_end(&mut out);
        assert!(res.is_err());
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
