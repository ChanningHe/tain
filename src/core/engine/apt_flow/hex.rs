//! Hex-string helpers shared across the apt_flow submodules.

use crate::backends::apt::checksums::ChecksumEntry;
use crate::core::types::{DigestAlgo, DigestSet};

pub(super) fn hex_of(bytes: impl AsRef<[u8]>) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let s = bytes.as_ref();
    let mut out = String::with_capacity(s.len() * 2);
    for &b in s {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0F) as usize] as char);
    }
    out
}

pub(super) fn hex_of_digest_algo(set: &DigestSet, algo: DigestAlgo) -> Option<String> {
    set.get(algo).map(|d| hex_of(&d.bytes))
}

pub(super) fn hex_of_digest_bytes(entry: &ChecksumEntry, algo: DigestAlgo) -> Option<String> {
    entry.digests.get(algo).map(|d| hex_of(&d.bytes))
}
