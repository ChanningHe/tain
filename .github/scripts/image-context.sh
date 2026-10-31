#!/bin/sh
# Usage: image-context.sh DOWNLOAD_DIR CONTEXT_DIR
# Builds the docker/Dockerfile.release context from the release tarballs in
# DOWNLOAD_DIR/tain-linux-<arch>/: amd64/tain, arm64/tain, licenses/ and an
# empty data/.
set -eu

DL="$1"
OUT="$2"

mkdir -p "$OUT/data" "$OUT/licenses"
for arch in amd64 arm64; do
    mkdir -p "$OUT/$arch"
    tar xzf "$DL/tain-linux-$arch/tain-linux-$arch.tar.gz" -C "$OUT/$arch" \
        --strip-components=1 "tain-linux-$arch/tain"
done
tar xzf "$DL/tain-linux-amd64/tain-linux-amd64.tar.gz" -C "$OUT/licenses" \
    --strip-components=1 tain-linux-amd64/LICENSE tain-linux-amd64/THIRD-PARTY-LICENSES
