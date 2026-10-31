#!/bin/sh
# Usage: deb-finalize.sh DEB THIRD_PARTY_LICENSES RELEASES_URL
# Adds what cargo-deb does not produce to a release .deb, in place:
# THIRD-PARTY-LICENSES, a changelog.Debian.gz pointing at the release notes
# (RELEASES_URL/tag/vX.Y.Z) and DEBIAN/md5sums.
set -eu

DEB="$1"
LICENSES="$2"
RELEASES_URL="$3"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
ROOT="$WORK/root"
dpkg-deb -R "$DEB" "$ROOT"

PACKAGE="$(dpkg-deb -f "$DEB" Package)"
VERSION="$(dpkg-deb -f "$DEB" Version)"
MAINTAINER="$(dpkg-deb -f "$DEB" Maintainer)"
# 1.2.0~rc.1-1 -> 1.2.0-rc.1 (the git tag without its leading v).
UPSTREAM="$(printf '%s' "${VERSION%-*}" | tr '~' '-')"
DOC="$ROOT/usr/share/doc/$PACKAGE"

install -m 644 "$LICENSES" "$DOC/THIRD-PARTY-LICENSES"

{
    printf '%s (%s) unstable; urgency=medium\n\n' "$PACKAGE" "$VERSION"
    printf '  * Release notes: %s/tag/v%s\n\n' "$RELEASES_URL" "$UPSTREAM"
    printf ' -- %s  %s\n' "$MAINTAINER" "$(LC_ALL=C date -u -R)"
} | gzip -9n > "$DOC/changelog.Debian.gz"
chmod 644 "$DOC/changelog.Debian.gz"

(cd "$ROOT" && find . -path ./DEBIAN -prune -o -type f -printf '%P\0' \
    | sort -z | xargs -0 md5sum) > "$ROOT/DEBIAN/md5sums"
chmod 644 "$ROOT/DEBIAN/md5sums"

SIZE="$(du -sk --apparent-size --exclude=DEBIAN "$ROOT" | cut -f1)"
sed -i "s/^Installed-Size: .*/Installed-Size: $SIZE/" "$ROOT/DEBIAN/control"

dpkg-deb --root-owner-group -Zxz --build "$ROOT" "$DEB" >/dev/null
