#!/bin/sh
# Usage: moving-tags.sh VERSION   (env: GH_TOKEN, GH_REPO)
# Decides which moving tags VERSION may take, from the published stable
# GitHub Releases plus VERSION itself. Run it right before each use: the
# answer changes as other versions are published, and re-runs must not
# reuse a stale one. Drafts and unpublished tags are ignored, so an
# abandoned higher tag cannot block patch releases.
# A backport (1.0.6 after 1.1.0) must not take latest or 1.
# Prints GITHUB_OUTPUT lines:
#   latest=true|false  highest stable version overall (image latest, GitHub Latest)
#   major=true|false   highest stable version within X   (image tag X)
#   minor=true|false   highest stable version within X.Y (image tag X.Y)
# Pre-releases take none of them. Fails closed on API errors.
set -eu

VERSION="$1"
STABLE='^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'

case "$VERSION" in
    *-*)
        printf 'latest=false\nmajor=false\nminor=false\n'
        exit 0
        ;;
esac
if ! printf '%s\n' "$VERSION" | grep -Eq "$STABLE"; then
    echo "not a X.Y.Z version: $VERSION" >&2
    exit 1
fi

LIST="$(gh api "repos/$GH_REPO/releases?per_page=100" --paginate)"
PUBLISHED="$(printf '%s\n' "$LIST" \
    | jq -r '.[] | select(.draft == false and .prerelease == false) | .tag_name')"
VERSIONS="$({ printf '%s\n' "$PUBLISHED" | sed -n 's/^v//p'; echo "$VERSION"; } \
    | grep -E "$STABLE" | sort -uV)"

MAJOR="${VERSION%%.*}"
REST="${VERSION#*.}"
MINOR="${REST%%.*}"

# true when VERSION is the highest version matching the anchored prefix $1.
is_highest() {
    top="$(printf '%s\n' "$VERSIONS" | grep -E "^$1" | tail -n 1)"
    if [ "$top" = "$VERSION" ]; then echo true; else echo false; fi
}

echo "latest=$(is_highest '')"
echo "major=$(is_highest "$MAJOR\\.")"
echo "minor=$(is_highest "$MAJOR\\.$MINOR\\.")"
