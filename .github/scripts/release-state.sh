#!/bin/sh
# Usage: release-state.sh TAG   (env: GH_TOKEN, GH_REPO)
# Prints the GitHub Release state for TAG: none, draft or published.
# Fails closed: an API error, or more than one release for TAG, exits
# non-zero. Lists releases directly rather than `gh release view`, which
# can report "release not found" when its draft lookup fails.
set -eu

TAG="$1"
LIST="$(gh api "repos/$GH_REPO/releases?per_page=100" --paginate)"
STATES="$(printf '%s\n' "$LIST" | jq -r --arg tag "$TAG" '.[] | select(.tag_name == $tag) | .draft')"

case "$STATES" in
    "") echo none ;;
    true) echo draft ;;
    false) echo published ;;
    *)
        echo "unexpected release state for $TAG: $STATES" >&2
        exit 1
        ;;
esac
