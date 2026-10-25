set shell := ["bash", "-euo", "pipefail", "-c"]

default:
    @just --list

# Bump to VERSION, commit and tag locally (no push).
release version:
    #!/usr/bin/env bash
    set -euo pipefail
    v={{ version }}
    [[ "$v" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "usage: just release X.Y.Z" >&2; exit 1; }
    [ -z "$(git status --porcelain)" ] || { echo "working tree is not clean" >&2; exit 1; }
    ! git rev-parse -q --verify "refs/tags/v$v" >/dev/null || { echo "tag v$v exists" >&2; exit 1; }
    sed -i "s/^version = \".*\"$/version = \"$v\"/" Cargo.toml
    sed -i "s/VERSION=[0-9.]*$/VERSION=$v/" README.md
    sed -i "s/\`tain\` [0-9.]* understands/\`tain\` $v understands/" docs/configuration.md
    cargo update --workspace --quiet
    git commit -qam "chore: release $v"
    git tag -a "v$v" -m "v$v"
    echo "tagged v$v; push with: git push --atomic origin main v$v"
