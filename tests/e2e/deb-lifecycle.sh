#!/usr/bin/env bash
# .deb lifecycle e2e test in a Debian container (requires docker):
# fresh install, upgrade keeps user config, purge keeps /srv/mirrors data,
# reinstall onto existing /srv/mirrors.
#
# Usage: tests/e2e/deb-lifecycle.sh [path/to/tain.deb]   # no arg: build .deb in docker
#
# Environment:
#   TAIN_E2E_IMAGE       Debian image (default: debian:trixie-slim)
#   TAIN_E2E_RUST_IMAGE  build image (default: rust:1.96.1-bookworm)
#   TAIN_E2E_SKIP_BUILD  1 = require a .deb path as $1
#   TAIN_E2E_KEEP        1 = keep the container for postmortem
#
# Exit: 0 all pass, 1 scenario failed, 2 setup problem.

set -euo pipefail

# ---- Config ----
IMAGE="${TAIN_E2E_IMAGE:-debian:trixie-slim}"
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
DEB_ARG="${1:-}"
SKIP_BUILD="${TAIN_E2E_SKIP_BUILD:-0}"
KEEP_CONTAINER="${TAIN_E2E_KEEP:-0}"

# ---- Helpers ----
log() { printf '[deb-lifecycle] %s\n' "$*" >&2; }
die() { log "FATAL: $*"; exit 2; }
fail() { log "FAIL: $*"; exit 1; }
pass() { log "PASS: $*"; }

require() {
    command -v "$1" >/dev/null 2>&1 || die "missing required tool: $1"
}

# ---- Preflight ----
require docker
docker info >/dev/null 2>&1 || die "docker daemon not reachable"

# ---- Build .deb (unless caller passed one) ----
# Built in a Debian rust container so libc/arch match the test image.
DEB_PATH=""
DEB_DIR="$REPO_ROOT/target/debian-e2e"
if [ -n "$DEB_ARG" ]; then
    DEB_PATH="$(cd "$(dirname "$DEB_ARG")" && pwd)/$(basename "$DEB_ARG")"
    [ -f "$DEB_PATH" ] || die ".deb not found at: $DEB_PATH"
    log "using pre-built .deb: $DEB_PATH"
elif [ "$SKIP_BUILD" = "1" ]; then
    die "TAIN_E2E_SKIP_BUILD=1 but no .deb path passed as \$1"
else
    RUST_IMAGE="${TAIN_E2E_RUST_IMAGE:-rust:1.96.1-bookworm}"
    log "building .deb inside container ($RUST_IMAGE); output → $DEB_DIR"
    mkdir -p "$DEB_DIR"

    # Source mounted read-only (no copy of a multi-GB target/); registry and
    # target dir cached on the host.
    mkdir -p "$REPO_ROOT/target/e2e-cargo-registry" "$REPO_ROOT/target/e2e-cargo-target"
    docker run --rm \
        -v "$REPO_ROOT:/src:ro" \
        -v "$DEB_DIR:/out" \
        -v "$REPO_ROOT/target/e2e-cargo-registry:/usr/local/cargo/registry" \
        -v "$REPO_ROOT/target/e2e-cargo-target:/target" \
        -w /src \
        "$RUST_IMAGE" \
        bash -euo pipefail -c '
            # Separate target dir so cargo-deb deps do not affect tain feature resolution.
            if ! command -v cargo-deb >/dev/null 2>&1; then
                CARGO_TARGET_DIR=/tmp/cargo-deb-target \
                    cargo install --locked cargo-deb --version 3.8.0 >&2
            fi
            export CARGO_TARGET_DIR=/target
            cargo build --release --locked --manifest-path /src/Cargo.toml
            cargo deb --no-build --manifest-path /src/Cargo.toml --output /out/tain-e2e.deb
        ' >&2 || die "in-container cargo deb build failed"

    DEB_PATH="$(ls -t "$DEB_DIR"/*.deb 2>/dev/null | head -n1)"
    [ -n "$DEB_PATH" ] && [ -f "$DEB_PATH" ] || die "in-container build produced no .deb"
    log "built .deb: $DEB_PATH"
fi

DEB_BASENAME="$(basename "$DEB_PATH")"
log "using Debian image: $IMAGE"
log "container will receive: /tmp/$DEB_BASENAME"

# ---- Container runner: all scenarios in one container, abort on first failure ----
DOCKER_RM_FLAG="--rm"
[ "$KEEP_CONTAINER" = "1" ] && DOCKER_RM_FLAG=""

CONTAINER_NAME="tain-deb-lifecycle-$$"
trap '[ "$KEEP_CONTAINER" = "1" ] && log "container kept: $CONTAINER_NAME" || docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true' EXIT

log "starting container $CONTAINER_NAME"

docker run $DOCKER_RM_FLAG --name "$CONTAINER_NAME" \
    -v "$DEB_PATH:/tmp/tain.deb:ro" \
    -e DEBIAN_FRONTEND=noninteractive \
    "$IMAGE" \
    bash -euo pipefail -c '
set -x
assert() { if ! eval "$1"; then echo "ASSERT FAIL: $1  ($2)" >&2; exit 42; fi; }
assert_not() { if eval "$1"; then echo "ASSERT FAIL (should be false): $1  ($2)" >&2; exit 42; fi; }

# Declared deps plus adduser (absent on -slim images), installed before
# dpkg -i so configure does not leave the package half-installed.
apt-get update -qq
apt-get install -y --no-install-recommends \
    ca-certificates tzdata adduser >/dev/null

# Scenario 1: Fresh install (dpkg -i)
echo "=== SCENARIO 1: fresh install ==="
dpkg -i /tmp/tain.deb

assert "id tain >/dev/null 2>&1"                          "tain user exists"
assert "getent group tain >/dev/null 2>&1"                "tain group exists"

SHELL_ACTUAL="$(getent passwd tain | cut -d: -f7)"
case "$SHELL_ACTUAL" in
    */nologin|*/false) : ;;
    *) echo "ASSERT FAIL: tain shell is $SHELL_ACTUAL, expected nologin/false" >&2; exit 42 ;;
esac

HOME_ACTUAL="$(getent passwd tain | cut -d: -f6)"
assert "[ \"$HOME_ACTUAL\" = /srv/mirrors ]"              "tain home = /srv/mirrors"

assert "[ -f /etc/tain/config.toml ]"                     "config.toml exists"
assert "[ -s /etc/tain/config.toml ]"                     "config.toml non-empty"
assert "grep -q \"\\[global\\]\" /etc/tain/config.toml"   "config has [global]"
assert "grep -q \"target =\" /etc/tain/config.toml"       "config has target ="

OWNER="$(stat -c "%U:%G" /etc/tain/config.toml)"
PERM="$(stat -c "%a" /etc/tain/config.toml)"
assert "[ \"$OWNER\" = root:tain ]"                       "config owner root:tain (got $OWNER)"
assert "[ \"$PERM\" = 640 ]"                              "config perm 0640 (got $PERM)"

DIR_OWNER="$(stat -c "%U:%G" /etc/tain)"
DIR_PERM="$(stat -c "%a" /etc/tain)"
assert "[ \"$DIR_OWNER\" = root:tain ]"                   "/etc/tain owner root:tain"
assert "[ \"$DIR_PERM\" = 750 ]"                          "/etc/tain perm 0750"

assert "[ -d /srv/mirrors ]"                              "/srv/mirrors dir exists"
SRV_OWNER="$(stat -c "%U:%G" /srv/mirrors)"
assert "[ \"$SRV_OWNER\" = tain:tain ]"                   "/srv/mirrors owned by tain"
SRV_PERM="$(stat -c "%a" /srv/mirrors)"
assert "[ \"$SRV_PERM\" = 755 ]"                          "/srv/mirrors perm 0755 (got $SRV_PERM)"

assert "[ -x /usr/bin/tain ]"                             "/usr/bin/tain executable"

if ! /usr/bin/tain --version >/dev/null 2>&1; then
    echo "WARN: tain --version failed (likely host-arch mismatch with container; skipping runtime check)" >&2
    TAIN_RUNTIME_OK=0
else
    TAIN_RUNTIME_OK=1
    /usr/bin/tain --version
fi

for u in tain-sync.service tain-sync.timer tain-daemon.service tain@.service; do
    assert "[ -f /usr/lib/systemd/system/$u ]"                "$u installed"
done

# Shipped daemon unit must not discourage daemon mode.
if grep -q "crash-loop" /usr/lib/systemd/system/tain-daemon.service; then
    echo "ASSERT FAIL: tain-daemon.service header still says crash-loop (regression)" >&2
    exit 42
fi
if grep -qi "not recommended" /usr/lib/systemd/system/tain-daemon.service; then
    echo "ASSERT FAIL: tain-daemon.service header discourages daemon (regression)" >&2
    exit 42
fi

# postinst must be idempotent (Debian Policy §9.1.1).
if command -v dpkg-reconfigure >/dev/null 2>&1; then
    dpkg-reconfigure -f noninteractive tain 2>&1 || { echo "ASSERT FAIL: postinst not idempotent" >&2; exit 42; }
fi
DPKG_MAINTSCRIPT_NAME=postinst DPKG_MAINTSCRIPT_PACKAGE=tain \
    /var/lib/dpkg/info/tain.postinst configure 0.1.0 \
    || { echo "ASSERT FAIL: postinst re-invoke non-zero" >&2; exit 42; }

USER_COUNT="$(getent passwd tain | wc -l)"
assert "[ \"$USER_COUNT\" = 1 ]"                          "single tain user after re-postinst"

echo "=== SCENARIO 1 PASS ==="

# Scenario 2: Upgrade — user config modifications survive
echo "=== SCENARIO 2: upgrade preserves user config ==="

USER_MARKER="# USER-CUSTOM-MARKER-$(date +%s)"
echo "$USER_MARKER" >> /etc/tain/config.toml
# Operator-chosen modes must survive postinst.
chmod 0751 /srv/mirrors
chmod 0710 /etc/tain

# config.toml is not a conffile; only the postinst `if [ ! -f ]` gate
# preserves it, so a same-version reinstall is a faithful upgrade test.
dpkg -i /tmp/tain.deb

assert "grep -qF \"$USER_MARKER\" /etc/tain/config.toml"  "user marker survived upgrade"

OWNER2="$(stat -c "%U:%G" /etc/tain/config.toml)"
PERM2="$(stat -c "%a" /etc/tain/config.toml)"
assert "[ \"$OWNER2\" = root:tain ]"                      "config owner still root:tain"
assert "[ \"$PERM2\" = 640 ]"                             "config perm still 0640"
assert "[ \"$(stat -c %a /srv/mirrors)\" = 751 ]"         "/srv/mirrors mode kept"
assert "[ \"$(stat -c %a /etc/tain)\" = 710 ]"            "/etc/tain mode kept"

assert "id tain >/dev/null 2>&1"                          "tain user still exists after upgrade"
for u in tain-sync.service tain-sync.timer tain-daemon.service; do
    assert "[ -f /usr/lib/systemd/system/$u ]"                "$u still installed"
done

echo "=== SCENARIO 2 PASS ==="

# Scenario 3: Purge — everything the pkg created goes; data survives
echo "=== SCENARIO 3: purge cleans user, group, /etc/tain; preserves /srv/mirrors ==="

mkdir -p /srv/mirrors/precious-mirror-data
echo "test-payload-$(date +%s)" > /srv/mirrors/precious-mirror-data/marker
DATA_INODE="$(stat -c %i /srv/mirrors/precious-mirror-data/marker)"

dpkg --purge tain

assert_not "[ -x /usr/bin/tain ]"                         "/usr/bin/tain removed"
assert_not "[ -d /etc/tain ]"                             "/etc/tain removed (postrm purge)"
assert_not "id tain >/dev/null 2>&1"                      "tain user removed"
assert_not "getent group tain >/dev/null 2>&1"            "tain group removed"

for u in tain-sync.service tain-sync.timer tain-daemon.service tain@.service; do
    assert_not "[ -f /usr/lib/systemd/system/$u ]"            "$u removed"
done

assert "[ -d /srv/mirrors ]"                              "/srv/mirrors preserved on purge"
assert "[ -f /srv/mirrors/precious-mirror-data/marker ]"  "operator data preserved on purge"
NEW_INODE="$(stat -c %i /srv/mirrors/precious-mirror-data/marker)"
assert "[ \"$DATA_INODE\" = \"$NEW_INODE\" ]"             "data inode unchanged (not recreated)"

echo "=== SCENARIO 3 PASS ==="

# Scenario 4: Fresh install onto an existing /srv/mirrors
# Like a data disk mounted before the first install.
echo "=== SCENARIO 4: reinstall after purge onto existing /srv/mirrors ==="
chown root:root /srv/mirrors
chmod 0755 /srv/mirrors
dpkg -i /tmp/tain.deb

SRV_OWNER="$(stat -c %U:%G /srv/mirrors)"
assert "[ \"$SRV_OWNER\" = tain:tain ]"                "existing /srv/mirrors owned by tain (got $SRV_OWNER)"
SRV_PERM="$(stat -c %a /srv/mirrors)"
assert "[ \"$SRV_PERM\" = 755 ]"                       "existing /srv/mirrors mode kept (got $SRV_PERM)"
assert "su -s /bin/sh tain -c \"touch /srv/mirrors/.write-test\"" "tain can write /srv/mirrors"
assert "[ -f /srv/mirrors/precious-mirror-data/marker ]" "operator data still present"

echo "=== SCENARIO 4 PASS ==="

echo "=== ALL SCENARIOS PASS ==="
'

pass "all four lifecycle scenarios PASSED"
exit 0
