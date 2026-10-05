# syntax=docker/dockerfile:1.7
# Static musl build. The `binary` stage feeds the release tarballs.
# cargo-zigbuild cross-compiles on the build host: zig is the musl C compiler
# that ring, bzip2-sys and lzma-sys need, so arm64 builds need no emulation.

ARG RUST_VERSION=1.88
ARG ALPINE_VERSION=3.22

# ---- build ----
FROM --platform=$BUILDPLATFORM rust:${RUST_VERSION}-alpine${ALPINE_VERSION} AS build
ARG TARGETARCH

# No openssl-dev: TLS is rustls.
RUN apk add --no-cache \
    musl-dev \
    make \
    perl \
    pkgconf \
    zig

ARG CARGO_ZIGBUILD_VERSION=0.23.4
RUN cargo install --locked "cargo-zigbuild@${CARGO_ZIGBUILD_VERSION}"

RUN case "$TARGETARCH" in \
    amd64) echo "x86_64-unknown-linux-musl"  > /tmp/rust-target ;; \
    arm64) echo "aarch64-unknown-linux-musl" > /tmp/rust-target ;; \
    *) echo "unsupported TARGETARCH=$TARGETARCH" >&2; exit 1 ;; \
    esac && rustup target add "$(cat /tmp/rust-target)"

WORKDIR /src

# Fetch deps from the manifest alone so source edits don't invalidate this layer.
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src && \
    echo 'fn main() {}' > src/main.rs && \
    echo '' > src/lib.rs && \
    RUST_TARGET="$(cat /tmp/rust-target)" && \
    cargo fetch --locked --target "$RUST_TARGET" && \
    rm -rf src

COPY src src
COPY tests tests

RUN RUST_TARGET="$(cat /tmp/rust-target)" && \
    cargo zigbuild --release --locked --target "$RUST_TARGET" && \
    cp "target/${RUST_TARGET}/release/tain" /tain

# ---- binary only ----
FROM scratch AS binary
COPY --from=build /tain /tain

# ---- runtime ----
FROM alpine:${ALPINE_VERSION} AS runtime
RUN apk add --no-cache \
    ca-certificates \
    tzdata

COPY --from=build /tain /usr/local/bin/tain

VOLUME ["/data"]

# No PUID/PGID entrypoint: set the uid with --user (or Compose `user:`,
# K8s runAsUser); the host data dir must be owned by that uid.
ENTRYPOINT ["/usr/local/bin/tain"]
# daemon needs TAIN_SCHEDULE or global.schedule (else exits 2).
# Use `sync` instead when an external scheduler drives the runs.
CMD ["daemon", "--config", "/etc/tain/config.toml"]
