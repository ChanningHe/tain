# Source build: `docker build -f docker/Dockerfile .`
# The `binary` stage also produces the release tarball binaries.
# cargo-zigbuild cross-compiles on the build host: zig is the musl C compiler
# that ring, bzip2-sys and lzma-sys need, so arm64 builds need no emulation.

# ---- build ----
FROM --platform=$BUILDPLATFORM rust:1.96.1-alpine3.22@sha256:fa16d058a94f0f1cf86cbbbd181a2ea2a0001e1fba1e93c366821a58f3e6c8a1 AS build
ARG TARGETARCH

# No openssl-dev: TLS is rustls.
# hadolint ignore=DL3018
RUN apk add --no-cache musl-dev make perl pkgconf zig

# Prebuilt cargo-zigbuild on amd64 build hosts (CI); upstream ships no
# aarch64-musl build, so arm64 hosts compile it. Bump version and checksum together.
ARG BUILDARCH
ARG CARGO_ZIGBUILD_VERSION=0.23.4
ADD --checksum=sha256:9e3cf73485edbd45905c8aadbc0fdf869c7ddc3848f0c898229f2680db52e44b \
    https://github.com/rust-cross/cargo-zigbuild/releases/download/v${CARGO_ZIGBUILD_VERSION}/cargo-zigbuild-x86_64-unknown-linux-musl.tar.xz \
    /tmp/cargo-zigbuild.tar.xz
RUN if [ "$BUILDARCH" = amd64 ]; then \
        tar -xJf /tmp/cargo-zigbuild.tar.xz -C /usr/local/cargo/bin --strip-components=1 \
            cargo-zigbuild-x86_64-unknown-linux-musl/cargo-zigbuild; \
    else \
        cargo install --locked "cargo-zigbuild@${CARGO_ZIGBUILD_VERSION}"; \
    fi && \
    rm /tmp/cargo-zigbuild.tar.xz

WORKDIR /src

# rust-toolchain.toml decides the compiler, whatever the base image ships.
COPY rust-toolchain.toml ./
RUN case "$TARGETARCH" in \
    amd64) echo "x86_64-unknown-linux-musl"  > /tmp/rust-target ;; \
    arm64) echo "aarch64-unknown-linux-musl" > /tmp/rust-target ;; \
    *) echo "unsupported TARGETARCH=$TARGETARCH" >&2; exit 1 ;; \
    esac && \
    rustup toolchain install && \
    rustup target add "$(cat /tmp/rust-target)"

# Fetch deps from the manifest alone so source edits don't invalidate this layer.
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src && \
    echo 'fn main() {}' > src/main.rs && \
    echo '' > src/lib.rs && \
    cargo fetch --locked --target "$(cat /tmp/rust-target)" && \
    rm -rf src

COPY src src
COPY tests tests

RUN RUST_TARGET="$(cat /tmp/rust-target)" && \
    cargo zigbuild --release --locked --target "$RUST_TARGET" && \
    cp "target/${RUST_TARGET}/release/tain" /tain && \
    mkdir /data

# ---- binary only ----
FROM scratch AS binary
COPY --from=build /tain /tain

# ---- runtime (same layout as Dockerfile.release) ----
FROM gcr.io/distroless/static-debian13:nonroot@sha256:e2e927ec666bae08560abb3c55d0659eceabb657f56b6782ab500a9fc7f555e3
COPY --from=build /tain /usr/local/bin/tain
COPY --from=build --chown=65532:65532 /data /data
VOLUME ["/data"]
ENTRYPOINT ["/usr/local/bin/tain"]
CMD ["daemon", "--config", "/etc/tain/config.toml"]
