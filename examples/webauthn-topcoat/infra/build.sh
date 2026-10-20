#!/bin/sh
# (c) Javier Fernandez @ JotaSoft 2026
# Build the relying party for AWS Lambda (x86_64, Amazon Linux 2023) in cargo-lambda's
# container, so the build machine needs only Docker. Output: target/lambda/webauthn-topcoat/
# bootstrap, which the CDK app (infra/) deploys.
#
# The source goes in and the binary comes out as tar streams rather than a bind mount, so
# this works wherever the checkout lives (Docker Desktop shares only some host paths). The
# demo uses jotakey-core's CBOR decoder, so the stream also carries that crate and the root
# Cargo.toml, whose [workspace.package] it inherits from.
# Docker volumes cache the toolchain, the crates and the build between runs.
#
# The page's footer names the commit (JOTAKEY_COMMIT), so the build refuses a working tree
# with uncommitted changes to the demo or to jotakey-core. ALLOW_DIRTY=1 builds anyway, and the footer then says
# "local build".
#
# x86_64, not arm64: the image's zig 0.13 rejects the --fix-cortex-a53-843419 linker flag
# that Rust passes for aarch64 Linux.
set -eu
EXAMPLE=$(cd "$(dirname "$0")/.." && pwd)
REPO=$(git -C "$EXAMPLE" rev-parse --show-toplevel)
SOURCES="Cargo.toml crates/jotakey-core examples/webauthn-topcoat/Cargo.toml examples/webauthn-topcoat/Cargo.lock examples/webauthn-topcoat/src"
TOOLCHAIN=1.98.0   # Cargo.toml rust-version
OUT="$EXAMPLE/target/lambda"
COMMIT=$(git -C "$REPO" rev-parse HEAD)
# shellcheck disable=SC2086 # SOURCES is a list of paths
if [ -n "$(git -C "$REPO" status --porcelain -- $SOURCES)" ]; then
    if [ "${ALLOW_DIRTY:-}" != 1 ]; then
        echo "uncommitted changes in the demo or jotakey-core: commit them, or set ALLOW_DIRTY=1" >&2
        exit 1
    fi
    COMMIT=
fi
mkdir -p "$OUT"
# shellcheck disable=SC2086
tar -c -C "$REPO" --exclude=target $SOURCES |
docker run --rm -i -e JOTAKEY_COMMIT="$COMMIT" \
    -v jotakey-lambda-cargo:/usr/local/cargo/registry \
    -v jotakey-lambda-rustup:/usr/local/rustup \
    -v jotakey-lambda-target:/build/examples/webauthn-topcoat/target \
    ghcr.io/cargo-lambda/cargo-lambda:1.9.1 \
    sh -c "set -e; mkdir -p /build && tar -x -C /build && cd /build/examples/webauthn-topcoat
           [ -n \"\$JOTAKEY_COMMIT\" ] || unset JOTAKEY_COMMIT
           { rustup toolchain install $TOOLCHAIN --profile minimal --target x86_64-unknown-linux-gnu &&
             cargo +$TOOLCHAIN lambda build --release --x86-64 --features lambda --locked; } >&2
           tar -c -C target/lambda webauthn-topcoat" |
tar -x -C "$OUT"
ls -l "$OUT/webauthn-topcoat/bootstrap"
echo "commit: ${COMMIT:-none (local build)}"
