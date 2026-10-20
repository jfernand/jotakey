#!/bin/sh
# (c) Javier Fernandez @ JotaSoft 2026
# Build the relying party for AWS Lambda (x86_64, Amazon Linux 2023) in cargo-lambda's
# container, so the build machine needs only Docker. Output: target/lambda/webauthn-topcoat/
# bootstrap, which the CDK app (infra/) deploys.
#
# The source goes in and the binary comes out as tar streams rather than a bind mount, so
# this works wherever the checkout lives (Docker Desktop shares only some host paths).
# Docker volumes cache the toolchain, the crates and the build between runs.
#
# x86_64, not arm64: the image's zig 0.13 rejects the --fix-cortex-a53-843419 linker flag
# that Rust passes for aarch64 Linux.
set -eu
EXAMPLE=$(cd "$(dirname "$0")/.." && pwd)
TOOLCHAIN=1.98.0   # Cargo.toml rust-version
OUT="$EXAMPLE/target/lambda"
mkdir -p "$OUT"
tar -c -C "$EXAMPLE" Cargo.toml Cargo.lock src |
docker run --rm -i \
    -v jotakey-lambda-cargo:/usr/local/cargo/registry \
    -v jotakey-lambda-rustup:/usr/local/rustup \
    -v jotakey-lambda-target:/build/target \
    ghcr.io/cargo-lambda/cargo-lambda:1.9.1 \
    sh -c "set -e; mkdir -p /build && tar -x -C /build && cd /build
           { rustup toolchain install $TOOLCHAIN --profile minimal --target x86_64-unknown-linux-gnu &&
             cargo +$TOOLCHAIN lambda build --release --x86-64 --features lambda --locked; } >&2
           tar -c -C target/lambda webauthn-topcoat" |
tar -x -C "$OUT"
ls -l "$OUT/webauthn-topcoat/bootstrap"
