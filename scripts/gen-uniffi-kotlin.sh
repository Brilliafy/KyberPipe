#!/usr/bin/env bash
set -euo pipefail

# Regenerate the UniFFI Kotlin binding into the SINGLE source of truth
# (AUDIT F9). The Android app consumes this directory via a Gradle
# source-set reference — there is deliberately NO second copy under
# android-app/app/src/main/java/uniffi/ (a stale copy there caused
# UnsatisfiedLinkError-on-device ABI drift when only one tree was regenerated).
#
# Usage:
#   bash scripts/gen-uniffi-kotlin.sh            # regenerate + verify
#
# Requires: a release build of libcore_crypto.so (so the .udl UDL surface is
# resolved against the actual exported symbols) and the uniffi-bindgen binary:
#   cargo run --manifest-path core-crypto/Cargo.toml --bin uniffi-bindgen -- --help
# (or `cargo install uniffi_bindgen`).
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="$ROOT_DIR/core-crypto/generated_kotlin"

echo "=== Regenerating UniFFI Kotlin binding into core-crypto/generated_kotlin ==="

# The binding must be generated against the SAME library the Android JNI build
# produces. If no release .so exists yet, build one for the host first.
LIB="$ROOT_DIR/target/release/libcore_crypto.so"
if [ ! -f "$LIB" ]; then
    echo "No release library — building host target first..."
    (cd "$ROOT_DIR/core-crypto" && cargo build --release)
fi

rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"

(cd "$ROOT_DIR/core-crypto" && \
    cargo run --quiet --bin uniffi-bindgen -- generate \
        --library "$LIB" \
        --language kotlin \
        --out-dir "$OUT_DIR")

# AUDIT F9: the Android tree must contain NO copy of the binding — only the
# srcDir reference in android-app/app/build.gradle.kts may provide it.
FORBIDDEN="android-app/app/src/main/java/uniffi/core_crypto/core_crypto.kt"
if [ -e "$ROOT_DIR/$FORBIDDEN" ]; then
    echo "✗ A stale binding copy exists at $FORBIDDEN — remove it (see AUDIT F9)." >&2
    exit 1
fi

echo "✓ Binding regenerated at $OUT_DIR (single source of truth)."
