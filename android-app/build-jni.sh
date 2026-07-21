#!/bin/bash
set -e

# Define paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
NDK_VERSION="25.2.9519653"
NDK_PATH="$HOME/Android/Sdk/ndk/$NDK_VERSION"

echo "=== Building Rust core-crypto JNI library for Android (arm64-v8a) ==="

if [ ! -d "$NDK_PATH" ]; then
    echo "Error: Android NDK not found at $NDK_PATH."
    echo "Please install NDK version $NDK_VERSION via Android SDK Manager."
    exit 1
fi

export ANDROID_NDK_HOME="$NDK_PATH"

# Run cargo ndk build
cd "$ROOT_DIR/core-crypto"
echo "Running cargo ndk build..."
cargo ndk --target arm64-v8a build --release

# Ensure target directory exists in android-app
JNI_DIR="$SCRIPT_DIR/app/src/main/jniLibs/arm64-v8a"
mkdir -p "$JNI_DIR"

# Copy library
echo "Copying libcore_crypto.so to $JNI_DIR..."
cp "$ROOT_DIR/target/aarch64-linux-android/release/libcore_crypto.so" "$JNI_DIR/"

echo "=== Build JNI successful! ==="
