#!/bin/bash
set -e

# Define paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
NDK_VERSION="29.0.14206865"
NDK_PATH="$HOME/Android/Sdk/ndk/$NDK_VERSION"
CARGO_REGISTRY="$HOME/.cargo/registry/src"
ZXING_SRC=$(find "$CARGO_REGISTRY" -maxdepth 2 -name "zxing-cpp-*" -type d 2>/dev/null | head -1)/core
ZXING_BUILD="/tmp/zxing-build"

echo "=== Building Rust core-crypto JNI library for Android (arm64-v8a) ==="

if [ ! -d "$NDK_PATH" ]; then
    echo "Error: Android NDK not found at $NDK_PATH."
    echo "Please install NDK version $NDK_VERSION via Android SDK Manager."
    exit 1
fi

export ANDROID_NDK_HOME="$NDK_PATH"

# Pre-build zxing-cpp C++ static library if not cached
if [ ! -f "$ZXING_BUILD/build/libZXing.a" ] && [ -d "$ZXING_SRC" ]; then
    echo "Building zxing-cpp static library for Android..."
    mkdir -p "$ZXING_BUILD"
    cmake -S "$ZXING_SRC" -B "$ZXING_BUILD/build" \
        -DCMAKE_TOOLCHAIN_FILE="$NDK_PATH/build/cmake/android.toolchain.cmake" \
        -DANDROID_ABI=arm64-v8a \
        -DANDROID_PLATFORM=21 \
        -DCMAKE_BUILD_TYPE=Release \
        -DBUILD_SHARED_LIBS=OFF \
        -DZXING_READERS=ON \
        -DZXING_WRITERS=ON \
        -DZXING_EXPERIMENTAL_API=OFF \
        -DZXING_C_API=ON
    cmake --build "$ZXING_BUILD/build" --parallel
fi

export ZXING_CPP_LIB_DIR="$ZXING_BUILD/build"

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
