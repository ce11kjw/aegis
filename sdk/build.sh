#!/bin/bash
# 构建 AegisGuard SDK -> AAR (v4.0)
#
# 用法: ./build.sh [arm64-v8a|armeabi-v7a|x86_64|all]
# 依赖: ANDROID_SDK_ROOT 或 /opt/android-sdk，NDK 27.2.12479018
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

SDK="${ANDROID_SDK_ROOT:-/opt/android-sdk}"
NDK="$SDK/ndk/27.2.12479018"
TC="$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin"
BT=$(ls -d "$SDK"/build-tools/* | sort -V | tail -1)
PLATFORM=$(ls -d "$SDK"/platforms/android-* | sort -V | tail -1)/android.jar

ENGINE="$REPO_ROOT/engine"
OUT="$SCRIPT_DIR/out"
VERSION="4.0.0"

echo "=== AegisGuard SDK $VERSION ==="
echo "SDK:      $SDK"
echo "NDK:      $NDK"
echo "Platform: $PLATFORM"

rm -rf "$OUT"
mkdir -p "$OUT/classes" "$OUT/aar/jni"

# ─────────────────────────────────────
# [1/5] 用 NDK 编译引擎（三个 ABI）
# ─────────────────────────────────────
build_abi() {
    local abi=$1 api=$2 cc=$3
    echo "[1/5] 编译引擎 $abi ..."
    mkdir -p "$OUT/aar/jni/$abi"
    "$TC/${cc}${api}-clang" -shared -fPIC -O2 \
        -I "$ENGINE/include" \
        -o "$OUT/aar/jni/$abi/libaegis.so" \
        "$ENGINE"/src/aegis.c \
        "$ENGINE"/src/sha256.c \
        "$ENGINE"/src/debug_detect.c \
        "$ENGINE"/src/frida_detect.c \
        "$ENGINE"/src/xposed_detect.c \
        "$ENGINE"/src/integrity.c \
        "$ENGINE"/src/emulator.c \
        "$ENGINE"/src/root_detect.c \
        "$ENGINE"/src/system_detect.c \
        "$ENGINE"/src/network.c \
        "$ENGINE"/src/original_detect.c \
        "$ENGINE"/src/opensource_detect.c \
        "$ENGINE"/src/device_detect.c \
        "$ENGINE"/src/app_integrity.c \
        "$ENGINE"/src/runtime_detect.c \
        "$ENGINE"/src/jni_bridge.c \
        -llog
    echo "    -> $(stat -c%s "$OUT/aar/jni/$abi/libaegis.so") bytes"
}

case "${1:-arm64-v8a}" in
    arm64-v8a)   build_abi arm64-v8a   24 aarch64-linux-android ;;
    armeabi-v7a) build_abi armeabi-v7a 24 armv7a-linux-androideabi ;;
    x86_64)      build_abi x86_64      24 x86_64-linux-android ;;
    all)
        build_abi arm64-v8a   24 aarch64-linux-android
        build_abi armeabi-v7a 24 armv7a-linux-androideabi
        build_abi x86_64      24 x86_64-linux-android ;;
    *) echo "未知架构: $1"; exit 1 ;;
esac

# ─────────────────────────────────────
# [2/5] 编译 Java
# ─────────────────────────────────────
echo "[2/5] javac ..."
javac -source 8 -target 8 -bootclasspath "$PLATFORM" \
    -d "$OUT/classes" $(find "$SCRIPT_DIR/src" -name "*.java") 2>&1 | \
    grep -v "bootstrap class path" || true

# ─────────────────────────────────────
# [3/5] 打包 classes.jar
# ─────────────────────────────────────
echo "[3/5] 打包 classes.jar ..."
(cd "$OUT/classes" && jar cf "$OUT/aar/classes.jar" .)

# ─────────────────────────────────────
# [4/5] 复制 Manifest
# ─────────────────────────────────────
echo "[4/5] 复制 AndroidManifest ..."
cp "$SCRIPT_DIR/AndroidManifest.xml" "$OUT/aar/AndroidManifest.xml"

# ─────────────────────────────────────
# [5/5] 打 AAR
# ─────────────────────────────────────
echo "[5/5] 打 AAR ..."
(cd "$OUT/aar" && jar cf "$OUT/AegisGuard-SDK-$VERSION.aar" \
    classes.jar jni/ AndroidManifest.xml)

ls -lh "$OUT/AegisGuard-SDK-$VERSION.aar"
echo "=== AAR 构建完成 ==="
