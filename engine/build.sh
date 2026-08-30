#!/bin/bash
# build.sh - Aegis 引擎一键构建
# 用法: ./build.sh [arm64-v8a|armeabi-v7a|x86_64|all]
set -e
cd "$(dirname "$0")"
NDK=/opt/android-sdk/ndk/27.2.12479018/android-ndk-r27c
TC=$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin
ARCH=${1:-arm64-v8a}

build_arch() {
    local arch=$1 api=$2 cc_suffix=$3
    echo ">>> 编译 $arch ..."
    local CC=$TC/${cc_suffix}${api}-clang
    mkdir -p out/lib/$arch
    $CC -shared -fPIC -O2 -I include -o out/lib/$arch/libaegis.so \
        src/aegis.c src/sha256.c src/debug_detect.c src/frida_detect.c \
        src/xposed_detect.c src/integrity.c src/emulator.c src/root_detect.c \
        src/system_detect.c src/network.c src/jni_bridge.c -llog
    # 编译本架构可执行测试程序
    $CC -O2 -I include -o out/aegis_test_${arch} \
        test/test_engine.c src/aegis.c src/sha256.c src/debug_detect.c \
        src/frida_detect.c src/xposed_detect.c src/integrity.c \
        src/emulator.c src/root_detect.c src/system_detect.c src/network.c
    echo ">>> $arch OK: out/lib/$arch/libaegis.so"
}

case $ARCH in
    arm64-v8a)   build_arch arm64-v8a   24 aarch64-linux-android ;;
    armeabi-v7a) build_arch armeabi-v7a 24 armv7a-linux-androideabi ;;
    x86_64)      build_arch x86_64      24 x86_64-linux-android ;;
    all) build_arch arm64-v8a 24 aarch64-linux-android
         build_arch armeabi-v7a 24 armv7a-linux-androideabi
         build_arch x86_64 24 x86_64-linux-android ;;
esac
echo "=== 全部完成 ==="
