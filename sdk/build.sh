#!/bin/bash
# 构建 AegisGuard SDK -> AAR
set -e
SDK=/opt/android-sdk
BT=$SDK/build-tools/34.0.0
PLATFORM=$SDK/platforms/android-34/android.jar
ROOT=/opt/aegis/sdk
OUT=$ROOT/out
rm -rf $OUT && mkdir -p $OUT/classes $OUT/aar

echo "[1/4] javac ..."
javac -source 8 -target 8 -bootclasspath $PLATFORM \
    -d $OUT/classes $(find src -name "*.java") 2>&1 | grep -v "bootstrap" || true

echo "[2/4] 打包 classes.jar ..."
cd $OUT/classes && jar cf ../aar/classes.jar . && cd ..

echo "[3/4] 复制 .so 到 jni 目录 ..."
mkdir -p aar/jni
for arch in arm64-v8a armeabi-v7a x86_64; do
  mkdir -p aar/jni/$arch
  cp /opt/aegis/engine/out/lib/$arch/libaegis.so aar/jni/$arch/
done

echo "[4/4] 打 AAR ..."
cd $OUT/aar
cp /opt/aegis/sdk/AndroidManifest.xml .
jar cf AegisGuard-SDK-1.0.0.aar classes.jar jni/ AndroidManifest.xml
cd ..
ls -la $OUT/aar/AegisGuard-SDK-1.0.0.aar
echo "=== AAR 构建完成 ==="
