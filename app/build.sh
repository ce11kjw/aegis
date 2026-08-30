#!/bin/bash
set -e
SDK=/opt/android-sdk
BT=$SDK/build-tools/34.0.0
PLATFORM=$SDK/platforms/android-34/android.jar
cd /opt/aegis/app
OUT=/opt/aegis/app/out
rm -rf $OUT && mkdir -p $OUT/classes

# 复制 .so
mkdir -p $OUT/lib
for arch in arm64-v8a armeabi-v7a x86_64; do
  mkdir -p $OUT/lib/$arch
  cp /opt/aegis/engine/out/lib/$arch/libaegis.so $OUT/lib/$arch/
done

echo "[1/5] aapt2 打包..."
$BT/aapt2 compile --dir res -o $OUT/res.zip 2>/dev/null || true
$BT/aapt2 link -o $OUT/base.apk -I $PLATFORM \
    --manifest AndroidManifest.xml --auto-add-overlay \
    $($BT/aapt2 dump configurations 2>/dev/null; [ -f $OUT/res.zip ] && echo "-R $OUT/res.zip")

echo "[2/5] javac ..."
javac -source 8 -target 8 -bootclasspath $PLATFORM \
    -d $OUT/classes $(find src -name "*.java") 2>&1 | grep -v "bootstrap class path" || true

echo "[3/5] d8 + 合并 .so ..."
$BT/d8 --lib $PLATFORM --release --output $OUT $(find $OUT/classes -name "*.class")
cd $OUT && zip -j -q base.apk classes.dex
# 注入 .so 到 APK (保留 lib/<arch>/ 目录结构)
zip -q -r base.apk lib/

echo "[4/5] zipalign ..."
$BT/zipalign -f 4 base.apk aligned.apk

echo "[5/5] 签名 ..."
KEYSTORE=/opt/aegis/app/aegis.keystore
if [ ! -f $KEYSTORE ]; then
  keytool -genkey -keystore $KEYSTORE -alias aegis -keyalg RSA -keysize 2048 \
    -validity 10000 -storepass aegis123 -keypass aegis123 -dname "CN=Aegis, O=Aegis, C=CN"
fi
$BT/apksigner sign --ks $KEYSTORE --ks-pass pass:aegis123 --key-pass pass:aegis123 \
    --out $OUT/AegisGuard-v2.0.0.apk aligned.apk

ls -la $OUT/AegisGuard-v2.0.0.apk
echo "=== 构建完成: $OUT/AegisGuard-v2.0.0.apk ==="
