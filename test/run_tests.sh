#!/bin/bash
# run_tests.sh - 在真机上对 Aegis 引擎发起攻击测试
# 前置: 手机已装 AegisGuard, adb 可用
PKG=com.ce11kjw.aegis

echo "=== 测试1: 基础注入 ==="
frida -U -f $PKG -l attack_all.js --no-pause -q 2>&1 | head -40

echo "=== 测试2: 反调试绕过 ==="
frida -U -f $PKG -l anti_debug_bypass.js --no-pause -q 2>&1 | head -30

echo "=== 测试3: 完整性绕过 ==="
frida -U -f $PKG -l integrity_bypass.js --no-pause -q 2>&1 | head -30
