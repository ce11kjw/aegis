# Aegis 安全检测引擎 🛡️

一核三用: 核心 C 引擎 → **EnvGuard v3 App** / **加固 SDK** / **Frida 攻防测试**

## 架构

```
┌─────────────────────────────────────────────┐
│        核心引擎 (C/C++ libaegis.so)          │
│  · 反调试(Frida/Xposed/ptrace检测)          │
│  · 完整性校验(签名/DEX/so哈希)              │
│  · 环境检测(模拟器/Root/注入)               │
└─────────────────────────────────────────────┘
         ↓                 ↓                 ↓
   【产品A】          【产品B】           【产品C】
   AegisGuard App    加固 SDK/AAR       Frida 测试脚本
   用户检测App        卖给其他开发者      攻防验证沙盒
```

## 检测模块 (37 项 / 7 大模块)

| 模块 | 数量 | 核心思路 |
|------|------|----------|
| 反调试 | 6 | TracerPid审计 / ptrace抢占 / 父进程审计 / 时间差 / 调试器进程扫描 |
| Frida注入 | 6 | 内存映射特征 / 特征线程 / D-Bus端口 / 特征文件 / 环境变量 |
| Xposed/Zygisk | 4 | 内存映射 / native.bridge / 模块路径 / Zygisk注入 |
| 完整性 | 4 | 自身路径 / 匿名可执行映射 / W+X权限 / SHA-256 |
| 模拟器 | 6 | Build字段 / 硬件平台 / 属性联动 / CPU核心 / 传感器 / 运营商 |
| Root | 5 | su二进制 / Root管理器 / test-keys / 分区rw / su执行 |
| 系统环境 | 6 | debuggable / SELinux / 编译类型 / CapEff / LD_PRELOAD |

## 构建

### 核心引擎
```bash
cd engine
./build.sh all        # 编译 arm64-v8a + armeabi-v7a + x86_64
./build.sh arm64-v8a  # 单架构
```

### 产品A: AegisGuard App
```bash
cd app
./build.sh            # 产出 out/AegisGuard-v1.0.0.apk
```

### 产品B: 加固 SDK
```bash
cd sdk
./build.sh            # 产出 out/aar/AegisGuard-SDK-1.0.0.aar
```

## SDK 集成示例

```java
// Application.onCreate
AegisGuard.init(this);

int score = AegisGuard.detect();          // 风险分 0-100
boolean rooted = AegisGuard.isRooted();   // 是否 root
boolean hooked = AegisGuard.isHooked();   // 是否被注入

// 敏感操作前阻断
AegisGuard.assertSecure();
```

## 攻防测试 (产品C)

```bash
cd test
# 手机需装 AegisGuard + adb + frida
./run_tests.sh
```

## 环境要求
- NDK r27+ / Android SDK 34 / JDK 17
- 服务器: Ubuntu 22.04
