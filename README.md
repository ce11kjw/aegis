# Aegis 安全检测引擎 🛡️

一核三用: 核心 C 引擎 → **AegisGuard App** / **加固 SDK** / **Frida 攻防测试**

**当前版本: v3.5.0** · 168 项检测 · 8 大模块

## 定位

纯环境检测工具: 检测当前设备环境是否被 **Root / 注入 / 调试 / 模拟 / 篡改**。
所有检测在设备本地完成, 不上传任何数据。

## 架构

```
┌─────────────────────────────────────────────┐
│        核心引擎 (C/C++ libaegis.so)          │
│  · 反调试 / Frida注入 / Xposed/Zygisk       │
│  · 完整性校验 / 模拟器识别 / Root检测        │
│  · 系统环境审计 / 网络环境                   │
└─────────────────────────────────────────────┘
         ↓                 ↓                 ↓
   【产品A】          【产品B】           【产品C】
   AegisGuard App    加固 SDK/AAR       Frida 测试脚本
   三页导航检测App     供第三方集成        攻防验证沙盒
```

## 检测能力 (168 项 / 8 模块)

| 模块 | 项数 | 覆盖内容 |
|------|------|---------|
| 反调试 | 22 | TracerPid / ptrace / 调试器进程 / SIGTRAP / seccomp / 时间差等 |
| Frida注入 | 20 | 内存映射 / 特征线程 / D-Bus端口 / V8引擎 / memfd / JS线程等 |
| Xposed/Zygisk | 16 | 内存映射 / 模块路径 / Dobby / xhook / libart异常等 |
| 完整性 | 20 | 哈希校验 / W+X权限 / 未签名内存 / libc路径 / 系统文件权限等 |
| 模拟器 | 22 | Build / 硬件平台 / CPU型号 / 传感器 / 蓝牙MAC / 串号等 |
| Root | 38 | su / Magisk / KernelSU / APatch / 守护进程 / bootloader / 内核符号等 |
| 系统环境 | 24 | SELinux / CapEff / kallsyms / 调度统计 / cgroup / overlayfs等 |
| 网络环境 | 6 | 全局代理 / VPN / CA证书 / USB调试 / ADB / 可疑端口 |

完整检测清单见 **[docs/detections.md](docs/detections.md)**

## 构建

### 核心引擎
```bash
cd engine
./build.sh all          # 编译 arm64-v8a + armeabi-v7a + x86_64
./build.sh arm64-v8a    # 单架构
```

### 产品A: AegisGuard App
```bash
cd app
./build.sh              # 产出 out/AegisGuard-v3.5.0.apk
```

### 产品B: 加固 SDK
```bash
cd sdk
./build.sh              # 产出 out/aar/AegisGuard-SDK-1.0.0.aar
```

## 产品A: 三页导航

```
🛡️ 检测  |  📚 知识库  |  ⚙️ 设置
```

- **检测**: 一键检测 + 结果一体 (得分/模块折叠/检测项详情展开)
- **知识库**: 168 项完整技术文档 (原理/攻击场景/证据解读/防御建议)
- **设置**: 报告中心(导出)/外观/引擎信息/隐私说明

## 攻防测试 (产品C)

```bash
cd test
# 手机需装 AegisGuard + adb + frida
./run_tests.sh
```

## 环境要求
- NDK r27+ / Android SDK 34 / JDK 17
- 构建服务器: Ubuntu 22.04
- 手机: Android 8+ (minSdk 26)

## 隐私
- 所有检测均在设备本地完成, 不联网、不上传
- 检测结果仅保存在当前会话, 导出才复制到剪贴板
