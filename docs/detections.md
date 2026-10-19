# Aegis 检测能力清单

**引擎版本: v3.7.0** · 共 **181 项检测** / 10 大模块

> 全部检测在设备本地 Native 层完成, 通过读取 `/proc` 文件系统、系统属性、文件路径扫描实现。


## 🐞 反调试 (22 项)

检测调试器附加、代码注入、异常进程状态

| # | 检测项 |
|---|--------|
| 1 | TracerPid调试跟踪 |
| 2 | ptrace抢占检测 |
| 3 | 父进程审计 |
| 4 | 调试时间差检测 |
| 5 | 调试器进程扫描 |
| 6 | inline hook检测 |
| 7 | Seccomp状态 |
| 8 | 进程状态异常 |
| 9 | 调试器端口扫描 |
| 10 | 硬件断点检测 |
| 11 | app_process审计 |
| 12 | fork看护检测 |
| 13 | SIGTRAP捕获 |
| 14 | 线程状态深度 |
| 15 | wchan卡点 |
| 16 | fd异常审计 |
| 17 | 自身debuggable |
| 18 | maps调试注入 |
| 19 | 页错误审计 |
| 20 | prologue完整性 |
| 21 | seccomp深度检测 |
| 22 | syscall注入检测 |

## 💉 Frida 注入 (20 项)

检测 Frida 注入痕迹、通信通道、JS 引擎

| # | 检测项 |
|---|--------|
| 1 | 内存映射Frida特征 |
| 2 | 特征线程扫描 |
| 3 | D-Bus端口探测 |
| 4 | 套接字特征 |
| 5 | Frida特征文件 |
| 6 | 环境变量检测 |
| 7 | fd管道特征 |
| 8 | frida进程扫描 |
| 9 | TCP连接特征 |
| 10 | 代码段可写检测 |
| 11 | Gadget文件检测 |
| 12 | Frida端口段 |
| 13 | V8引擎映射 |
| 14 | 线程数异常 |
| 15 | memfd匿名内存 |
| 16 | 异常信号处理 |
| 17 | text段改写 |
| 18 | socketpair通信 |
| 19 | 多注入组合 |
| 20 | JS引擎线程 |

## 🧩 Xposed / Zygisk (16 项)

检测 Xposed/LSPosed 框架与 hook 库

| # | 检测项 |
|---|--------|
| 1 | 内存映射Xposed特征 |
| 2 | 系统属性检测 |
| 3 | Xposed模块路径 |
| 4 | Zygisk注入检测 |
| 5 | xposed.jar检测 |
| 6 | libxposed检测 |
| 7 | Installer数据 |
| 8 | Shamiko隐藏 |
| 9 | 类加载器异常 |
| 10 | Taichi模块 |
| 11 | Dobby hook |
| 12 | xhook/ehook |
| 13 | libart异常 |
| 14 | tmp注入so |
| 15 | Xposed属性 |
| 16 | dalvik缓存 |

## 🔐 完整性 (20 项)

检测重打包、篡改、注入、权限异常

| # | 检测项 |
|---|--------|
| 1 | 自身路径校验 |
| 2 | 匿名可执行映射 |
| 3 | W+X so检测 |
| 4 | so哈希校验 |
| 5 | APK签名校验 |
| 6 | resources校验 |
| 7 | DEX哈希校验 |
| 8 | so内存vs磁盘 |
| 9 | 重打包特征 |
| 10 | libc路径异常 |
| 11 | 已删除so/dex |
| 12 | 包目录异常 |
| 13 | JNI路径审计 |
| 14 | 未签名内存 |
| 15 | exe路径异常 |
| 16 | 系统so覆盖 |
| 17 | 哈希基准对比 |
| 18 | 系统文件权限 |
| 19 | so路径异常 |
| 20 | adb目录权限 |

## 📱 模拟器 (22 项)

检测模拟器环境与虚拟硬件特征

| # | 检测项 |
|---|--------|
| 1 | Build字段检测 |
| 2 | 硬件平台检测 |
| 3 | 属性联动检测 |
| 4 | CPU核心数检测 |
| 5 | 传感器数量检测 |
| 6 | 运营商检测 |
| 7 | CPU指令集检测 |
| 8 | 基带版本检测 |
| 9 | GPU渲染器检测 |
| 10 | 电池属性检测 |
| 11 | 内存大小检测 |
| 12 | 设备节点检测 |
| 13 | qemu内核标志 |
| 14 | Fingerprint指纹 |
| 15 | CPU型号异常 |
| 16 | 输入设备过少 |
| 17 | 蓝牙地址异常 |
| 18 | 无线MAC异常 |
| 19 | NFC缺失 |
| 20 | GPS硬件 |
| 21 | 电池异常 |
| 22 | 序列号异常 |

## 👑 Root (38 项)

检测 Magisk/KernelSU/APatch/su 与内核特征

| # | 检测项 |
|---|--------|
| 1 | su二进制检测 |
| 2 | Root管理器特征 |
| 3 | test-keys签名 |
| 4 | 系统分区rw挂载 |
| 5 | su执行测试 |
| 6 | magiskpolicy检测 |
| 7 | KernelSU检测 |
| 8 | APatch检测 |
| 9 | busybox检测 |
| 10 | Magisk镜像 |
| 11 | dm-verity检测 |
| 12 | DenyList检测 |
| 13 | app_process替换 |
| 14 | bootloader解锁 |
| 15 | vbmeta校验 |
| 16 | Magisk环境变量 |
| 17 | 内核cmdline |
| 18 | 管理器APK |
| 19 | 系统分区rw细查 |
| 20 | Zygisk环境 |
| 21 | magiskd守护进程 |
| 22 | ksud守护进程 |
| 23 | zygiskd守护进程 |
| 24 | which su/magisk |
| 25 | Magisk隐藏挂载 |
| 26 | 模块枚举 |
| 27 | Zygisk数据目录 |
| 28 | KSU内核特征 |
| 29 | APatch内核特征 |
| 30 | SELinux不一致 |
| 31 | build属性篡改 |
| 32 | modules_update |
| 33 | post-fs-data |
| 34 | KSU设备节点 |
| 35 | mountinfo镜像 |
| 36 | init.rc检测 |
| 37 | syscall表暴露 |
| 38 | 内核Root符号 |

## 🖥️ 系统环境 (24 项)

检测系统属性、SELinux、内核状态异常

| # | 检测项 |
|---|--------|
| 1 | 系统调试状态 |
| 2 | SELinux状态 |
| 3 | 编译类型 |
| 4 | CapEff权限 |
| 5 | LD_PRELOAD检测 |
| 6 | 属性联动检测 |
| 7 | ro.secure标志 |
| 8 | SELinux运行时 |
| 9 | 内核版本异常 |
| 10 | VPN服务检测 |
| 11 | 安全标志审计 |
| 12 | 开机时间异常 |
| 13 | init进程异常 |
| 14 | 可疑系统二进制 |
| 15 | 保修位熔断 |
| 16 | 属性完整性 |
| 17 | overlayfs挂载 |
| 18 | 内核模块异常 |
| 19 | sepolicy检测 |
| 20 | SELinux上下文 |
| 21 | SELinux历史审计 |
| 22 | 内核符号表 |
| 23 | 调度统计异常 |
| 24 | cgroup异常 |

## 🌐 网络环境 (6 项)

检测代理、VPN、CA 证书、调试连接

| # | 检测项 |
|---|--------|
| 1 | 全局代理检测 |
| 2 | VPN接口检测 |
| 3 | 用户CA证书检测 |
| 4 | USB调试检测 |
| 5 | ADB连接检测 |
| 6 | 可疑端口监听 |

## 🆕 原创检测 (16 项)

针对现有开源方案未覆盖的场景自研，重点覆盖新框架与交叉验证

| # | 检测项 | 说明 |
|---|--------|------|
| 1 | APatch专属检测 | `/data/adb/ap/` 全目录 + kptools + selinux_hide + pathhide |
| 2 | ZygiskNext检测 | `/data/adb/zygisksu/` + zygiskd 进程（伪装成 ksu 目录） |
| 3 | Magisk模块指纹 | `module.prop` 四字段（id/name/version/author）完整性 |
| 4 | 内核模块残留 | `/proc/modules` 中 magisk/ksu/apatch/kpatch 等 |
| 5 | SELinux规则篡改 | 自定义 sepolicy 文件残留 |
| 6 | 属性写入时间异常 | 属性文件 mtime vs 开机时长交叉验证（resetprop 痕迹） |
| 7 | MTK平台一致性 | 声称 MTK 但无任何 MTK 内核节点 ⇒ 属性篡改 |
| 8 | 挂载表差异量化 | `/proc/self/mountinfo` vs `/proc/1/mountinfo` 行数偏差 |
| 9 | 系统时钟一致性 | `/proc/uptime` vs `CLOCK_MONOTONIC` 偏差 |
| 10 | 三时钟跳变检测 | `MONOTONIC` / `BOOTTIME` 20ms 内前进量一致性 |
| 11 | 匿名可执行映射 | `r-xp` 且无 pathname 的映射 > 5 条 |
| 12 | 系统服务进程链 | `system_server` 的 exe 是否指向 app_process |
| 13 | 调试属性矛盾 | `ro.debuggable=1` + `ro.build.type=user` |
| 14 | USB描述符伪造 | `ro.product.vendor.name` 与 `model` 矛盾 |
| 15 | 动态代码加载路径 | 从 `/data/local/tmp`、`/memfd:` 等加载 so |
| 16 | Android15安全状态 | API 35+ 的 `READ_ADDITIONAL_SECURITY_STATE` 可用性 |

## 🔀 开源融合 (10 项)

基于 MIT / Apache-2.0 项目的检测思路重写实现

| # | 检测项 | 来源 | 说明 |
|---|--------|------|------|
| 1 | libc内存磁盘校验 | **DetectFrida** (MIT) | 内存 .text 段 vs 磁盘文件 FNV-1a 比对，任何 inline hook 都会暴露 |
| 2 | Frida特征线程 | DetectFrida | `gum-js-loop` / `gmain` / `gdbus` / `pool-frida` |
| 3 | Frida命名管道 | DetectFrida | `/proc/self/fd` 中 `linjector` / `frida` |
| 4 | 属性值一致性 | **AntiFaker** (Apache-2.0) | `ro.build.tags` / `type` / `secure` / `debuggable` 四项联动校验 |
| 5 | 序列号全零 | AntiFaker | `ro.serialno` 全 0 ⇒ 模拟器 |
| 6 | 模拟器属性阈值 | **emulator-detector** (Apache-2.0) | 15 条属性命中 ≥ 5 条判定 |
| 7 | 模拟器特征文件 | emulator-detector | Genymotion / QEMU / x86 / Andy / Nox 全套路径 |
| 8 | 模拟器网段 | emulator-detector | 路由表含 `10.0.2.0/24`（QEMU 默认） |
| 9 | 模拟器运营商 | emulator-detector | `310260`（模拟器 MCC/MNC） |
| 10 | RootOfTrust自洽 | **GrapheneOS Auditor** (MIT) | `verifiedbootstate=green` 与 `flash.locked` / `vbmeta` 三向校验 |
