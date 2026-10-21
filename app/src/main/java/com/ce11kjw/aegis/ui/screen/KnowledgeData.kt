package com.ce11kjw.aegis.ui.screen

/**
 * 知识库数据（v4.3 重构）
 *
 * 每条包含：
 *  - title      标题
 *  - category   分类
 *  - summary    一句话说明
 *  - detect     检测原理
 *  - solution   解决方案（按可行性评级）
 *  - keys       关联的检测项名称
 */

enum class SolutionGrade(val label: String) {
    WORKING("实测可行"),
    PARTIAL("部分可行"),
    THEORY("理论可行"),
    NONE("无法规避")
}

data class KnowledgeEntry(
    val title: String,
    val category: String,
    val summary: String,
    val detect: String,
    val solution: String,
    val grade: SolutionGrade,
    val keys: List<String> = emptyList()
)

val KNOWLEDGE: List<KnowledgeEntry> = listOf(

    // ══════ 一、Root 类 ══════
    KnowledgeEntry(
        title = "su 二进制检测（9 个路径）",
        category = "Root",
        summary = "扫描 /system/bin/su 等 9 个传统 su 路径。",
        detect = """逐个 stat 以下路径，存在即命中：
  /system/bin/su          /system/xbin/su
  /sbin/su                /su/bin/su
  /system/bin/.ext/.su    /data/local/bin/su
  /data/local/xbin/su     /system/bin/debuggerd
  /system/bin/failsafe/su

现代 Root（Magisk/KSU/APatch）通常不在这些位置留 su，
所以此项单靠已不足以判定 Root，更多是老方案兼容。""",
        solution = """✅ 实测可行：Shamiko + DenyList

1. 安装 Shamiko（Zygisk 模式）
2. 把目标 App 加入 DenyList：
   · Magisk：设置 → 配置 DenyList → 勾选
   · APatch：编辑 /data/adb/ap/package_config
     格式：包名,exclude,allow,uid,to_uid,sctx
     例：com.example.app,1,0,10234,0,u:r:magisk:s0
3. 重启 App 即不可见

⚠️ 前提：Shamiko 需运行在 Zygisk Next 之上
⚠️ 只对 untrusted_app 域生效，shell/root 仍可见

替代：SUSFS（内核模块，路径遮蔽更彻底）""",
        grade = SolutionGrade.WORKING,
        keys = listOf("su二进制检测", "which su/magisk")
    ),

    KnowledgeEntry(
        title = "Root 管理器特征目录",
        category = "Root",
        summary = "检查 /data/adb/magisk、/data/adb/ksu、/data/adb/apd。",
        detect = """stat 以下目录，存在即命中：
  /data/adb/magisk        (Magisk)
  /data/adb/magisk.db
  /data/adb/ksu           (KernelSU)
  /data/adb/apd           (APatch)
  /sbin/magisk
  /debug_ramdisk/magisk
  /sbin/.magisk
  /sbin/.magisk/mirror

即使 su 被隐藏，目录本身也常残留。""",
        solution = """✅ 实测可行

实测（App uid=10388）：
  /data/adb/ap       → ✅ 不可见
  /data/adb/apd      → ✅ 不可见
  /data/adb/modules  → ✅ 不可见

手段：
1. Shamiko 加入 DenyList
2. InkVault hideenv.sh 做 tmpfs 覆盖（/data/adb/ap）

⚠️ 不要用 tmpfs 覆盖 /data/adb/modules
   会让模块管理器看不到模块，包括本模块自己""",
        grade = SolutionGrade.WORKING,
        keys = listOf("Root管理器特征", "KernelSU检测", "APatch检测")
    ),

    KnowledgeEntry(
        title = "magiskd / ksud / apd 守护进程",
        category = "Root",
        summary = "遍历 /proc 查找 root 管理器的常驻守护进程。",
        detect = """遍历 /proc/<pid>/comm，匹配：
  magiskd  (Magisk)
  ksud     (KernelSU)
  apd      (APatch)
  zygiskd  (Zygisk Next)

守护进程是 root 的核心，杀掉会失去 root，
所以它们必然一直运行，理论上可被扫描到。
但 Shamiko 会在 untrusted_app 域拦截 /proc 遍历。""",
        solution = """⚠️ 部分可行

Shamiko 能阻止 App 看到这些进程，但：
· native 层直接 open /proc 可能绕过
· 取决于 Shamiko 版本

推荐：
1. 保持 Shamiko 最新版
2. 使用「乱序 PID 生成」
3. 内核层：SUSFS 的 hide_proc（最强）

⚠️ 绝不要杀 apd/magiskd —— 会直接失去 root""",
        grade = SolutionGrade.PARTIAL,
        keys = listOf("magiskd守护进程", "ksud守护进程", "zygiskd守护进程", "apd进程伪装")
    ),

    KnowledgeEntry(
        title = "kpatch 内核符号（APatch 关键特征）",
        category = "Root",
        summary = "扫描 /proc/kallsyms 中的 kpatch_* 符号。",
        detect = """读取 /proc/kallsyms，查找：
  kpatch_init / kpatch_exit / kpatch_hook
  kpatch_superkey / kpatch_syscall
  kpm_init / kpm_control / kernelpatch

APatch 基于 KernelPatch，会在内核注册这些符号。
即使 /data/adb/ap 被完全隐藏，内核符号表仍然存在。

⚠️ Aegis v4.3 新增的深度检测，
   传统工具（含 Momo）通常不查这一项。""",
        solution = """⚠️ 需要 SUSFS（你当前未安装）

普通方案无法隐藏 kallsyms 符号，必须：
1. 安装 SUSFS（需内核支持）
2. 启用符号隐藏：
   echo 1 > /sys/kernel/susfs/.../hide_kallsyms

你当前状态：❌ 未安装 SUSFS
→ 此项无法规避

替代：换用 KernelSU（ksu_* 符号同样会被检测）""",
        grade = SolutionGrade.PARTIAL,
        keys = listOf("kpatch内核符号", "KSU内核特征", "APatch内核特征", "内核Root符号")
    )
    ,

    // ══════ 二、Hook / 注入类 ══════
    KnowledgeEntry(
        title = "Xposed / LSPosed 框架",
        category = "Hook",
        summary = "检测 XposedBridge.jar、libxposed_art.so 等静态特征。",
        detect = """1. 检查文件存在：
   /system/framework/XposedBridge.jar
   /system/lib/libxposed_art.so
   /system/lib64/libxposed_art.so
2. 检查 /proc/self/maps 的 xposed 映射
3. 检查 ClassLoader（XposedBridge 类）
4. 检查 ro.dalvik.vm.native.bridge

LSPosed 是 Xposed 现代实现，基于 Zygisk，
不在 /system 留静态文件，只能运行时检测。""",
        solution = """✅ 实测可行（LSPosed 自带作用域）

1. 打开 LSPosed 管理器
2. 模块 → 勾选需要生效的模块
3. 作用域 → 只勾选目标 App

⚠️ 关键：Aegis 应"不勾选任何模块"
   这样 LSPosed 不会往 Aegis 进程注入

但局限：
· 若检测的是"设备整体"而非自己进程，
  作用域不生效，仍能通过文件/maps 检测到

实测：Shamiko 能拦截 XposedBridge.jar""",
        grade = SolutionGrade.WORKING,
        keys = listOf("Xposed模块路径", "xposed.jar检测", "libxposed检测", "Installer数据")
    ),

    KnowledgeEntry(
        title = "Frida 注入检测（18 项）",
        category = "Hook",
        summary = "检测 Frida 的线程名、命名管道、端口、内存特征。",
        detect = """Aegis 覆盖 18 项：
1. 线程名：gum-js-loop / gmain / gdbus / pool-frida
2. 命名管道：linjector（/proc/self/fd）
3. 端口：27042 / 27043（Frida Server 默认）
4. 内存映射：/proc/self/maps 中 frida-agent.so
5. memfd：/memfd: 匿名内存
6. 环境变量：FRIDA_*
7. 特征文件：/data/local/tmp/frida-server

Frida 痕迹极其明显，几乎没有隐蔽手段。""",
        solution = """✅ 实测可行（不用时删掉）

最有效：**不用时删除 frida-server**
```
rm /data/local/tmp/frida-server
rm /data/local/tmp/frida-server16
rm /data/local/tmp/re.frida.server
```

InkVault hideenv.sh 已支持（/data 文件移走 + 空占位）
实测（v1.4.0）：
  frida-server:    84,805,928 B → 0 B / 000 ✅
  frida-server16:  53,702,368 B → 0 B / 000 ✅

注意：
· 已注入的进程运行时痕迹无法清除
· 需重启目标 App 才能清 maps
· 端口 27042 可用 -l 参数改""",
        grade = SolutionGrade.WORKING,
        keys = listOf("内存映射Frida特征", "特征线程扫描", "Frida特征文件", "fd管道特征", "frida进程扫描", "Frida特征线程", "Frida命名管道", "Frida端口段")
    ),

    KnowledgeEntry(
        title = "Zygisk 注入检测",
        category = "Hook",
        summary = "检测 Zygisk 注入到 zygote 的痕迹。",
        detect = """1. ro.dalvik.vm.native.bridge 属性
2. /proc/self/maps 中 zygisk 映射
3. zygote 进程的匿名内存段异常
4. /data/adb/modules/zygisksu 目录
5. zygiskd / zygiskd64 进程

Zygisk 是 Magisk 24+ 内置，
Zygisk Next 是独立实现（可用于 KSU/APatch）。""",
        solution = """✅ 实测可行

Shamiko 本身就是 Zygisk 模块，专门隐藏 Zygisk 痕迹：
1. 安装 Shamiko
2. 确保 zygisksu 模块启用
3. 在 DenyList 中加入目标 App

⚠️ 无法完全隐藏的是：
   若检测 zygote 进程（不是自己），
   Shamiko 对 zygote 本身不生效
   → 需 SUSFS 的 hide_zygote""",
        grade = SolutionGrade.PARTIAL,
        keys = listOf("Zygisk注入检测", "Zygisk环境", "Zygisk数据目录", "ZygiskNext检测")
    ),

    KnowledgeEntry(
        title = "Shamiko 自身是否被发现",
        category = "Hook",
        summary = "检测 /data/adb/modules/shamiko 目录。",
        detect = """1. /data/adb/modules/shamiko 目录存在
2. module.prop 的 description 含 Shamiko
3. Magisk DenyList 配置文件痕迹

Shamiko 不能隐藏"自己"目录，
但 /data/adb/modules 对普通 App 本就不可访问（SELinux）。""",
        solution = """✅ 无需处理（SELinux 已保护）

/data/adb/modules 的 SELinux 上下文
不允许 untrusted_app 访问。

实测（App uid=10388）：
  /data/adb/modules → ✅ 不可见（FileNotFoundError）

⚠️ 若用 root 身份检测（Aegis 深度模式），
   就能看到了。这不可避——root 有完全权限。""",
        grade = SolutionGrade.WORKING,
        keys = listOf("Shamiko隐藏", "模块枚举", "Magisk模块指纹")
    ),

    // ══════ 三、完整性类 ══════
    KnowledgeEntry(
        title = "libc 内存 / 磁盘校验（最硬核）",
        category = "完整性",
        summary = "对比 libc.so 内存 .text 段与磁盘文件，检测 inline hook。",
        detect = """来自 DetectFrida（MIT）：
1. 从 /proc/self/maps 找到 libc.so 可执行段
2. 读内存前 8KB（覆盖函数入口区）
3. 从磁盘 libc.so 相同偏移读 8KB
4. 用 FNV-1a 64 位哈希对比

任何 inline hook（Frida/Xposed/Dobby/xhook）
都会修改内存指令字节，导致哈希不一致。

⚠️ 最难规避：
   · 无法用属性伪造绕过
   · 无法用 mount 隐藏绕过（比的是运行时内存）
   · 只能 hook 检测函数本身（循环论证）""",
        solution = """❌ 基本无法规避（这是设计意图）

理论绕过：
1. Hook 检测函数（Frida 也能被检测）
   → 循环论证，需更强的 hook 框架
2. 硬件调试寄存器（不修改内存）
   → 需内核支持，普通 root 做不到
3. 修改磁盘 libc.so（让两边一致）
   → 只读分区，且会让所有 App 崩溃

结论：这一项检测是可靠的。
若要骗过，只能 hook Aegis 自己的函数，
但那会被 inline hook 检测抓到。

反过来说：若想确认环境是否被注入，
这项检测极其可靠，建议保留。""",
        grade = SolutionGrade.NONE,
        keys = listOf("libc内存磁盘校验", "inline hook检测", "prologue完整性", "代码段可写检测")
    ),

    KnowledgeEntry(
        title = "匿名可执行内存映射",
        category = "完整性",
        summary = "统计 /proc/self/maps 中无 pathname 的 r-x 段。",
        detect = """遍历 /proc/self/maps，统计：
· 权限含 'x'（可执行）
· 无 pathname（或为 [xxx]）

正常 App 有少量（ART JIT 生成），约 3-8 条。
注入框架会产生更多。

Aegis 阈值：> 8 条报警。""",
        solution = """⚠️ 部分可行

无法消除的：
· ART JIT 代码（正常 App 也有）
· 系统库的匿名映射

可消除的：
· Frida gadget 的匿名映射 → 删 frida-server 并重启 App
· 内存加载的 so → 不用时卸载

若命中 8-15 条，可能只是 JIT 较多，
看 evidence 里的具体映射地址判断。""",
        grade = SolutionGrade.PARTIAL,
        keys = listOf("匿名可执行映射", "未签名内存", "W+X so检测")
    ),

    KnowledgeEntry(
        title = "APK 自身完整性",
        category = "完整性",
        summary = "检查 APK 路径、权限、属主、ZIP 结构、额外 DEX。",
        detect = """Aegis 应用完整性模块（10 项）：
1. APK 路径：应在 /data/app/，不在 /data/local/tmp
2. APK 权限：应为 644，不可写
3. APK 目录：不应可写
4. APK mtime：不应在未来
5. APK 属主：应为 1000 (system)
6. 侧载工具：MT管理器 / Termux / Scene / Thanox
7. 额外 DEX：非 /data/app 路径的 dex
8. 自身 so 路径：libaegis.so 应从 APK 内加载
9. 进程名称：cmdline 不应含 '/' 或为空
10. ZIP 结构：应有 EOCD 魔数 PK\\x05\\x06

用于识别"App 被二次打包"。""",
        solution = """✅ 无需处理（正常安装即可）

从官方渠道安装（GitHub Releases）全部通过。

若命中：
· APK路径非法 → 直接从 /data/local/tmp 运行
  解决：正常 pm install
· APK权限可写 → 系统异常
  解决：重新安装
· 侧载工具痕迹 → 装了 MT管理器
  解决：提示性质，非风险""",
        grade = SolutionGrade.WORKING,
        keys = listOf("APK路径合法性", "APK文件权限", "APK属主一致性", "额外DEX加载", "自身so路径", "ZIP结构完整性", "侧载工具痕迹")
    )
    ,

    // ══════ 四、设备伪造类 ══════
    KnowledgeEntry(
        title = "Build 属性交叉验证",
        category = "设备",
        summary = "六个 Build 字段互相印证，识别只改了一两个的改机。",
        detect = """读取并交叉验证：
  ro.product.model          型号
  ro.product.brand          品牌
  ro.product.manufacturer   厂商
  ro.product.device         设备代号
  ro.product.name           产品名
  ro.product.board          主板

校验规则：
1. brand 与 manufacturer 应一致或包含
2. device 与 product 应相同或前缀相关
3. board 不应是 generic / unknown

命中 ≥ 2 处矛盾 → 高风险。

改机工具常只改 model，导致：
  model = "小米 15 Pro"
  device = "corot"（K60 Ultra）
→ 矛盾""",
        solution = """⚠️ 只能全改，不能改一个

要规避必须同步修改全部 6 个：
```
resetprop -n ro.product.model "23078RKD5C"
resetprop -n ro.product.brand "Redmi"
resetprop -n ro.product.manufacturer "Xiaomi"
resetprop -n ro.product.device "corot"
resetprop -n ro.product.name "corot"
resetprop -n ro.product.board "corot"
```
（K60 Ultra 真实值，仅供参考）

⚠️ 若改成别的机型，必须同时改 device/board

最佳实践：**不要改机型**
你当前 device 值是 "Xiaomi 17T Pro"（伪造 marketname）
但 model=23078RKD5C 是真实的 → Aegis 会命中矛盾""",
        grade = SolutionGrade.PARTIAL,
        keys = listOf("Build属性一致性", "属性联动检测", "build属性篡改", "Fingerprint格式")
    ),

    KnowledgeEntry(
        title = "序列号三路比对",
        category = "设备",
        summary = "ro.serialno / ro.boot.serialno / ro.vendor.oem.serialno 应一致。",
        detect = """读取三个序列号属性：
  ro.serialno              (Build.getSerial 用)
  ro.boot.serialno         (bootloader 传入)
  ro.vendor.oem.serialno   (厂商写入)

三者应完全相同。
ALING_Serialno 等工具常只改 ro.serialno，
漏掉另外两个 → 检测到不一致。

⚠️ 这是 AntiFaker 项目的核心思路（Apache-2.0）。""",
        solution = """✅ 三处全改即可

```
resetprop -n ro.serialno "<新序列号>"
resetprop -n ro.boot.serialno "<新序列号>"
resetprop -n ro.vendor.oem.serialno "<新序列号>"
```

⚠️ InkVault 的 device.sh sn-full 已实现：
```
sh /data/adb/modules/webui_info/scripts/device.sh sn-full
```
service.sh 开机自动执行。

⚠️ 别用随机值
   真实序列号有固定格式（小米 12 位字母数字）
   随机值可能被 IMEI 格式校验抓到""",
        grade = SolutionGrade.WORKING,
        keys = listOf("序列号一致性", "序列号异常", "序列号全零")
    ),

    KnowledgeEntry(
        title = "传感器 / 硬件真实性",
        category = "设备",
        summary = "检查传感器数量、电池曲线、摄像头、输入设备。",
        detect = """1. /sys/class/sensors 传感器数量（>8 正常，<3 报警）
2. 电池电压（2.8-4.6V）、温度（-10~60℃）
3. /sys/class/video4linux 摄像头数量
4. /proc/bus/input/devices 输入设备（>3）
5. 存储容量（4GB-4TB）
6. CPU 核心数、内存大小

模拟器通常这些值都不对。
真实设备改机不会影响。""",
        solution = """✅ 无需处理（真实设备天然通过）

这是给模拟器/云手机设计的检测。
真实物理设备（K60 Ultra）自动通过。

若命中：
· 传感器 < 3 → 定制 ROM 问题
· 电池电压异常 → 硬件故障
· 摄像头不可见 → 权限问题""",
        grade = SolutionGrade.WORKING,
        keys = listOf("传感器真实性", "电池曲线合理性", "摄像头存在性", "输入设备清单", "传感器数量检测")
    ),

    // ══════ 五、系统 / 内核类 ══════
    KnowledgeEntry(
        title = "SELinux 策略篡改",
        category = "系统",
        summary = "检测自定义 sepolicy，及关键规则是否被放开。",
        detect = """1. 检查自定义 sepolicy 文件：
   /data/adb/magisk/sepolicy
   /data/adb/ksu/sepolicy
   /data/adb/ap/sepolicy
   /data/adb/modules/*/sepolicy.rule
2. 检查关键规则：
   allow untrusted_app ksu_file:file read
   allow untrusted_app magisk_file:file read
   allow untrusted_app lsposed_file:file read
   allow untrusted_app xposed_data:file read
3. /sys/fs/selinux/enforce 应为 1

Duck Detector 等反作弊会 selinux_check_access()，
若返回 Allowed 就判定 root。

⚠️ APatch/KSU 把规则写在具体域
   （untrusted_app_all），不是 appdomain 宏""",
        solution = """✅ 实测可行（InkVault 已有 sepolicy.sh）

InkVault v1.3.5+ sepolicy.sh：
1. 备份原始 policy
2. magiskpolicy --live 移除 app 域对 ksu_file 的放行
3. 热加载立即生效

```
# 设置中开启 auto_sepolicy_fix=1
sh .../sepolicy.sh scan   # 扫描
sh .../sepolicy.sh fix    # 修复
```

你当前状态：service.sh 显示
"SELinux 策略硬化已重应用" ✅（开机自动）

⚠️ 移除规则可能导致某些功能异常
   （如模块管理器读不到模块目录）""",
        grade = SolutionGrade.WORKING,
        keys = listOf("SELinux规则篡改", "sepolicy检测", "SELinux状态", "magiskpolicy检测")
    ),

    KnowledgeEntry(
        title = "内核模块残留",
        category = "系统",
        summary = "检查 /proc/modules 中的 magisk / ksu / apatch。",
        detect = """读取 /proc/modules，匹配：
  magisk / ksud / apatch / kpatch / kernelpatch
  zygisk / shamiko / riru

最直接的内核证据。
⚠️ 现代 root（Magisk/APatch）通常是直接 patch 内核，
   不加载模块，所以 /proc/modules 可能本来就干净。""",
        solution = """⚠️ 部分可行

若真加载了内核模块：
· SUSFS 的 hide_modules（需内核支持）
· 或 insmod 时用特殊参数 unlisted

但现代 root（APatch/Magisk）**不加载模块**，
直接 patch 内核内存，所以本身就干净。

你的设备（APatch）：/proc/modules 大概率干净""",
        grade = SolutionGrade.PARTIAL,
        keys = listOf("内核模块残留", "内核模块异常", "内核符号表")
    ),

    KnowledgeEntry(
        title = "挂载表差异量化",
        category = "系统",
        summary = "对比 /proc/self/mountinfo 与 /proc/1/mountinfo 的行数。",
        detect = """1. 统计 /proc/self/mountinfo 行数
2. 统计 /proc/1/mountinfo 行数
3. 计算差值

正常：
· App 沙箱会多几条（独立 namespace）
· 差异通常在 -5 到 +30

异常：
· 差异 < -5：挂载被隐藏了
· 差异 > 30：注入大量 bind mount

判据：超出 [-5, 30] → 中风险。""",
        solution = """⚠️ 无法精确控制

针对"mount namespace 被篡改"。

若用 tmpfs 覆盖（如 InkVault hide_paths）：
会增加 mountinfo 行数 → 差异变大

实测你的设备：
· InkVault 已 tmpfs 覆盖 /data/adb/ap
· 增加 1 条 mount
· 不至于 > 30

若命中：
· 减少 tmpfs 覆盖数量
· 改用 Shamiko 路径隐藏（不产生 mount）""",
        grade = SolutionGrade.THEORY,
        keys = listOf("挂载表差异量化", "mountinfo镜像", "系统分区rw挂载", "overlayfs挂载")
    )
    ,

    // ══════ 六、常见问题 ══════
    KnowledgeEntry(
        title = "为什么我 root 了但 Aegis 说环境安全？",
        category = "常见问题",
        summary = "这是【正常现象】，不是 bug。",
        detect = """原因：

Aegis 以【普通应用身份】（untrusted_app 域）运行。
Shamiko / Zygisk 的设计目标就是：
"让普通应用看不到 root 痕迹"。

所以：
· App 视角（Aegis 主界面）→ 看到"隐藏后的干净环境"
· Root 视角（Aegis v4.3 深度模式）→ 真实状态

这不是 bug，而是隐藏方案在工作。

【验证方法】Termux 中执行：
```python
import os
os.setuid(10388)   # 切到 Aegis 的 uid
try:
    os.stat('/system/bin/su')
    print('可见')
except:
    print('不可见')  # ← App 视角
```""",
        solution = """✅ v4.3 新增「深度检测」解决

1. Aegis → 设置 → 深度检测
2. 首次进入弹 root 授权 → 允许
3. 打开「以 root 身份检测」
4. 回检测页重新扫描

此时看到真实的 root 痕迹。

⚠️ 注意：
· 深度模式需 su，未 root 设备开关置灰
· 深度模式看到全部 218 项（含被隐藏的）
· 普通模式的"安全"也是真的
  （针对普通应用的攻击面确实安全）""",
        grade = SolutionGrade.WORKING,
        keys = listOf()
    ),

    KnowledgeEntry(
        title = "评分怎么算的？为什么是 95 分？",
        category = "常见问题",
        summary = "四层加权模型，Root 框架识别是基线。",
        detect = """评分算法（v3.7.3 重写）：

**L1 Root 框架基线**
命中 Magisk/KernelSU/APatch 任一 → 60 分起
2 个框架 → +12（72）
3 个 → +10（82）

**L2 Root 证据数量**
CRIT +3/条（≤20）
HIGH +2/条（≤10）
MED  +1/条（≤5）

**L2.5 模拟器基线**
≥8 项 → 90 / ≥5 → 80 / ≥3 → 70 / 1-2 → +15

**L2.8 新模块**
设备伪造 ≥5 → 80 / ≥3 → 65
应用篡改 ≥2 → 70 / 1 → +12
运行时 ≥3 → 65 / ≥2 → 55

**L3 Hook 框架**
Frida +10 / Xposed +8 / Zygisk +6 / 隐藏 +5

**L4 其他模块**
按比例折算，上限 +15（无 root 封顶 45）

最终：min(100, 总和)""",
        solution = """ℹ️ 这是说明，不是问题

想降低分数：
· 减少 Root 框架数量
· 卸载 LSPosed
· 用 Shamiko 隐藏（普通模式）

但注意：
· 普通模式隐藏后分数大降（看不到）
· 深度模式分数不降（看真实状态）

这不是"骗分"，
而是反映不同视角下的真实风险。""",
        grade = SolutionGrade.THEORY,
        keys = listOf()
    ),

    KnowledgeEntry(
        title = "APatch vs Magisk vs KSU 检测难度",
        category = "常见问题",
        summary = "APatch 最难隐藏内核特征。",
        detect = """三种 root 方案对比：

| 特征 | Magisk | KernelSU | APatch |
|---|---|---|---|
| /data/adb 目录 | ✅ | ✅ | ✅ |
| 守护进程 | magiskd | ksud | apd |
| 内核符号 | 无 | ksu_* | kpatch_* |
| /proc/modules | 可能 | 无 | 无 |
| 隐藏难度 | 低 | 中 | **高** |

**APatch 最难隐藏的原因**：
基于 KernelPatch，直接 patch 内核代码，
在内核注册 kpatch_init 等符号。
这些符号在 /proc/kallsyms 可见，
**无法通过用户态手段移除**。

唯一隐藏方案是 SUSFS（内核模块，
过滤 kallsyms 输出），需重新编译内核。""",
        solution = """⚠️ 需要 SUSFS（你当前未安装）

方案 1：安装 SUSFS
· 需内核支持（不是所有设备）
· 装后：
  echo 1 > /sys/kernel/susfs/.../hide_kallsyms
· 效果：kpatch 符号完全隐藏

方案 2：换 KernelSU
· ksu_* 符号同样会被检测
· 但社区更活跃，隐藏方案更成熟

方案 3：接受检测
· 自己用不必追求完全不可检测
· 关键是不影响正常使用（银行/支付）

你的设备现状：
APatch + Shamiko + TrickyStore + PIF
→ 已通过大部分检测
→ 唯独 kallsyms 符号无法规避""",
        grade = SolutionGrade.PARTIAL,
        keys = listOf("kpatch内核符号", "KSU内核特征", "APatch内核特征")
    )
)
