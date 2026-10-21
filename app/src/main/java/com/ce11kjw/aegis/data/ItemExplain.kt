package com.ce11kjw.aegis.data

/**
 * 检测项的「意味着什么」+「如何解决」（v4.6）
 *
 * 结构：
 *  - meaning  检测到/未检测到时分别意味着什么
 *  - fix      命中后如何处理（引用知识库条目）
 *
 * 覆盖策略：
 *  - 高频/高危项：逐条手写（约 40 项）
 *  - 其余项：按模块给通用说明 + 指向知识库
 */
data class ItemExplain(
    /** 命中时意味着什么 */
    val meaningHit: String,
    /** 未命中时意味着什么 */
    val meaningClean: String,
    /** 如何处理（固定文本，不是动态） */
    val fix: String,
    /** 关联的知识库标题（可为空） */
    val kbRef: String = ""
)

object ItemExplains {

    private val map: Map<String, ItemExplain> = mapOf(

        // ══════ Root 类 ══════
        "su二进制检测" to ItemExplain(
            "在系统路径下发现了 su 可执行文件。这意味着设备已被 root，"
                + "任何应用理论上都能通过 su 提权。",
            "在 9 个传统 su 路径下均未发现 su 文件。这是安全状态。",
            "✅ 若要隐藏：安装 Shamiko + 在 DenyList 中加入本应用。\n"
                + "⚠️ 现代 Root（Magisk/KSU/APatch）通常不在这些路径留 su，"
                + "所以未命中不代表没 root。",
            "su 二进制检测（9 个路径）"
        ),

        "Root管理器特征" to ItemExplain(
            "发现 Magisk / KernelSU / APatch 的管理器目录"
                + "（/data/adb/magisk、/data/adb/ksu、/data/adb/apd 等）。"
                + "这是设备已被 root 的直接证据。",
            "未在标准路径发现 Root 管理器目录。",
            "✅ 用 Shamiko 把本应用加入 DenyList，或给 /data/adb 做 tmpfs 覆盖。\n"
                + "⚠️ 不要覆盖 /data/adb/modules，会让模块管理器失效。",
            "Root 管理器特征目录"
        ),

        "APatch专属检测" to ItemExplain(
            "发现 APatch 特有的目录或文件（/data/adb/ap、kptools、"
                + "selinux_hide、pathhide 等）。APatch 基于内核补丁，"
                + "比 Magisk 更难被传统检测发现。",
            "未发现 APatch 特征文件。",
            "⚠️ 此项只能靠 Shamiko 或内核级方案（SUSFS）隐藏。\n"
                + "脚本层无法隐藏 /data/adb/ap 内的所有文件。",
            "Root 管理器特征目录"
        ),

        "APatch superkey" to ItemExplain(
            "发现 APatch 的 superkey 文件或 ro.kernelpatch.version 属性。"
                + "这是 APatch 0.10+ 的独有特征，用于内核态鉴权。",
            "未发现 APatch superkey。",
            "⚠️ 需要 SUSFS 内核模块才能隐藏。普通用户态手段无效。",
            "kpatch 内核符号（APatch 关键特征）"
        ),

        "kpatch内核符号" to ItemExplain(
            "在 /proc/kallsyms 中发现了 kpatch_* 符号。这是 APatch 的 "
                + "KernelPatch 在内核注册的符号，即使 /data/adb/ap 被完全隐藏，"
                + "这些符号仍然存在。",
            "kallsyms 中未发现 kpatch 相关符号。",
            "❌ 无法规避（除非安装 SUSFS 并在内核层过滤 kallsyms）。\n"
                + "这是 APatch 最难隐藏的特征，也是本应用的差异化检测项。",
            "kpatch 内核符号（APatch 关键特征）"
        ),

        "APatch配置篡改" to ItemExplain(
            "发现 APatch 的配置文件（package_config / deny_list），"
                + "或该文件在最近 1 小时内被修改过。"
                + "说明有人主动改过 Root 隐藏配置。",
            "未发现 APatch 配置文件。",
            "⚠️ 若只是发现文件：说明设备已 root（正常）。\n"
                + "⚠️ 若提示「最近被修改」：检查是否有恶意软件在改隐藏配置。",
            "Root 管理器特征目录"
        ),

        "apd进程伪装" to ItemExplain(
            "发现 apd 守护进程，且其 cmdline 可能被伪造。"
                + "apd 是 APatch 的核心进程，杀掉会失去 root。",
            "未发现 apd 进程。",
            "⚠️ 无法处理（apd 必须在运行）。\n"
                + "若 cmdline 异常，可能是有人试图伪装该进程规避检测。",
            "magiskd / ksud / apd 守护进程"
        ),

        "magiskd守护进程" to ItemExplain(
            "发现 magiskd 守护进程。这是 Magisk 的核心进程，"
                + "负责模块管理和 root 授权。",
            "未发现 magiskd 进程（可能已被 Shamiko 隐藏，或未使用 Magisk）。",
            "✅ Shamiko 可阻止普通应用通过 /proc 看到该进程。",
            "magiskd / ksud / apd 守护进程"
        ),

        "ksud守护进程" to ItemExplain(
            "发现 ksud 守护进程（KernelSU 核心）。",
            "未发现 ksud 进程。",
            "✅ Shamiko 可隐藏。",
            "magiskd / ksud / apd 守护进程"
        ),

        "zygiskd守护进程" to ItemExplain(
            "发现 zygiskd 守护进程。Zygisk Next 是独立实现的 Zygisk，"
                + "不依赖 Magisk。",
            "未发现 zygiskd 进程。",
            "✅ Shamiko 可隐藏。",
            "Zygisk 注入检测"
        ),

        "bootloader解锁" to ItemExplain(
            "ro.boot.flash.locked 为 0，说明 bootloader 已解锁。"
                + "解锁 bootloader 是 root 的前提，也会降低设备整体安全性"
                + "（可被刷入任意镜像）。",
            "bootloader 处于锁定状态（flash.locked=1）。",
            "⚠️ 属性层可用 resetprop 伪装成 1。\n"
                + "⚠️ 但 TEE 硬件证书里的 RootOfTrust 无法伪造，"
                + "需要 TrickyStore 替换证书链。",
            "bootloader 解锁 / vbmeta 状态"
        ),

        "vbmeta校验" to ItemExplain(
            "ro.boot.vbmeta.device_state 不是 locked，说明验证启动"
                + "（Verified Boot）被绕过或禁用。",
            "vbmeta 处于 locked 状态。",
            "⚠️ 同 bootloader，属性可伪装但 TEE 证书不行。",
            "bootloader 解锁 / vbmeta 状态"
        ),

        "RootOfTrust自洽" to ItemExplain(
            "发现 RootOfTrust 三要素（verifiedbootstate / flash.locked / "
                + "vbmeta.device_state）互相矛盾。说明有人在用 resetprop "
                + "修改属性，但没改全。",
            "RootOfTrust 三要素自洽。",
            "⚠️ 把所有相关属性统一改成 locked/1/green，"
                + "或使用 InkVault 的 envhide.sh hide-bl 自动处理。",
            "bootloader 解锁 / vbmeta 状态"
        ),

        // ══════ Hook 类 ══════
        "Xposed模块路径" to ItemExplain(
            "发现 Xposed / LSPosed 的模块文件或目录。"
                + "说明设备安装了 Hook 框架，可以修改任意应用的运行时行为。",
            "未发现 Xposed 相关文件。",
            "✅ 在 LSPosed 管理器中，把本应用从作用域中排除。\n"
                + "✅ 或用 Shamiko 隐藏 /system/framework/XposedBridge.jar。",
            "Xposed / LSPosed 框架"
        ),

        "Shamiko隐藏" to ItemExplain(
            "发现 Shamiko 模块目录。Shamiko 是专门用于隐藏 root 的 Zygisk 模块。"
                + "它本身不会让设备更危险，只是说明设备有隐藏方案。",
            "未发现 Shamiko。",
            "✅ 无需处理（Shamiko 是保护性工具）。\n"
                + "⚠️ 若处于普通应用视角，Shamiko 目录本就不可访问（SELinux 保护）。",
            "Shamiko 自身是否被发现"
        ),

        "libc内存磁盘校验" to ItemExplain(
            "libc.so 的内存指令与磁盘文件不一致。这意味着有人对 libc "
                + "做了 inline hook（通常是 Frida / Xposed / Dobby）。"
                + "这是**最可靠**的注入检测，无法用属性伪造绕过。",
            "libc.so 内存与磁盘完全一致，没有 inline hook。",
            "❌ 基本无法规避（这是设计意图）。\n"
                + "若有 Frida 正在运行：关闭 Frida 并重启目标 App。",
            "libc 内存 / 磁盘校验（最硬核）"
        ),

        "Frida特征线程" to ItemExplain(
            "发现 Frida 的特征线程（gum-js-loop / gmain / gdbus）。"
                + "说明 Frida 已注入当前进程。",
            "未发现 Frida 特征线程。",
            "✅ 关闭 Frida 并杀进程，再重启 App。",
            "Frida 注入检测（18 项）"
        ),

        "Frida命名管道" to ItemExplain(
            "在 /proc/self/fd 中发现了 linjector 或 frida 命名管道。"
                + "这是 Frida 注入器的通信通道。",
            "未发现 Frida 命名管道。",
            "✅ 关闭 Frida，重启 App。",
            "Frida 注入检测（18 项）"
        ),

        "匿名可执行映射" to ItemExplain(
            "当前进程有较多无路径名且可执行的内存段。"
                + "正常 App 会有少量（ART JIT 生成），但过多说明有动态注入。",
            "匿名可执行映射数量正常（ART JIT 所需）。",
            "⚠️ 若命中：查看 evidence 里的映射地址。\n"
                + "· 少量（<15）：可能只是 JIT 较多，属正常\n"
                + "· 大量（>30）：高度可疑，可能有注入框架",
            "匿名可执行内存映射"
        ),

        // ══════ 完整性类 ══════
        "APK路径合法性" to ItemExplain(
            "本应用从非常规路径运行（非 /data/app）。"
                + "正常的已安装 App 应该从 /data/app/ 加载。",
            "本应用从标准路径运行。",
            "✅ 若从 /data/local/tmp 直接运行：改为正常安装（pm install）。",
            "APK 自身完整性"
        ),

        "ZIP结构完整性" to ItemExplain(
            "APK 的 ZIP 结构损坏（找不到 EOCD 中央目录结束符）。"
                + "可能是重打包工具处理不当导致。",
            "APK 的 ZIP 结构完整。",
            "✅ 重新从官方渠道下载安装。",
            "APK 自身完整性"
        ),

        "额外DEX加载" to ItemExplain(
            "发现从非标准路径加载的 DEX 文件。"
                + "正常的 App 只从自己 APK 内加载 DEX。",
            "所有 DEX 都从标准路径加载。",
            "⚠️ 若命中：可能是动态加载框架（如插件化、热修复），"
                + "也可能是恶意代码加载。需检查具体路径。",
            "APK 自身完整性"
        ),

        // ══════ 调试类 ══════
        "TracerPid调试跟踪" to ItemExplain(
            "TracerPid 非 0，说明当前进程被 ptrace 附加（调试器或注入器）。"
                + "这是最经典的反调试检测。",
            "TracerPid 为 0，当前进程未被任何调试器附加。",
            "✅ 关闭 USB 调试和所有调试工具，重启 App。\n"
                + "⚠️ 若你在用 Frida：这是正常现象（Frida 会 ptrace）。",
            ""
        ),

        "ptrace抢占检测" to ItemExplain(
            "尝试 ptrace 自己失败，说明已有其他进程在 ptrace 当前进程。"
                + "这是调试器/注入器的强证据。",
            "ptrace 可用，当前进程未被抢占。",
            "✅ 同上：关闭调试工具，重启 App。",
            ""
        ),

        "SIGTRAP捕获" to ItemExplain(
            "当前进程捕获了 SIGTRAP 信号。"
                + "正常 App 不会捕获该信号，通常是调试器或反调试对抗工具。",
            "未捕获 SIGTRAP。",
            "⚠️ 若在用 Frida / 反调试模块：属正常。\n"
                + "否则可能是恶意注入。",
            ""
        ),

        // ══════ 系统类 ══════
        "SELinux规则篡改" to ItemExplain(
            "发现自定义 sepolicy 文件，或 SELinux 处于 permissive 模式。"
                + "这意味着访问控制被削弱，恶意应用更容易提权。",
            "SELinux 处于 enforcing 模式，未发现自定义策略。",
            "✅ InkVault 的 sepolicy.sh fix 可移除多余规则。\n"
                + "⚠️ 不要设为 disabled/permissive，会大幅降低安全性。",
            "SELinux 策略篡改"
        ),

        "内核模块残留" to ItemExplain(
            "在 /proc/modules 中发现 magisk / ksu / apatch 等模块。"
                + "这是 Root 方案加载了内核模块的直接证据。",
            "/proc/modules 中无 Root 相关模块。",
            "⚠️ 现代 Root（APatch/Magisk）通常不加载模块"
                + "（直接 patch 内核），所以此项为空也属正常。",
            "内核模块残留"
        ),

        // ══════ 设备类 ══════
        "Build属性一致性" to ItemExplain(
            "Build 属性之间存在矛盾（如 model 与 device 不匹配）。"
                + "说明有人用改机工具修改了部分属性，但没改全。",
            "Build 属性六项交叉验证通过，无矛盾。",
            "✅ 改机时必须同步修改全部 6 个字段"
                + "（model/brand/manufacturer/device/product/board）。\n"
                + "⚠️ 最佳实践：不要改机型。",
            "Build 属性交叉验证"
        ),

        "序列号一致性" to ItemExplain(
            "三个序列号属性不一致（ro.serialno / ro.boot.serialno / "
                + "ro.vendor.oem.serialno）。说明改机工具只改了一部分。",
            "三个序列号完全一致。",
            "✅ InkVault 的 device.sh sn-full 可同步三个属性。",
            "序列号三路比对"
        ),

        "传感器真实性" to ItemExplain(
            "传感器数量异常（过少或为零）。"
                + "真实设备通常有 8 个以上传感器，模拟器可能一个都没有。",
            "传感器数量正常，符合真实设备特征。",
            "✅ 无需处理（真实设备天然通过）。",
            "传感器 / 硬件真实性"
        ),

        // ══════ 运行时类 ══════
        "UID权限异常" to ItemExplain(
            "当前进程以 root（uid=0）或系统级 uid 运行。"
                + "正常的 App 进程 uid 应 ≥ 10000。",
            "当前进程 uid 正常（普通应用）。",
            "⚠️ 若本应用不是通过 su 启动却检测到 uid=0，"
                + "说明启动链被劫持，需重装。",
            ""
        ),

        "线程数异常" to ItemExplain(
            "当前进程线程数过多（> 60）。"
                + "注入框架通常会额外创建线程。",
            "线程数正常。",
            "⚠️ 若命中且未使用注入框架：检查是否有恶意代码在后台运行。",
            ""
        ),

        "定时器漂移" to ItemExplain(
            "CLOCK_REALTIME 与 CLOCK_MONOTONIC 前进量不一致。"
                + "说明时间函数被 hook。",
            "两个时钟同步，无 hook 迹象。",
            "⚠️ 若在用时间加速/减速工具：关闭即可。",
            ""
        ),

        // ══════ 网络类 ══════
        "全局代理检测" to ItemExplain(
            "检测到系统级 HTTP 代理。所有网络流量会经过代理服务器，"
                + "可能被中间人窃听。",
            "未设置全局代理。",
            "✅ 若不需要代理：设置 → WLAN → 高级 → 代理 → 无。",
            ""
        ),

        "VPN接口检测" to ItemExplain(
            "检测到活跃的 VPN 接口。"
                + "VPN 会改变网络出口，可能被用于绕过地域限制或隐私保护。",
            "无活跃 VPN。",
            "⚠️ 若你在用 VPN：这是正常状态。\n"
                + "⚠️ 若未知 VPN：立即关闭，可能是恶意软件。",
            ""
        ),

        "用户CA证书检测" to ItemExplain(
            "安装了用户级 CA 证书。"
                + "这允许持有对应私钥的人解密你的 HTTPS 流量（中间人攻击）。",
            "未安装用户 CA 证书。",
            "⚠️ 若你在做抓包调试：正常。\n"
                + "⚠️ 若未知证书：立即删除（设置 → 安全 → 加密与凭据 → 用户证书）。",
            ""
        ),

        "USB调试检测" to ItemExplain(
            "USB 调试已开启。连接电脑后，任何有 ADB 权限的人都能"
                + "读取数据、安装应用、甚至提权。",
            "USB 调试已关闭 ✓",
            "✅ 关闭开发者选项中的「USB 调试」。",
            ""
        ),
    )

    /** 按模块的通用说明（未手写的检测项走这个） */
    private val moduleDefaults: Map<String, ItemExplain> = mapOf(
        "反调试" to ItemExplain(
            "检测到调试/注入痕迹。这通常意味着有工具在监视或修改当前进程。",
            "未检测到调试痕迹。",
            "✅ 关闭所有调试工具（Android Studio / Frida / Xposed）。\n"
                + "✅ 关闭 USB 调试后重启 App。",
            ""
        ),
        "Frida注入" to ItemExplain(
            "检测到 Frida 动态插桩框架的痕迹。Frida 可以读取和修改进程内存。",
            "未检测到 Frida 痕迹。",
            "✅ 关闭 Frida Server，删除 /data/local/tmp/frida-server。",
            "Frida 注入检测（18 项）"
        ),
        "Xposed/Zygisk" to ItemExplain(
            "检测到 Hook 框架（Xposed / LSPosed / Zygisk）的痕迹。",
            "未检测到 Hook 框架。",
            "✅ 在 LSPosed 作用域中排除本应用，或用 Shamiko 隐藏。",
            "Xposed / LSPosed 框架"
        ),
        "完整性" to ItemExplain(
            "检测到完整性异常（可能是注入、篡改或重打包）。",
            "完整性校验通过。",
            "⚠️ 重新从官方渠道安装本应用。",
            "APK 自身完整性"
        ),
        "模拟器" to ItemExplain(
            "检测到虚拟化/模拟器环境特征。",
            "未检测到模拟器特征，符合真实设备。",
            "✅ 无需处理（真实设备自动通过）。",
            "传感器 / 硬件真实性"
        ),
        "Root" to ItemExplain(
            "检测到 Root 相关痕迹。",
            "未检测到 Root 痕迹。",
            "✅ 用 Shamiko + DenyList 隐藏。",
            "su 二进制检测（9 个路径）"
        ),
        "系统环境" to ItemExplain(
            "系统环境存在异常配置（可能影响安全性）。",
            "系统环境配置正常。",
            "⚠️ 检查 SELinux 状态、内核参数等。",
            "SELinux 策略篡改"
        ),
        "网络环境" to ItemExplain(
            "网络环境存在风险（代理 / VPN / 可疑证书）。",
            "网络环境正常。",
            "✅ 关闭不需要的代理 / VPN，删除未知证书。",
            ""
        ),
        "设备伪造" to ItemExplain(
            "检测到设备属性被修改（改机/伪装）。",
            "设备属性一致，无伪造痕迹。",
            "✅ 改机时需同步修改所有相关属性。",
            "Build 属性交叉验证"
        ),
        "应用完整性" to ItemExplain(
            "本应用的包体完整性存在异常。",
            "本应用包体完整。",
            "✅ 重新安装。",
            "APK 自身完整性"
        ),
        "运行时行为" to ItemExplain(
            "当前进程的运行时行为异常（线程/句柄/时钟）。",
            "运行时行为正常。",
            "⚠️ 重启 App，若持续异常需排查注入。",
            ""
        )
    )

    /**
     * 获取某检测项的解释
     * @param itemName 检测项名称
     * @param moduleName 模块名（用于兜底）
     */
    fun get(itemName: String, moduleName: String): ItemExplain {
        // 1) 精确匹配
        map[itemName]?.let { return it }

        // 2) 模糊匹配（包含关系）
        for ((k, v) in map) {
            if (itemName.contains(k) || k.contains(itemName)) return v
        }

        // 3) 按模块兜底
        return moduleDefaults[moduleName] ?: ItemExplain(
            "检测到异常，具体含义请参考检测原理。",
            "该项检测通过。",
            "请参考知识库中对应模块的说明。",
            ""
        )
    }
}
