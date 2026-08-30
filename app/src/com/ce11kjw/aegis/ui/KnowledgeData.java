package com.ce11kjw.aegis.ui;

/**
 * KnowledgeData - 安全知识库数据源
 * 首页检测详情 + 知识库页 共用同一份技术文档
 * 每项包含: 原理 / 攻击场景 / 证据解读 / 防御建议
 */
public class KnowledgeData {

    public static final String[] MODULE_NAMES = {
        "反调试", "Frida注入", "Xposed/Zygisk", "完整性", "模拟器", "Root", "系统环境", "网络环境"
    };

    /** 返回某检测项的知识卡: [原理, 攻击场景, 证据解读, 防御建议] */
    public static String[] itemInfo(String name) {
        String[] base = baseInfo(name);
        return base;
    }

    private static String[] baseInfo(String n) {
        // [原理, 攻击场景, 证据解读, 防御建议]
        if (n.contains("TracerPid")) return new String[]{
            "Android 的 /proc/self/status 中 TracerPid 字段记录了当前进程被哪个 PID 跟踪。正常应用该值为 0，一旦被调试器 attach 就会变为调试器 PID。",
            "攻击者使用 gdb / lldb / IDA 附加进程，单步调试、读取内存、修改寄存器，逆向核心逻辑。",
            "TracerPid > 0 且不是本进程自身，即为被调试的强证据。",
            "检测到后立即终止敏感操作，可向服务器上报该 PID 供追踪。"};

        if (n.contains("ptrace")) return new String[]{
            "ptrace 是 Linux 的进程跟踪系统调用，同一时刻一个进程只能被一个调试器跟踪。引擎尝试 attach 自身，若返回 EPERM 说明已被抢占。",
            "攻击者先用 ptrace attach 目标，阻止其自我检测，掩护后续 hook 操作。",
            "ptrace(PTRACE_ATTACH, self) 返回 EPERM = 已被外部跟踪。",
            "检测到抢占后进入对抗流程：混淆执行路径、拖延关键逻辑。"};

        if (n.contains("父进程")) return new String[]{
            "正常 Android 应用由 zygote 进程 fork 产生。若父进程不是 zygote 家族，说明进程被异常方式拉起。",
            "通过定制注入器（如 fork + exec）启动应用，绕过正常启动流程。",
            "父进程 comm 不是 zygote/init 即异常。",
            "校验父进程链，异常则判定为可疑启动。"};

        if (n.contains("时间差")) return new String[]{
            "被调试时每条指令都经过调试器，执行基准运算耗时显著增加。通过计时探测执行环境。",
            "单步调试会让代码逐条执行，100 万次加法耗时从毫秒级暴涨到秒级。",
            "基准运算耗时超过正常阈值（如 100ms）即怀疑被单步。",
            "耗时异常时进入随机延迟 + 假路径，干扰逆向。"};

        if (n.contains("调试器进程")) return new String[]{
            "扫描 /proc 下所有进程的 comm，识别 gdb/lldb/ida 等已知调试器进程。",
            "攻击者在设备上运行调试器 server，通过端口转发远程附加。",
            "发现 gdb / lldb / android_server 等进程名。",
            "发现调试进程即判定环境不可信，可提示用户关闭。"};

        if (n.contains("inline")) return new String[]{
            "inline hook 会改写函数开头的机器码（通常跳转到 hook 函数）。通过比对关键函数头指令检测是否被改。",
            "Frida / xhook / bhook 等工具通过 inline hook 拦截系统调用与应用函数。",
            "关键函数前几条指令与预期不符（如缺少标准 prologue）。",
            "对关键函数做只读映射 + 周期校验，发现改写立即告警。"};

        if (n.contains("内存映射")) return new String[]{
            "扫描 /proc/self/maps 中的已加载库，frida/xposed/zygisk 的 so 库会留下独特映射路径。",
            "Frida 通过 ptrace + 内存注入将 frida-agent.so 打入进程，留下明显映射特征。",
            "maps 中出现 frida-agent / gum-js / libgadget 等路径段。",
            "发现特征映射即判定被注入，建议退出并告警。"};

        if (n.contains("特征线程")) return new String[]{
            "Frida 注入后会创建专属工作线程（如 gum-js-loop、gmain）负责 JS 解释与消息循环。",
            "攻击者用 frida 的脚本引擎注入 JS 代码，需线程承载。",
            "进程线程列表中扫描到 frida 特征线程名。",
            "扫描 /proc/self/task 下所有线程 comm，命中即告警。"};

        if (n.contains("D-Bus")) return new String[]{
            "Frida-server 默认监听 27042 端口，使用 D-Bus 协议通信。探测本地端口可发现。",
            "攻击者运行 frida-server 并让客户端连入控制目标进程。",
            "本地 27042/27043 端口有 D-Bus 响应（REJECTED/AUTH 等）。",
            "探测到 D-Bus 服务即判定存在 frida-server，可尝试反制。"};

        if (n.contains("套接字")) return new String[]{
            "分析 /proc/net/tcp 与进程打开的 socket，寻找异常连接特征。",
            "注入工具会建立本地 socket 用于回传数据或接收指令。",
            "检测到进程打开异常本地 socket。",
            "配合端口扫描交叉验证。"};

        if (n.contains("特征文件")) return new String[]{
            "Frida 工具的 server 二进制、辅助脚本常留在 /data/local/tmp 等可写目录。",
            "攻击者将 frida-server、linjector 等工具放入临时目录并启动。",
            "检查到 /data/local/tmp/frida-server 等特征文件存在。",
            "发现特征文件即提示存在注入工具链。"};

        if (n.contains("环境变量")) return new String[]{
            "Frida 注入会向进程环境注入 FRIDA_ 前缀的变量用于传参。",
            "通过环境变量传递脚本路径、配置给注入的 agent。",
            "进程 environ 中出现 FRIDA_ / GUM_ 前缀变量。",
            "检查 environ 前缀即可快速判断。"};

        if (n.contains("系统属性")) return new String[]{
            "ro.dalvik.vm.native.bridge 属性用于加载跨架构桥接库，Xposed 类框架常修改此属性挂载注入。",
            "Xposed / LSPosed 通过修改 native.bridge 指向自己的 so 实现框架加载。",
            "native.bridge 属性值不为 0 或指向非系统库。",
            "校验系统关键属性，异常即判定框架被篡改。"};

        if (n.contains("模块路径")) return new String[]{
            "Xposed/LSPosed 模块安装后会在 /data/adb/modules 或数据目录留下特征目录。",
            "攻击者安装 Xposed 框架与模块，hook 目标应用。",
            "发现 riru_ / zygisk_ / lsposed / xposed 等特征目录。",
            "扫描特征目录即可快速判定框架存在。"};

        if (n.contains("Zygisk")) return new String[]{
            "Magisk 的 Zygisk 会在 zygote 进程注入 so，进而影响所有子进程。",
            "攻击者通过 Zygisk 实现系统级 hook，注入面覆盖所有应用。",
            "进程内存加载了 zygisk 相关 so。",
            "检测到 Zygisk 说明存在 Magisk + 注入框架组合。"};

        if (n.contains("自身路径")) return new String[]{
            "通过 /proc/self/exe 获取进程真实可执行路径，用于后续完整性校验。",
            "被注入的应用可能被重定向到替身可执行文件。",
            "自身路径与预期安装路径不一致。",
            "记录基路径，配合哈希校验。"};

        if (n.contains("匿名可执行")) return new String[]{
            "正常进程的代码映射来自已签名文件；rwx 的匿名可执行映射通常是动态生成的 shellcode。",
            "攻击者 mmap 一块 rwx 内存写入 shellcode 并跳转执行，绕过文件检测。",
            "maps 中出现多个无文件背景的 rwx 匿名映射。",
            "限制匿名可执行映射数量，异常即告警。"};

        if (n.contains("W+X")) return new String[]{
            "安全的 so 库只读执行（r-x）。若 so 以可写可执行（rwx）加载，说明被动态修改。",
            "攻击者修改 so 的段权限以便写入 hook 代码。",
            "maps 中 .so 出现 rwx 或 rwxp 权限段。",
            "W+X 权限是严重异常，直接判定被篡改。"};

        if (n.contains("哈希")) return new String[]{
            "对自身 DEX / so 计算 SHA-256，与签名或出厂值比对。",
            "重打包、加壳脱壳、二进制补丁都会改变文件哈希。",
            "当前哈希与基准哈希不一致。",
            "完整性失败即提示重装或判定被篡改。"};

        if (n.contains("Build")) return new String[]{
            "模拟器固件的 Build 字段常包含 sdk_gphone / emulator / Genymotion 等特征。",
            "攻击者在模拟器中运行应用，规避设备限制或批量刷量。",
            "ro.product.model 命中已知模拟器指纹。",
            "命中即判定模拟器环境。"};

        if (n.contains("硬件平台")) return new String[]{
            "模拟器硬件抽象层固定为 goldfish / ranchu，与真实 SoC 平台不同。",
            "模拟器使用虚拟硬件，无法模拟真实芯片标识。",
            "ro.hardware 为 goldfish/ranchu 等模拟器平台。",
            "硬件平台是模拟器的强特征。"};

        if (n.contains("属性联动")) return new String[]{
            "真实设备的品牌、型号、硬件属性互相一致；模拟器常伪造出矛盾组合。",
            "模拟器伪装成某品牌，但硬件层仍暴露真实虚拟平台。",
            "品牌是 HUAWEI 但硬件是 ranchu 等矛盾组合。",
            "多属性交叉验证，矛盾即判定模拟器。"};

        if (n.contains("CPU核心")) return new String[]{
            "现代手机 CPU 至少 4 核，模拟器虚拟机通常只分配 1-2 核。",
            "模拟器按主机资源分配 vCPU，核心数偏少。",
            "/proc/cpuinfo 中 processor 数量 < 2。",
            "核心数过少结合其他特征综合判断。"};

        if (n.contains("传感器")) return new String[]{
            "真实手机标配加速度、陀螺仪、磁力、光线等 5+ 传感器；模拟器几乎没有。",
            "模拟器无真实物理传感器。",
            "传感器数量 1-2 个甚至为 0。",
            "传感器稀缺是模拟器强特征。"};

        if (n.contains("运营商")) return new String[]{
            "真实设备插 SIM 卡后运营商字段非空；模拟器无 SIM。",
            "模拟器未插真实 SIM 卡。",
            "gsm.operator.alpha 为空。",
            "运营商为空结合其他特征判断。"};

        if (n.contains("su二进制")) return new String[]{
            "Root 后系统常见路径会放置 su 可执行文件用于提权。",
            "攻击者或用户通过 su 获取 root 权限执行敏感操作。",
            "/system/bin/su、/system/xbin/su 等路径存在。",
            "发现 su 即判定存在 root 能力。"};

        if (n.contains("Root管理器")) return new String[]{
            "Magisk / KernelSU / APatch 等 root 管理器会在 /data/adb 留下数据文件。",
            "设备安装 root 管理器后持续拥有提权能力。",
            "magisk.db、ksu.db、apd 目录等特征存在。",
            "发现 root 管理器即判定设备已 root。"};

        if (n.contains("test-keys")) return new String[]{
            "官方 ROM 使用 release-keys 签名，test-keys 是自定义编译固件特征。",
            "刷入第三方 ROM 后保留 test-keys 签名。",
            "ro.build.tags 包含 test-keys。",
            "test-keys 说明系统被刷改，可信度降低。"};

        if (n.contains("分区rw")) return new String[]{
            "正常系统分区只读挂载，Root 修改系统时需要以 rw 重新挂载。",
            "Root 工具重挂载 /system 或根分区以写入文件。",
            "/proc/mounts 中系统分区以 rw 挂载。",
            "系统分区可写说明被持久化修改。"};

        if (n.contains("su执行")) return new String[]{
            "尝试 fork 执行 su -c true，能成功说明 root 权限已授予当前应用。",
            "应用被授予 root 权限后可直接执行提权命令。",
            "su 命令返回成功（exit 0）。",
            "当前进程有 root 权限是最高风险信号。"};

        if (n.contains("调试状态")) return new String[]{
            "ro.debuggable=1 说明系统允许调试，工程机或调试版固件特征。",
            "调试版固件可被轻松附加调试，安全防护弱。",
            "ro.debuggable 为 1。",
            "调试版系统风险升高。"};

        if (n.contains("SELinux")) return new String[]{
            "SELinux enforcing 是 Android 默认安全机制，被禁用说明系统被改。",
            "攻击者禁用 SELinux 以绕过沙箱限制。",
            "ro.build.selinux 为 disabled。",
            "SELinux 禁用是严重系统异常。"};

        if (n.contains("编译类型")) return new String[]{
            "ro.build.type 为 user 是正式版，eng/userdebug 是开发版。",
            "开发版固件保留调试能力，更易被攻击。",
            "ro.build.type 为 eng 或 userdebug。",
            "非正式版固件可信度降低。"};

        if (n.contains("CapEff")) return new String[]{
            "普通应用 CapEff 应为 0；为全 1（0x3fffffffff）说明拥有全部内核能力。",
            "root 或注入后的进程拥有完整 capability，可执行特权操作。",
            "CapEff 为 0x3fffffffff 等特权值。",
            "特权 capability 是 root 或逃逸信号。"};

        if (n.contains("LD_PRELOAD")) return new String[]{
            "LD_PRELOAD 环境变量会强制预加载指定动态库，是经典注入手段。",
            "攻击者设置 LD_PRELOAD 劫持 libc 函数实现 hook。",
            "进程环境存在 LD_PRELOAD 且非空。",
            "LD_PRELOAD 注入可直接判定被篡改。"};

        return new String[]{"暂无详细说明", "暂无", "暂无", "根据风险等级评估"};
    }
}
