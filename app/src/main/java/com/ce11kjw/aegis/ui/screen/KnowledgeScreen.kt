package com.ce11kjw.aegis.ui.screen

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.Spring
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.spring
import androidx.compose.animation.core.tween
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ExpandMore
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.rotate
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.ce11kjw.aegis.ui.theme.StatusWarning
import androidx.compose.animation.animateContentSize

data class KnowledgeEntry(
    val title: String,
    val category: String,
    val summary: String,
    val detail: String
)

val KNOWLEDGE = listOf(
    KnowledgeEntry(
        "什么是 Root 检测？", "基础概念",
        "判断设备是否具有超级用户权限，是安全评估的第一步。",
        "Root 检测通常包含三类手段：\n\n" +
        "1. 文件检测：检查 su 二进制、Magisk 目录等已知路径是否存在。\n" +
        "2. 行为检测：尝试执行 su 命令，看是否返回 uid=0。\n" +
        "3. 属性检测：检查 ro.build.tags、ro.debuggable 等系统属性是否符合官方值。\n\n" +
        "现代 Root 方案（Magisk/KernelSU/APatch）会主动隐藏上述痕迹，因此需要更深入的检测，例如检测挂载表异常、进程残留、内核符号等。"
    ),
    KnowledgeEntry(
        "APatch 与 Magisk 的区别", "框架对比",
        "APatch 基于内核补丁，Magisk 基于 systemless 挂载。",
        "Magisk：\n" +
        "• 通过 magiskd 守护进程 + overlayfs 实现 systemless 修改\n" +
        "• 特征：/data/adb/magisk、/sbin/.magisk、magiskd 进程\n\n" +
        "KernelSU：\n" +
        "• 内核态实现，通过 GKI 内核模块注入\n" +
        "• 特征：/data/adb/ksu、ksud 进程、内核符号 ksu_*\n\n" +
        "APatch：\n" +
        "• 基于 KernelPatch，直接打内核补丁\n" +
        "• 特征：/data/adb/ap、apd 进程、kptools、superkey 系统调用\n" +
        "• 优点：无需解锁 bootloader 分区修改，更难被检测"
    ),
    KnowledgeEntry(
        "Zygisk Next 是什么", "框架对比",
        "独立实现的 Zygisk，不依赖 Magisk。",
        "Zygisk Next 是 Zygisk 的独立实现，可以在 KernelSU / APatch 上运行。\n\n" +
        "它与 Magisk 内置 Zygisk 的区别：\n" +
        "• 完全独立的守护进程 zygiskd\n" +
        "• 数据目录 /data/adb/zygisksu（伪装成 ksu 目录）\n" +
        "• 不与 magiskd 通信，因此检测 Magisk 无法发现它\n\n" +
        "检测要点：\n" +
        "• 目录存在性：/data/adb/zygisksu/module.prop\n" +
        "• 进程扫描：zygiskd / zygiskd64\n" +
        "• 注入痕迹：zygote 进程的匿名内存映射"
    ),
    KnowledgeEntry(
        "Frida 检测原理", "注入检测",
        "Frida 是动态插桩框架，会在进程中留下多种痕迹。",
        "常见检测点：\n\n" +
        "1. 线程名：gum-js-loop、gmain、gdbus 是 Frida 的运行时线程\n" +
        "2. 命名管道：linjector 是 Frida 的注入器管道\n" +
        "3. 端口：Frida Server 默认监听 27042/27043\n" +
        "4. 内存映射：/proc/self/maps 中出现 frida-agent.so\n" +
        "5. 代码段校验：Frida 会 inline hook libc，导致内存与磁盘不一致\n\n" +
        "最硬核的方法是内联内存校验：直接读取 libc 的 .text 段，与磁盘文件比对哈希。任何 inline hook 都会导致差异。"
    ),
    KnowledgeEntry(
        "SELinux 的作用", "系统安全",
        "强制访问控制机制，限制进程能访问哪些资源。",
        "SELinux 有三种状态：\n" +
        "• Enforcing：强制执行，违规操作被拒绝\n" +
        "• Permissive：只记录不阻止\n" +
        "• Disabled：完全关闭\n\n" +
        "Root 方案常见的 SELinux 操作：\n" +
        "• 将 su 域设为 permissive\n" +
        "• 添加自定义规则（如允许 untrusted_app 读 ksu_file）\n" +
        "• 通过 magiskpolicy --live 运行时修改\n\n" +
        "检测要点：\n" +
        "• /sys/fs/selinux/enforce 是否为 1\n" +
        "• getenforce 输出\n" +
        "• 关键规则是否被放开（如 untrusted_app → ksu_file）"
    ),
    KnowledgeEntry(
        "TEE 与 Key Attestation", "硬件安全",
        "可信执行环境提供硬件级证明，是最终极的检测手段。",
        "TEE（Trusted Execution Environment）是独立于 Android 的安全执行环境。\n\n" +
        "Key Attestation 原理：\n" +
        "• 向 TEE 请求生成密钥对\n" +
        "• TEE 签发证书链，包含设备状态（RootOfTrust）\n" +
        "• RootOfTrust 字段：\n" +
        "  - deviceLocked：bootloader 是否锁定\n" +
        "  - verifiedBootState：green 表示完整启动链\n" +
        "  - verifiedBootKey：验证启动公钥指纹\n\n" +
        "优势：属性可以被 resetprop 伪造，但 TEE 证书由硬件密钥签名，无法伪造。\n\n" +
        "局限：需要联网验证证书链（GrapheneOS Auditor 用远端服务）。"
    ),
    KnowledgeEntry(
        "模拟器检测方法", "环境识别",
        "通过硬件特征、属性、文件等多维度识别虚拟环境。",
        "主要特征：\n\n" +
        "1. 属性：ro.kernel.qemu=1、ro.hardware=goldfish、ro.product.model=sdk\n" +
        "2. 文件：/dev/socket/qemud、/system/lib/libc_malloc_debug_qemu.so\n" +
        "3. 网段：QEMU 默认使用 10.0.2.0/24\n" +
        "4. 硬件：传感器数量少、CPU 核心数异常、无基带\n" +
        "5. 电话号段：15555215554-15555215584（模拟器默认）\n\n" +
        "误报控制：单一特征容易误判，通常采用多点投票，命中 ≥5 条才判定为模拟器。"
    ),
    KnowledgeEntry(
        "为什么检测会误报", "使用建议",
        "部分检测项在特定机型上可能产生误判。",
        "常见误报原因：\n\n" +
        "1. 定制 ROM：类原生系统（LineageOS、Pixel Experience）会修改系统属性，可能触发部分检测。\n" +
        "2. 厂商加固：部分手机厂商会自行修改 SELinux 策略，导致规则检测误判。\n" +
        "3. 开发者选项：开启 USB 调试、允许 Mock 位置等会触发相应检测。\n" +
        "4. 系统更新：OTA 更新期间属性文件被重写，可能触发属性时间检测。\n\n" +
        "建议：关注「严重」级别项，对「警告」级别结合实际情况判断。"
    )
)

@Composable
fun KnowledgeScreen(modifier: Modifier = Modifier) {
    LazyColumn(
        modifier = modifier.fillMaxSize(),
        contentPadding = PaddingValues(start = 16.dp, end = 16.dp, top = 8.dp, bottom = 96.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        item {
            Column(Modifier.padding(vertical = 16.dp)) {
                Text(
                    "知识库",
                    fontSize = 28.sp,
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.onBackground
                )
                Spacer(Modifier.height(4.dp))
                Text(
                    "了解各项检测背后的原理",
                    fontSize = 13.sp,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
        items(KNOWLEDGE) { entry ->
            KnowledgeCard(entry)
        }
    }
}

@Composable
private fun KnowledgeCard(entry: KnowledgeEntry) {
    var expanded by remember { mutableStateOf(false) }
    val rotation by animateFloatAsState(
        targetValue = if (expanded) 180f else 0f,
        animationSpec = tween(250),
        label = "k-arrow"
    )

    Surface(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(14.dp),
        color = MaterialTheme.colorScheme.surface
    ) {
        Column(
            Modifier.animateContentSize(
                animationSpec = spring(
                    dampingRatio = Spring.DampingRatioLowBouncy,
                    stiffness = Spring.StiffnessMediumLow
                )
            )
        ) {
            Row(
                Modifier
                    .fillMaxWidth()
                    .clickable { expanded = !expanded }
                    .padding(16.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column(Modifier.weight(1f)) {
                    Text(
                        entry.title,
                        fontSize = 15.sp,
                        fontWeight = FontWeight.Medium,
                        color = MaterialTheme.colorScheme.onSurface
                    )
                    Spacer(Modifier.height(4.dp))
                    Box(
                        Modifier
                            .background(
                                StatusWarning.copy(alpha = 0.12f),
                                RoundedCornerShape(4.dp)
                            )
                            .padding(horizontal = 6.dp, vertical = 2.dp)
                    ) {
                        Text(
                            entry.category,
                            fontSize = 10.sp,
                            color = StatusWarning
                        )
                    }
                    Spacer(Modifier.height(6.dp))
                    Text(
                        entry.summary,
                        fontSize = 12.sp,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        lineHeight = 17.sp
                    )
                }
                Icon(
                    Icons.Filled.ExpandMore,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier
                        .size(20.dp)
                        .rotate(rotation)
                )
            }

            AnimatedVisibility(
                visible = expanded,
                enter = expandVertically(tween(240)) + fadeIn(tween(200)),
                exit = shrinkVertically(tween(200)) + fadeOut(tween(150))
            ) {
                Box(
                    Modifier
                        .fillMaxWidth()
                        .background(MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.4f))
                        .padding(16.dp)
                ) {
                    Text(
                        entry.detail,
                        fontSize = 12.sp,
                        color = MaterialTheme.colorScheme.onSurface,
                        lineHeight = 19.sp
                    )
                }
            }
        }
    }
}
