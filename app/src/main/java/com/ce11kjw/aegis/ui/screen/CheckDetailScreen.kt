package com.ce11kjw.aegis.ui.screen

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.ce11kjw.aegis.data.CheckItem
import com.ce11kjw.aegis.data.CheckReport
import com.ce11kjw.aegis.ui.component.color
import com.ce11kjw.aegis.ui.component.scoreColor
import com.ce11kjw.aegis.ui.component.scoreLabel
import com.ce11kjw.aegis.ui.theme.*

/**
 * 检测详情页（v4.0 新增）
 *
 * 从主页点某个检测项进入，展示：
 *  - 该项的完整信息（模块 / 等级 / 证据）
 *  - 同模块的其他项（上下文）
 *  - 该项的判定逻辑说明
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun CheckDetailScreen(
    item: CheckItem,
    report: CheckReport?,
    onBack: () -> Unit,
    modifier: Modifier = Modifier
) {
    val statusColor = item.status.color()
    val siblings = remember(report, item) {
        report?.items?.filter { it.module == item.module && it.name != item.name }
            ?.sortedByDescending { it.level }
            ?: emptyList()
    }

    Scaffold(
        containerColor = MaterialTheme.colorScheme.background,
        topBar = {
            TopAppBar(
                title = { Text("检测详情", fontSize = 17.sp) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, "返回")
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.background
                )
            )
        }
    ) { padding ->
        LazyColumn(
            modifier = modifier
                .fillMaxSize()
                .padding(padding),
            contentPadding = PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            // ── 状态卡 ──
            item {
                Surface(
                    shape = RoundedCornerShape(16.dp),
                    color = MaterialTheme.colorScheme.surface
                ) {
                    Column(Modifier.padding(20.dp)) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Box(
                                Modifier
                                    .size(12.dp)
                                    .background(statusColor, RoundedCornerShape(6.dp))
                            )
                            Spacer(Modifier.width(10.dp))
                            Text(
                                text = if (item.isRisk) item.levelStr + "风险" else "通过",
                                fontSize = 13.sp,
                                color = statusColor,
                                fontWeight = FontWeight.SemiBold
                            )
                        }
                        Spacer(Modifier.height(12.dp))
                        Text(
                            text = item.name,
                            fontSize = 20.sp,
                            fontWeight = FontWeight.Bold,
                            color = MaterialTheme.colorScheme.onSurface
                        )
                        Spacer(Modifier.height(6.dp))
                        Text(
                            text = item.moduleName,
                            fontSize = 12.sp,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
            }

            // ── 证据 ──
            if (item.evidence.isNotBlank()) {
                item {
                    Surface(
                        shape = RoundedCornerShape(14.dp),
                        color = MaterialTheme.colorScheme.surface
                    ) {
                        Column(Modifier.padding(16.dp)) {
                            Text(
                                "证据",
                                fontSize = 12.sp,
                                fontWeight = FontWeight.SemiBold,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                            Spacer(Modifier.height(8.dp))
                            Text(
                                text = item.evidence,
                                fontSize = 13.sp,
                                fontFamily = FontFamily.Monospace,
                                lineHeight = 20.sp,
                                color = MaterialTheme.colorScheme.onSurface
                            )
                        }
                    }
                }
            }

            // ── 判定说明 ──
            item {
                val desc = explain(item.name)
                if (desc != null) {
                    Surface(
                        shape = RoundedCornerShape(14.dp),
                        color = MaterialTheme.colorScheme.surface
                    ) {
                        Column(Modifier.padding(16.dp)) {
                            Text(
                                "判定逻辑",
                                fontSize = 12.sp,
                                fontWeight = FontWeight.SemiBold,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                            Spacer(Modifier.height(8.dp))
                            Text(
                                text = desc,
                                fontSize = 13.sp,
                                lineHeight = 20.sp,
                                color = MaterialTheme.colorScheme.onSurface
                            )
                        }
                    }
                }
            }

            // ── 同模块其他项 ──
            if (siblings.isNotEmpty()) {
                item {
                    Text(
                        text = "${item.moduleName} · 其他检测项（${siblings.size}）",
                        fontSize = 12.sp,
                        fontWeight = FontWeight.SemiBold,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(top = 8.dp, start = 4.dp)
                    )
                }
                items(siblings) { sib ->
                    SiblingRow(sib)
                }
            }
        }
    }
}

@Composable
private fun SiblingRow(item: CheckItem) {
    val color = item.status.color()
    Surface(
        shape = RoundedCornerShape(10.dp),
        color = MaterialTheme.colorScheme.surface
    ) {
        Row(
            Modifier
                .fillMaxWidth()
                .padding(horizontal = 14.dp, vertical = 11.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Box(Modifier.size(6.dp).background(color, RoundedCornerShape(3.dp)))
            Spacer(Modifier.width(10.dp))
            Text(
                item.name,
                fontSize = 13.sp,
                color = MaterialTheme.colorScheme.onSurface,
                modifier = Modifier.weight(1f)
            )
            Text(
                if (item.isRisk) item.levelStr else "OK",
                fontSize = 11.sp,
                color = color
            )
        }
    }
}

/** 检测项判定逻辑说明（按名称匹配） */
private fun explain(name: String): String? = when {
    name.contains("Build属性一致性") ->
        "读取 ro.product.model / brand / manufacturer / device / product / board 六个属性，\n" +
        "两两交叉验证。改机工具通常只改其中 1-2 个字段，导致字段间矛盾。\n" +
        "判定：矛盾 ≥ 2 处 → 高风险。"

    name.contains("序列号一致性") ->
        "对比三个来源的序列号：\n" +
        "  · ro.serialno（Build.getSerial 使用）\n" +
        "  · ro.boot.serialno（bootloader 传入）\n" +
        "  · ro.vendor.oem.serialno（厂商写入）\n" +
        "三者应完全相同。不一致说明有属性被 resetprop 改过。"

    name.contains("libc内存磁盘校验") ->
        "从 /proc/self/maps 定位 libc.so 的可执行段，读取内存前 8KB，\n" +
        "与磁盘上 libc.so 对应偏移的字节做 FNV-1a 哈希比对。\n" +
        "任何 inline hook（Frida / Xposed）都会修改内存指令，导致哈希不一致。\n" +
        "不一致时再用 1KB 二次确认，避免巧合误报。"

    name.contains("Shamiko") ->
        "Shamiko 是 Magisk 的 Zygisk 隐藏模块。检测点：\n" +
        "  · /data/adb/modules/shamiko 目录\n" +
        "  · module.prop 中的 description 字段\n" +
        "  · Magisk 的 DenyList 配置痕迹\n" +
        "Shamiko 会主动隐藏自身，但模块目录本身通常还在。"

    name.contains("APatch") ->
        "APatch 基于 KernelPatch，特征与 Magisk/KSU 不同：\n" +
        "  · /data/adb/ap/ 目录（含 kptools、selinux_hide、pathhide）\n" +
        "  · apd 守护进程\n" +
        "  · superkey 系统调用\n" +
        "APatch 不易被传统 Root 检测发现，需专门检测。"

    name.contains("ZygiskNext") ->
        "Zygisk Next 是独立的 Zygisk 实现，不依赖 Magisk。\n" +
        "特征：\n" +
        "  · /data/adb/zygisksu/ 目录（伪装成 ksu 目录）\n" +
        "  · zygiskd / zygiskd64 守护进程\n" +
        "  · 因不通过 magiskd，传统 Magisk 检测无法发现。"

    name.contains("匿名可执行映射") ->
        "遍历 /proc/self/maps，统计权限为 r-x 且无 pathname 的映射段。\n" +
        "正常 App 有少量（ART JIT 生成），通常 < 5 条。\n" +
        "注入框架（Frida、内存加载的 so）会产生更多匿名可执行段。\n" +
        "判定：> 8 条 → 高风险。"

    name.contains("信号处理器劫持") ->
        "读取 /proc/self/status 的 SigCgt 字段（捕获的信号位掩码）。\n" +
        "SIGTRAP（信号 5，bit 4）通常只有调试器会捕获。\n" +
        "App 正常不会捕获 SIGTRAP，若置位说明有调试/反调试工具。"

    name.contains("ZIP结构完整性") ->
        "读取 APK 文件末尾，查找 EOCD（End of Central Directory）。\n" +
        "魔数：PK\\x05\\x06（0x504B0506）。\n" +
        "重打包工具若处理不当会破坏 ZIP 结构，导致找不到 EOCD。"

    name.contains("定时器漂移") ->
        "同时采样 CLOCK_REALTIME 与 CLOCK_MONOTONIC，自旋等待约 5ms 后再次采样。\n" +
        "两个时钟的前进量应当一致（差值 < 50ms）。\n" +
        "用自旋而非 sleep，避免 sleep 本身被 hook。"

    name.contains("TracerPid") ->
        "读取 /proc/self/status 的 TracerPid 字段。\n" +
        "非 0 表示当前进程被 ptrace 附加（调试器/注入器）。\n" +
        "这是最经典的反调试检测，但也最容易被 hook 绕过。"

    name.contains("su二进制") ->
        "检查常见 su 路径是否存在：\n" +
        "  /system/bin/su, /system/xbin/su, /sbin/su,\n" +
        "  /su/bin/su, /data/local/bin/su 等 9 个路径。\n" +
        "现代 Root 方案（Magisk/KSU/APatch）通常不在这些位置留 su，\n" +
        "所以单靠此项已不足以判定 Root。"

    else -> null
}
