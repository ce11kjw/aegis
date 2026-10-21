package com.ce11kjw.aegis.ui.screen

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.ce11kjw.aegis.BuildConfig
import com.ce11kjw.aegis.data.MODULES
import com.ce11kjw.aegis.ui.theme.StatusClean
import com.ce11kjw.aegis.ui.theme.StatusWarning
import com.ce11kjw.aegis.data.CheckReport
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material.icons.filled.Share

@Composable
fun SettingsScreen(
    report: CheckReport? = null,
    enabledModules: Set<Int> = MODULES.map { it.id }.toSet(),
    onToggleModule: (Int, Boolean) -> Unit = { _, _ -> },
    modifier: Modifier = Modifier
) {
    val ctx = LocalContext.current

    LazyColumn(
        modifier = modifier.fillMaxSize(),
        contentPadding = PaddingValues(start = 16.dp, end = 16.dp, top = 8.dp, bottom = 96.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        item {
            Column(Modifier.padding(vertical = 16.dp)) {
                Text("设置", fontSize = 28.sp, fontWeight = FontWeight.Bold)
                Spacer(Modifier.height(4.dp))
                Text(
                    "关于本应用与检测模块",
                    fontSize = 13.sp,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }

        // ---------- 模块概览 ----------
        item { SectionLabel("检测模块 · 可单独开关") }
        item {
            Surface(shape = RoundedCornerShape(14.dp), color = MaterialTheme.colorScheme.surface) {
                Column(Modifier.padding(vertical = 4.dp)) {
                    MODULES.forEachIndexed { index, m ->
                        val on = m.id in enabledModules
                        Row(
                            Modifier
                                .fillMaxWidth()
                                .padding(horizontal = 16.dp, vertical = 6.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Box(
                                Modifier
                                    .size(7.dp)
                                    .background(
                                        if (on) StatusClean else MaterialTheme.colorScheme.outline,
                                        androidx.compose.foundation.shape.CircleShape
                                    )
                            )
                            Spacer(Modifier.width(12.dp))
                            Column(Modifier.weight(1f)) {
                                Text(
                                    m.name,
                                    fontSize = 14.sp,
                                    color = if (on) MaterialTheme.colorScheme.onSurface
                                            else MaterialTheme.colorScheme.onSurfaceVariant
                                )
                                Text(
                                    m.desc,
                                    fontSize = 11.sp,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            }
                            Switch(
                                checked = on,
                                onCheckedChange = { onToggleModule(m.id, it) },
                                modifier = Modifier.height(28.dp)
                            )
                        }
                        if (index < MODULES.size - 1) {
                            HorizontalDivider(
                                modifier = Modifier.padding(start = 35.dp),
                                color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.4f)
                            )
                        }
                    }
                }
            }
        }
        item {
            Text(
                "关闭的模块不会参与扫描，可减少耗时。",
                fontSize = 11.sp,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(start = 4.dp, top = 2.dp)
            )
        }

        // ---------- 报告导出 ----------
        item { SectionLabel("报告导出") }
        item {
            Surface(shape = RoundedCornerShape(14.dp), color = MaterialTheme.colorScheme.surface) {
                Column {
                    ExportRow(
                        title = "导出为 TXT",
                        subtitle = "纯文本，适合阅读与分享",
                        enabled = report != null,
                        onClick = {
                            report?.let {
                                val f = com.ce11kjw.aegis.data.ReportExporter.exportTxt(ctx, it)
                                com.ce11kjw.aegis.data.ReportExporter.share(ctx, f)
                            }
                        }
                    )
                    HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
                    ExportRow(
                        title = "导出为 JSON",
                        subtitle = "结构化数据，供程序处理",
                        enabled = report != null,
                        onClick = {
                            report?.let {
                                val f = com.ce11kjw.aegis.data.ReportExporter.exportJson(ctx, it)
                                com.ce11kjw.aegis.data.ReportExporter.share(ctx, f)
                            }
                        }
                    )
                    HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
                    ExportRow(
                        title = "导出为 HTML",
                        subtitle = "带样式，适合截图分享",
                        enabled = report != null,
                        onClick = {
                            report?.let {
                                val f = com.ce11kjw.aegis.data.ReportExporter.exportHtml(ctx, it)
                                com.ce11kjw.aegis.data.ReportExporter.share(ctx, f)
                            }
                        }
                    )
                }
            }
        }

        // ---------- 关于 ----------
        item { SectionLabel("关于") }
        item {
            Surface(shape = RoundedCornerShape(14.dp), color = MaterialTheme.colorScheme.surface) {
                Column {
                    InfoRow("版本", "v${BuildConfig.VERSION_NAME} (${BuildConfig.VERSION_CODE})")
                    InfoRow("检测项", "181 项 · 10 模块")
                    InfoRow("引擎", "libaegis.so (Native C)")
                    InfoRow("隐私", "全部本地检测，不上传数据")
                }
            }
        }

        // ---------- 说明 ----------
        item {
            Surface(
                shape = RoundedCornerShape(14.dp),
                color = StatusWarning.copy(alpha = 0.08f)
            ) {
                Row(Modifier.padding(16.dp)) {
                    Icon(
                        Icons.Filled.Info,
                        contentDescription = null,
                        tint = StatusWarning,
                        modifier = Modifier.size(18.dp)
                    )
                    Spacer(Modifier.width(10.dp))
                    Text(
                        "本应用仅用于检测自身运行环境，不收集任何个人信息，不修改系统设置。部分检测项在定制 ROM 上可能产生误报，请结合实际情况判断。",
                        fontSize = 12.sp,
                        lineHeight = 18.sp,
                        color = MaterialTheme.colorScheme.onSurface
                    )
                }
            }
        }
    }
}

@Composable
private fun SectionLabel(text: String) {
    Text(
        text,
        fontSize = 12.sp,
        fontWeight = FontWeight.SemiBold,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        modifier = Modifier.padding(top = 12.dp, bottom = 2.dp, start = 4.dp)
    )
}

@Composable
private fun InfoRow(label: String, value: String) {
    Row(
        Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(
            label,
            fontSize = 14.sp,
            color = MaterialTheme.colorScheme.onSurface,
            modifier = Modifier.width(72.dp)
        )
        Text(
            value,
            fontSize = 13.sp,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}

@Composable
private fun ExportRow(
    title: String,
    subtitle: String,
    enabled: Boolean,
    onClick: () -> Unit
) {
    Row(
        Modifier
            .fillMaxWidth()
            .clickable(enabled = enabled, onClick = onClick)
            .padding(horizontal = 16.dp, vertical = 14.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Icon(
            imageVector = Icons.Filled.Share,
            contentDescription = null,
            tint = if (enabled) MaterialTheme.colorScheme.primary
                   else MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.4f),
            modifier = Modifier.size(20.dp)
        )
        Spacer(Modifier.width(14.dp))
        Column(Modifier.weight(1f)) {
            Text(
                title,
                fontSize = 15.sp,
                color = if (enabled) MaterialTheme.colorScheme.onSurface
                        else MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.5f)
            )
            Text(
                subtitle,
                fontSize = 12.sp,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
        if (!enabled) {
            Text(
                "需先检测",
                fontSize = 11.sp,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}
