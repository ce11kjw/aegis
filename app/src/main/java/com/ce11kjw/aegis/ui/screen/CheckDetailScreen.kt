package com.ce11kjw.aegis.ui.screen

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Build
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.ce11kjw.aegis.data.CheckItem
import com.ce11kjw.aegis.data.CheckReport
import com.ce11kjw.aegis.data.ItemExplains
import com.ce11kjw.aegis.ui.component.color
import com.ce11kjw.aegis.ui.theme.*

/**
 * 检测详情页（v4.6 重构）
 *
 * 结构：
 *  1. 状态卡（等级 + 名称 + 模块）
 *  2. 🔍 检测到了什么（evidence 原文）
 *  3. 💡 意味着什么（ItemExplains.meaning）
 *  4. 🛠️ 如何解决（ItemExplains.fix）
 *  5. 📚 相关知识（跳知识库）
 *
 * 已移除「同模块其他检测项」列表。
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun CheckDetailScreen(
    item: CheckItem,
    report: CheckReport?,
    onBack: () -> Unit,
    onOpenKnowledge: ((String) -> Unit)? = null,
    modifier: Modifier = Modifier
) {
    val statusColor = item.status.color()
    val explain = remember(item) { ItemExplains.get(item.name, item.moduleName) }

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
            contentPadding = PaddingValues(start = 16.dp, end = 16.dp, bottom = 32.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            // ── 1. 状态卡 ──
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
                                text = if (item.isRisk) "${item.levelStr}风险" else "通过",
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

            // ── 2. 检测到了什么 ──
            item {
                SectionCard(
                    icon = Icons.Filled.Search,
                    title = "检测到了什么",
                    iconTint = if (item.isRisk) StatusWarning else StatusClean
                ) {
                    if (item.evidence.isNotBlank()) {
                        Text(
                            text = item.evidence,
                            fontSize = 13.sp,
                            fontFamily = FontFamily.Monospace,
                            lineHeight = 20.sp,
                            color = MaterialTheme.colorScheme.onSurface
                        )
                    } else {
                        Text(
                            text = if (item.isRisk) "（本次检测未提供详细证据）" else "未发现异常",
                            fontSize = 13.sp,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
            }

            // ── 3. 意味着什么 ──
            item {
                SectionCard(
                    icon = Icons.Filled.Info,
                    title = "这意味着什么",
                    iconTint = StatusInfo
                ) {
                    Text(
                        text = if (item.isRisk) explain.meaningHit else explain.meaningClean,
                        fontSize = 13.sp,
                        lineHeight = 20.sp,
                        color = MaterialTheme.colorScheme.onSurface
                    )
                }
            }

            // ── 4. 如何解决 ──
            item {
                SectionCard(
                    icon = Icons.Filled.Build,
                    title = "如何解决",
                    iconTint = if (item.isRisk) StatusClean else MaterialTheme.colorScheme.onSurfaceVariant
                ) {
                    Text(
                        text = explain.fix,
                        fontSize = 13.sp,
                        lineHeight = 20.sp,
                        color = MaterialTheme.colorScheme.onSurface
                    )
                }
            }

            // ── 5. 相关知识 ──
            if (explain.kbRef.isNotEmpty() && onOpenKnowledge != null) {
                item {
                    Surface(
                        shape = RoundedCornerShape(14.dp),
                        color = MaterialTheme.colorScheme.surface,
                        onClick = { onOpenKnowledge(explain.kbRef) }
                    ) {
                        Row(
                            Modifier
                                .fillMaxWidth()
                                .padding(16.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text(
                                "📚 相关知识",
                                fontSize = 13.sp,
                                fontWeight = FontWeight.SemiBold,
                                color = MaterialTheme.colorScheme.primary
                            )
                            Spacer(Modifier.weight(1f))
                            Text(
                                explain.kbRef,
                                fontSize = 12.sp,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                maxLines = 1
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun SectionCard(
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    title: String,
    iconTint: androidx.compose.ui.graphics.Color,
    content: @Composable ColumnScope.() -> Unit
) {
    Surface(
        shape = RoundedCornerShape(14.dp),
        color = MaterialTheme.colorScheme.surface
    ) {
        Column(Modifier.padding(16.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    icon,
                    contentDescription = null,
                    tint = iconTint,
                    modifier = Modifier.size(16.dp)
                )
                Spacer(Modifier.width(8.dp))
                Text(
                    title,
                    fontSize = 12.sp,
                    fontWeight = FontWeight.SemiBold,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            Spacer(Modifier.height(10.dp))
            content()
        }
    }
}
