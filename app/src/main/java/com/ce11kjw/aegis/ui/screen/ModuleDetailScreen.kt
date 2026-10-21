package com.ce11kjw.aegis.ui.screen

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.animateContentSize
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
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.ExpandMore
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.rotate
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.ce11kjw.aegis.data.CheckItem
import com.ce11kjw.aegis.ui.component.color
import com.ce11kjw.aegis.ui.theme.*

/**
 * 模块详情页（v4.6 新增，三级导航的第 2 级）
 *
 * 展示某个模块下的全部检测项：
 *  - 顶部：模块名 + 命中统计
 *  - 命中的检测项（展开显示，可点进详情）
 *  - 未命中的检测项（默认折叠，可展开查看）
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ModuleDetailScreen(
    moduleName: String,
    items: List<CheckItem>,
    onBack: () -> Unit,
    onItemClick: (CheckItem) -> Unit,
    modifier: Modifier = Modifier
) {
    val hits = remember(items) { items.filter { it.isRisk }.sortedByDescending { it.level } }
    val clean = remember(items) { items.filter { !it.isRisk } }

    var showClean by remember { mutableStateOf(false) }

    Scaffold(
        containerColor = MaterialTheme.colorScheme.background,
        topBar = {
            TopAppBar(
                title = { Text(moduleName, fontSize = 17.sp) },
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
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            // ── 统计卡 ──
            item {
                Surface(
                    shape = RoundedCornerShape(14.dp),
                    color = MaterialTheme.colorScheme.surface
                ) {
                    Row(
                        Modifier
                            .fillMaxWidth()
                            .padding(20.dp),
                        horizontalArrangement = Arrangement.SpaceEvenly
                    ) {
                        StatCell("检测项", items.size, MaterialTheme.colorScheme.onSurface)
                        StatCell(
                            "命中",
                            hits.size,
                            if (hits.isEmpty()) StatusClean else StatusDanger
                        )
                        StatCell("通过", clean.size, StatusClean)
                    }
                }
            }

            // ── 命中的检测项 ──
            if (hits.isNotEmpty()) {
                item {
                    Text(
                        "发现的问题（${hits.size}）",
                        fontSize = 12.sp,
                        fontWeight = FontWeight.SemiBold,
                        color = StatusDanger,
                        modifier = Modifier.padding(top = 8.dp, start = 4.dp)
                    )
                }
                items(hits, key = { it.name }) { item ->
                    ModuleItemRow(item, onClick = { onItemClick(item) })
                }
            } else {
                item {
                    Surface(
                        shape = RoundedCornerShape(14.dp),
                        color = StatusClean.copy(alpha = 0.08f)
                    ) {
                        Row(
                            Modifier
                                .fillMaxWidth()
                                .padding(16.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Box(
                                Modifier
                                    .size(8.dp)
                                    .background(StatusClean, CircleShape)
                            )
                            Spacer(Modifier.width(10.dp))
                            Text(
                                "该模块的 ${items.size} 项检测全部通过",
                                fontSize = 13.sp,
                                color = StatusClean
                            )
                        }
                    }
                }
            }

            // ── 通过的检测项（可折叠）──
            if (clean.isNotEmpty()) {
                item {
                    Row(
                        Modifier
                            .fillMaxWidth()
                            .clickable { showClean = !showClean }
                            .padding(top = 12.dp, bottom = 4.dp, start = 4.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        val rot by animateFloatAsState(
                            targetValue = if (showClean) 180f else 0f,
                            animationSpec = tween(220),
                            label = "clean-arrow"
                        )
                        Text(
                            "通过的检测项（${clean.size}）",
                            fontSize = 12.sp,
                            fontWeight = FontWeight.SemiBold,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.weight(1f)
                        )
                        Icon(
                            Icons.Filled.ExpandMore,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier
                                .size(18.dp)
                                .rotate(rot)
                        )
                    }
                }

                if (showClean) {
                    items(clean, key = { "clean-${it.name}" }) { item ->
                        ModuleItemRow(item, onClick = { onItemClick(item) })
                    }
                }
            }
        }
    }
}

@Composable
private fun StatCell(label: String, value: Int, color: androidx.compose.ui.graphics.Color) {
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Text(
            value.toString(),
            fontSize = 22.sp,
            fontWeight = FontWeight.Bold,
            color = color
        )
        Text(
            label,
            fontSize = 11.sp,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}

@Composable
private fun ModuleItemRow(item: CheckItem, onClick: () -> Unit) {
    val color = item.status.color()

    Surface(
        shape = RoundedCornerShape(12.dp),
        color = MaterialTheme.colorScheme.surface,
        onClick = onClick
    ) {
        Row(
            Modifier
                .fillMaxWidth()
                .padding(horizontal = 14.dp, vertical = 13.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Box(Modifier.size(8.dp).background(color, CircleShape))
            Spacer(Modifier.width(12.dp))
            Column(Modifier.weight(1f)) {
                Text(
                    item.name,
                    fontSize = 14.sp,
                    color = MaterialTheme.colorScheme.onSurface
                )
                if (item.isRisk && item.evidence.isNotBlank()) {
                    Spacer(Modifier.height(3.dp))
                    Text(
                        item.evidence,
                        fontSize = 11.sp,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 1
                    )
                }
            }
            Spacer(Modifier.width(8.dp))
            Text(
                if (item.isRisk) item.levelStr else "OK",
                fontSize = 11.sp,
                color = color
            )
            Spacer(Modifier.width(4.dp))
            Text(
                "›",
                fontSize = 18.sp,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}
