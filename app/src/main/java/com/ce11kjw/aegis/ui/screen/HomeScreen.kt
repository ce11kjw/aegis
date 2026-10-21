package com.ce11kjw.aegis.ui.screen

import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.scale
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.ce11kjw.aegis.data.CheckItem
import com.ce11kjw.aegis.data.CheckReport
import com.ce11kjw.aegis.ui.component.CheckRow
import com.ce11kjw.aegis.ui.component.ScoreRing
import com.ce11kjw.aegis.ui.component.scoreColor
import com.ce11kjw.aegis.ui.component.scoreLabel
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.animation.core.Animatable
import androidx.compose.ui.graphics.graphicsLayer
import kotlinx.coroutines.launch

@OptIn(ExperimentalFoundationApi::class)
@Composable
fun HomeScreen(
    report: CheckReport?,
    scanning: Boolean,
    onRescan: () -> Unit,
    onItemClick: (CheckItem) -> Unit = {},
    modifier: Modifier = Modifier
) {
    val listState = rememberLazyListState()

    /* 入场动画只播一次：
     * 原实现每个 item 都有 LaunchedEffect(Unit) + delay(index*30)，
     * 列表项滑出屏幕被回收、再滑回来时会重新触发，
     * 导致"滚回去内容又淡入一次"，且 181 项时末尾延迟高达 5.4s。
     * 改为：整屏只保留一个 flag，扫描完成后统一触发一次。 */
    var entrancePlayed by remember { mutableStateOf(false) }
    LaunchedEffect(report?.count, scanning) {
        if (report != null && !scanning && !entrancePlayed) {
            entrancePlayed = true
        }
    }
    // 重新扫描后重置，允许下一轮再播一次
    LaunchedEffect(scanning) {
        if (scanning) entrancePlayed = false
    }

    // 缓存分组结果：grouped() 内部 groupBy + 两次 sortedBy，181 项时开销不小。
    // 注意必须在 Composable 上下文（LazyColumn 外），LazyListScope 内不能调 remember。
    val grouped = remember(report) { report?.grouped() ?: emptyList() }

    LazyColumn(
        state = listState,
        modifier = modifier.fillMaxSize(),
        contentPadding = PaddingValues(start = 16.dp, end = 16.dp, top = 8.dp, bottom = 96.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        // ---------- 评分卡 ----------
        item(key = "score") {
            ScoreHeader(report, scanning)
        }

        // ---------- 统计条 ----------
        if (report != null && !scanning) {
            item(key = "stats") {
                StatsBar(report)
            }
        }

        // ---------- 骨架屏（动效7）----------
        if (scanning) {
            items(6, key = { "skeleton_$it" }) {
                SkeletonRow(delayMillis = it * 80)
            }
            return@LazyColumn
        }

        // ---------- 分组列表（动效3 吸顶 + 动效6 stagger）----------
        grouped.forEach { (moduleName, items) ->
            stickyHeader(key = "header_$moduleName") {
                SectionHeader(moduleName, items.count { it.isRisk })
            }
            itemsIndexed(items, key = { _, item -> "$moduleName-${item.name}" }) { index, item ->
                /* 性能优化：
                 * 1. 去掉每项的 AnimatedVisibility（滚动时反复重组）
                 * 2. 去掉 LaunchedEffect(Unit)+delay（回收重建会重播）
                 * 3. stagger 只在首次入场时生效，且上限 10 项（最多 300ms） */
                val delayMs = if (entrancePlayed) 0 else (index.coerceAtMost(10) * 30L)
                AnimatedCheckRow(item = item, delayMs = delayMs, onClick = { onItemClick(item) })
            }
        }
    }
}

/** 顶部评分区 */
@Composable
private fun ScoreHeader(report: CheckReport?, scanning: Boolean) {
    Column(
        Modifier
            .fillMaxWidth()
            .padding(vertical = 24.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        if (scanning) {
            ScoreRing(score = 0, modifier = Modifier.scale(0.92f))
            Spacer(Modifier.height(12.dp))
            Text(
                text = "正在扫描…",
                fontSize = 14.sp,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        } else if (report != null) {
            ScoreRing(score = report.score)
            Spacer(Modifier.height(12.dp))
            Text(
                text = scoreLabel(report.score),
                fontSize = 18.sp,
                fontWeight = FontWeight.SemiBold,
                color = scoreColor(report.score)
            )
            Spacer(Modifier.height(4.dp))
            Text(
                text = "共 ${report.count} 项检测",
                fontSize = 12.sp,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

/** 统计条 */
@Composable
private fun StatsBar(report: CheckReport) {
    Surface(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(14.dp),
        color = MaterialTheme.colorScheme.surface
    ) {
        Row(
            Modifier
                .fillMaxWidth()
                .padding(vertical = 14.dp),
            horizontalArrangement = Arrangement.SpaceEvenly
        ) {
            StatCell("严重", report.dangerCount, com.ce11kjw.aegis.ui.theme.StatusDanger)
            StatCell("警告", report.warningCount, com.ce11kjw.aegis.ui.theme.StatusWarning)
            StatCell("正常", report.count - report.riskCount, com.ce11kjw.aegis.ui.theme.StatusClean)
        }
    }
}

@Composable
private fun StatCell(label: String, count: Int, color: androidx.compose.ui.graphics.Color) {
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Text(
            text = count.toString(),
            fontSize = 20.sp,
            fontWeight = FontWeight.Bold,
            color = color
        )
        Text(
            text = label,
            fontSize = 11.sp,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}

/** 分组吸顶标题 */
@Composable
private fun SectionHeader(name: String, riskCount: Int) {
    Box(
        Modifier
            .fillMaxWidth()
            .background(MaterialTheme.colorScheme.background)
            .padding(top = 16.dp, bottom = 6.dp)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                text = name,
                fontSize = 13.sp,
                fontWeight = FontWeight.SemiBold,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            if (riskCount > 0) {
                Spacer(Modifier.width(6.dp))
                Box(
                    Modifier
                        .background(
                            com.ce11kjw.aegis.ui.theme.StatusDanger.copy(alpha = 0.15f),
                            RoundedCornerShape(4.dp)
                        )
                        .padding(horizontal = 5.dp, vertical = 1.dp)
                ) {
                    Text(
                        text = "$riskCount",
                        fontSize = 10.sp,
                        color = com.ce11kjw.aegis.ui.theme.StatusDanger
                    )
                }
            }
        }
    }
}

/** 骨架屏（动效7）*/
@Composable
private fun SkeletonRow(delayMillis: Int) {
    var alpha by remember { mutableStateOf(0.3f) }
    LaunchedEffect(Unit) {
        kotlinx.coroutines.delay(delayMillis.toLong())
        alpha = 1f
    }

    Surface(
        modifier = Modifier
            .fillMaxWidth()
            .alpha(alpha),
        shape = RoundedCornerShape(14.dp),
        color = MaterialTheme.colorScheme.surface
    ) {
        Row(
            Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp, vertical = 16.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Box(
                Modifier
                    .size(8.dp)
                    .background(
                        MaterialTheme.colorScheme.surfaceVariant,
                        androidx.compose.foundation.shape.CircleShape
                    )
            )
            Spacer(Modifier.width(12.dp))
            Column(Modifier.weight(1f)) {
                Box(
                    Modifier
                        .fillMaxWidth(0.6f)
                        .height(12.dp)
                        .background(
                            MaterialTheme.colorScheme.surfaceVariant,
                            RoundedCornerShape(4.dp)
                        )
                )
                Spacer(Modifier.height(6.dp))
                Box(
                    Modifier
                        .fillMaxWidth(0.35f)
                        .height(10.dp)
                        .background(
                            MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.6f),
                            RoundedCornerShape(4.dp)
                        )
                )
            }
        }
    }
}

/**
 * 带入场动画的检测项
 *
 * 与原实现（AnimatedVisibility + 每项 LaunchedEffect）的区别：
 *  - 用 Animatable 直接驱动 graphicsLayer，只在动画期间重组
 *  - 动画结束后 alpha=1 / translationY=0，与普通 CheckRow 完全一致
 *  - delayMs=0（非首次入场）时完全跳过动画，零额外开销
 *
 * 修复的卡顿原因：
 *  1. AnimatedVisibility 在 LazyColumn 中会持续占布局槽位并参与重组
 *  2. 每项 LaunchedEffect(Unit) 在 item 被回收重建时会重新触发
 *  3. index*30 的 delay 在 181 项时末尾高达 5.4 秒
 */
@Composable
private fun AnimatedCheckRow(item: CheckItem, delayMs: Long, onClick: () -> Unit) {
    val alphaAnim = remember { Animatable(if (delayMs == 0L) 1f else 0f) }
    val offsetAnim = remember { Animatable(if (delayMs == 0L) 0f else 24f) }

    LaunchedEffect(delayMs) {
        if (delayMs > 0L) kotlinx.coroutines.delay(delayMs)
        if (alphaAnim.value < 1f || offsetAnim.value > 0f) {
            kotlinx.coroutines.coroutineScope {
                launch { alphaAnim.animateTo(1f, tween(220)) }
                launch { offsetAnim.animateTo(0f, tween(220)) }
            }
        }
    }

    CheckRow(
        item = item,
        onClick = onClick,
        modifier = Modifier.graphicsLayer {
            alpha = alphaAnim.value
            translationY = offsetAnim.value
        }
    )
}
