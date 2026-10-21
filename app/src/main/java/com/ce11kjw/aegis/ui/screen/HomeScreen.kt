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
import com.ce11kjw.aegis.ui.component.ScanProgress
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
    onModuleClick: (String, List<CheckItem>) -> Unit = { _, _ -> },
    scanModule: String = "",
    scanDone: Int = 0,
    scanTotal: Int = 0,
    scanFinished: List<String> = emptyList(),
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

        // ---------- 扫描进度 + 骨架屏（v4.5）----------
        if (scanning) {
            item(key = "scan_progress") {
                ScanProgress(
                    currentModule = scanModule,
                    done = scanDone,
                    total = scanTotal,
                    finishedModules = scanFinished,
                    modifier = Modifier.padding(vertical = 8.dp)
                )
            }
            items(4, key = { "skeleton_$it" }) {
                SkeletonRow(delayMillis = it * 80)
            }
            return@LazyColumn
        }

        // ---------- 模块卡片列表（v4.6 三级导航第 1 级）----------
        item(key = "modules_label") {
            Text(
                "检测模块（${grouped.size}）",
                fontSize = 12.sp,
                fontWeight = FontWeight.SemiBold,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(top = 8.dp, start = 4.dp, bottom = 2.dp)
            )
        }

        itemsIndexed(
            grouped,
            key = { _, p -> "module_${p.first}" }
        ) { index, (moduleName, items) ->
            val hitCount = items.count { it.isRisk }
            val maxLevel = items.filter { it.isRisk }.maxOfOrNull { it.level } ?: 0
            val color = when {
                maxLevel >= 3 -> com.ce11kjw.aegis.ui.theme.StatusDanger
                maxLevel >= 2 -> com.ce11kjw.aegis.ui.theme.StatusWarning
                maxLevel >= 1 -> com.ce11kjw.aegis.ui.theme.StatusInfo
                else -> com.ce11kjw.aegis.ui.theme.StatusClean
            }

            var visible by remember { mutableStateOf(entrancePlayed) }
            LaunchedEffect(entrancePlayed) {
                if (!entrancePlayed) {
                    kotlinx.coroutines.delay(index.coerceAtMost(10) * 30L)
                    visible = true
                }
            }

            androidx.compose.animation.AnimatedVisibility(
                visible = visible,
                enter = androidx.compose.animation.fadeIn(tween(220)) +
                        androidx.compose.animation.slideInVertically(tween(220)) { it / 6 }
            ) {
                ModuleCard(
                    name = moduleName,
                    total = items.size,
                    hits = hitCount,
                    accent = color,
                    onClick = { onModuleClick(moduleName, items) }
                )
            }
        }
    }
}

/**
 * 模块卡片（第 1 级）
 *
 * 显示：模块名 + 总项数 + 命中数 + 进入箭头
 */
@Composable
private fun ModuleCard(
    name: String,
    total: Int,
    hits: Int,
    accent: androidx.compose.ui.graphics.Color,
    onClick: () -> Unit
) {
    Surface(
        shape = RoundedCornerShape(14.dp),
        color = MaterialTheme.colorScheme.surface,
        onClick = onClick
    ) {
        Row(
            Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp, vertical = 14.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            // 左侧状态条
            Box(
                Modifier
                    .size(width = 3.dp, height = 32.dp)
                    .background(accent, RoundedCornerShape(2.dp))
            )
            Spacer(Modifier.width(14.dp))

            Column(Modifier.weight(1f)) {
                Text(
                    name,
                    fontSize = 15.sp,
                    fontWeight = FontWeight.Medium,
                    color = MaterialTheme.colorScheme.onSurface
                )
                Spacer(Modifier.height(3.dp))
                Text(
                    "$total 项检测",
                    fontSize = 11.sp,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }

            // 右侧命中数
            if (hits > 0) {
                Box(
                    Modifier
                        .background(accent.copy(alpha = 0.14f), RoundedCornerShape(6.dp))
                        .padding(horizontal = 8.dp, vertical = 3.dp)
                ) {
                    Text(
                        "$hits 个问题",
                        fontSize = 11.sp,
                        fontWeight = FontWeight.Medium,
                        color = accent
                    )
                }
            } else {
                Text(
                    "全部通过",
                    fontSize = 11.sp,
                    color = com.ce11kjw.aegis.ui.theme.StatusClean
                )
            }

            Spacer(Modifier.width(8.dp))
            Text(
                "›",
                fontSize = 20.sp,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
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
