package com.ce11kjw.aegis.ui.screen

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.slideInVertically
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

@Composable
fun HomeScreen(
    report: CheckReport?,
    scanning: Boolean,
    onRescan: () -> Unit,
    modifier: Modifier = Modifier
) {
    val listState = rememberLazyListState()

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
        report?.grouped()?.forEach { (moduleName, items) ->
            stickyHeader(key = "header_$moduleName") {
                SectionHeader(moduleName, items.count { it.isRisk })
            }
            itemsIndexed(items, key = { _, item -> "$moduleName-${item.name}" }) { index, item ->
                // 动效6: stagger 入场
                var visible by remember { mutableStateOf(false) }
                LaunchedEffect(Unit) {
                    kotlinx.coroutines.delay(index * 30L)
                    visible = true
                }
                AnimatedVisibility(
                    visible = visible,
                    enter = fadeIn(tween(280)) + slideInVertically(tween(280)) { it / 5 }
                ) {
                    CheckRow(item = item)
                }
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
