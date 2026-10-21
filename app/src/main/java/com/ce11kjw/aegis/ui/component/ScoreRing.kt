package com.ce11kjw.aegis.ui.component

import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.*
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.ce11kjw.aegis.ui.theme.*
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.ui.unit.Dp

/**
 * 评分环 —— 动效1
 * 从 0 扫到目标分数（1200ms FastOutSlowIn），颜色随分数渐变
 */
@Composable
fun ScoreRing(
    score: Int,
    modifier: Modifier = Modifier,
    size: Dp = 160.dp,
    strokeWidth: Dp = 12.dp
) {
    // 分数动画
    val animated by animateFloatAsState(
        targetValue = score.coerceIn(0, 100) / 100f,
        animationSpec = tween(1200, easing = FastOutSlowInEasing),
        label = "score"
    )

    val color = scoreColor(score)
    val trackColor = MaterialTheme.colorScheme.surfaceVariant

    Box(modifier = modifier.size(size), contentAlignment = Alignment.Center) {
        Canvas(Modifier.fillMaxSize()) {
            val stroke = strokeWidth.toPx()
            val inset = stroke / 2
            val arcSize = Size(this.size.width - stroke, this.size.height - stroke)
            val topLeft = Offset(inset, inset)

            // 轨道
            drawArc(
                color = trackColor,
                startAngle = 135f,
                sweepAngle = 270f,
                useCenter = false,
                topLeft = topLeft,
                size = arcSize,
                style = Stroke(width = stroke, cap = StrokeCap.Round)
            )

            // 进度
            drawArc(
                brush = Brush.sweepGradient(
                    listOf(color.copy(alpha = 0.7f), color)
                ),
                startAngle = 135f,
                sweepAngle = 270f * animated,
                useCenter = false,
                topLeft = topLeft,
                size = arcSize,
                style = Stroke(width = stroke, cap = StrokeCap.Round)
            )
        }

        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            Text(
                text = (animated * 100).toInt().toString(),
                fontSize = 42.sp,
                fontWeight = FontWeight.Bold,
                color = color
            )
            Text(
                text = scoreLabel(score),
                fontSize = 13.sp,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

fun scoreColor(score: Int): Color = when {
    score >= 70 -> StatusDanger      // 70-100 危险/严重 红
    score >= 30 -> StatusWarning     // 30-69  可疑/存在风险 橙
    score >= 10 -> StatusInfo        // 10-29  轻微异常 蓝
    else -> StatusClean              // 0-9    安全 绿
}

/**
 * 评分等级文案（与 aegis_score v2 的分段对齐）
 *
 *    0-9    环境安全    无任何风险信号
 *   10-29   轻微异常    可能开了调试 / 非标准 ROM
 *   30-49   可疑        存在部分风险特征，需人工确认
 *   50-69   存在风险    明确的环境改动
 *   70-89   危险        确认 Root / Hook
 *   90-100  严重        多重 Root 框架 + 隐藏方案 + Hook
 */
fun scoreLabel(score: Int): String = when {
    score >= 90 -> "严重风险"
    score >= 70 -> "危险"
    score >= 50 -> "存在风险"
    score >= 30 -> "可疑"
    score >= 10 -> "轻微异常"
    else -> "环境安全"
}
