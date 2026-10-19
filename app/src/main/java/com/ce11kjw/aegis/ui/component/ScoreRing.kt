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
    score >= 70 -> StatusDanger
    score >= 40 -> StatusWarning
    score >= 15 -> StatusInfo
    else -> StatusClean
}

fun scoreLabel(score: Int): String = when {
    score >= 70 -> "环境异常"
    score >= 40 -> "存在风险"
    score >= 15 -> "轻微异常"
    else -> "环境安全"
}
