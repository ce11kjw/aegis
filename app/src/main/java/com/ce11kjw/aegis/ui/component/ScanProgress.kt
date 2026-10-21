package com.ce11kjw.aegis.ui.component

import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.ce11kjw.aegis.ui.theme.StatusClean
import com.ce11kjw.aegis.ui.theme.StatusInfo

/**
 * 扫描进度可视化（v4.5）
 *
 * 展示：
 *  - 当前正在扫描的模块名
 *  - 进度条（模块数 / 总数）
 *  - 已完成的模块列表（打勾）
 */
@Composable
fun ScanProgress(
    currentModule: String,
    done: Int,
    total: Int,
    finishedModules: List<String>,
    modifier: Modifier = Modifier
) {
    val progress by animateFloatAsState(
        targetValue = if (total > 0) done.toFloat() / total else 0f,
        animationSpec = tween(280),
        label = "scan-progress"
    )

    Column(modifier = modifier.fillMaxWidth()) {
        // 顶部：当前模块 + 计数
        Row(
            Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Box(
                Modifier
                    .size(8.dp)
                    .background(StatusInfo, CircleShape)
            )
            Spacer(Modifier.width(10.dp))
            Text(
                text = if (done >= total && total > 0) "扫描完成" else "正在扫描：$currentModule",
                fontSize = 13.sp,
                fontWeight = FontWeight.Medium,
                color = MaterialTheme.colorScheme.onSurface,
                modifier = Modifier.weight(1f)
            )
            Text(
                text = "$done / $total",
                fontSize = 12.sp,
                fontFamily = FontFamily.Monospace,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }

        Spacer(Modifier.height(10.dp))

        // 进度条
        Box(
            Modifier
                .fillMaxWidth()
                .height(4.dp)
                .clip(RoundedCornerShape(2.dp))
                .background(MaterialTheme.colorScheme.surfaceVariant)
        ) {
            Box(
                Modifier
                    .fillMaxWidth(progress)
                    .fillMaxHeight()
                    .clip(RoundedCornerShape(2.dp))
                    .background(StatusInfo)
            )
        }

        // 已完成的模块（最多显示 6 个，超出省略）
        if (finishedModules.isNotEmpty()) {
            Spacer(Modifier.height(12.dp))
            val show = finishedModules.takeLast(6)
            Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                show.forEach { name ->
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Box(
                            Modifier
                                .size(4.dp)
                                .background(
                                    StatusClean.copy(alpha = 0.7f),
                                    CircleShape
                                )
                        )
                        Spacer(Modifier.width(8.dp))
                        Text(
                            text = name,
                            fontSize = 11.sp,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
                if (finishedModules.size > 6) {
                    Text(
                        text = "… 已完成 ${finishedModules.size} 个模块",
                        fontSize = 10.sp,
                        color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.6f),
                        modifier = Modifier.padding(start = 12.dp)
                    )
                }
            }
        }
    }
}
