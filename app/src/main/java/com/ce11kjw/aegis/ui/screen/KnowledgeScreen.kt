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
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Clear
import androidx.compose.material.icons.filled.ExpandMore
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.rotate
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.ce11kjw.aegis.ui.theme.*

@Composable
fun KnowledgeScreen(modifier: Modifier = Modifier) {
    var query by remember { mutableStateOf("") }
    var category by remember { mutableStateOf<String?>(null) }

    val categories = remember { listOf("全部") + KNOWLEDGE.map { it.category }.distinct() }

    val filtered = remember(query, category) {
        KNOWLEDGE.filter { e ->
            val catOk = category == null || category == "全部" || e.category == category
            val q = query.trim()
            val qOk = q.isEmpty() ||
                e.title.contains(q, true) ||
                e.summary.contains(q, true) ||
                e.detect.contains(q, true) ||
                e.solution.contains(q, true) ||
                e.category.contains(q, true) ||
                e.keys.any { it.contains(q, true) }
            catOk && qOk
        }
    }

    Column(modifier = modifier.fillMaxSize()) {
        // ── 搜索框 ──
        OutlinedTextField(
            value = query,
            onValueChange = { query = it },
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp, vertical = 8.dp),
            placeholder = { Text("搜索检测项、原理或解决方案…", fontSize = 13.sp) },
            leadingIcon = {
                Icon(Icons.Filled.Search, null, Modifier.size(20.dp))
            },
            trailingIcon = {
                if (query.isNotEmpty()) {
                    IconButton(onClick = { query = "" }) {
                        Icon(Icons.Filled.Clear, "清空", Modifier.size(18.dp))
                    }
                }
            },
            singleLine = true,
            shape = RoundedCornerShape(12.dp),
            keyboardOptions = KeyboardOptions(imeAction = ImeAction.Search),
            keyboardActions = KeyboardActions(onSearch = { /* 实时过滤，无需操作 */ }),
            colors = OutlinedTextFieldDefaults.colors(
                unfocusedContainerColor = MaterialTheme.colorScheme.surface,
                focusedContainerColor = MaterialTheme.colorScheme.surface
            )
        )

        // ── 分类筛选 ──
        LazyRow(
            contentPadding = PaddingValues(horizontal = 16.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            items(categories) { cat ->
                val sel = (category ?: "全部") == cat
                FilterChip(
                    selected = sel,
                    onClick = { category = if (cat == "全部") null else cat },
                    label = { Text(cat, fontSize = 12.sp) }
                )
            }
        }

        // ── 结果统计 ──
        if (query.isNotEmpty() || category != null) {
            Text(
                "找到 ${filtered.size} 条",
                fontSize = 11.sp,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(start = 20.dp, top = 6.dp)
            )
        }

        // ── 列表 ──
        if (filtered.isEmpty()) {
            Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Text("没有匹配的内容", fontSize = 15.sp,
                        color = MaterialTheme.colorScheme.onSurfaceVariant)
                    Spacer(Modifier.height(6.dp))
                    Text("试试搜索「su」「Frida」「SELinux」「评分」",
                        fontSize = 12.sp,
                        color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.6f))
                }
            }
        } else {
            LazyColumn(
                contentPadding = PaddingValues(start = 16.dp, end = 16.dp, bottom = 96.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                items(filtered, key = { it.title }) { entry ->
                    KnowledgeCard(entry, query)
                }
            }
        }
    }
}

@Composable
private fun KnowledgeCard(entry: KnowledgeEntry, query: String) {
    var expanded by remember { mutableStateOf(false) }
    val rotation by animateFloatAsState(
        targetValue = if (expanded) 180f else 0f,
        animationSpec = tween(250),
        label = "kb-arrow"
    )
    val gradeColor = gradeColor(entry.grade)

    Surface(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(14.dp),
        color = MaterialTheme.colorScheme.surface
    ) {
        Column(
            Modifier
                .animateContentSize(
                    animationSpec = spring(
                        dampingRatio = Spring.DampingRatioLowBouncy,
                        stiffness = Spring.StiffnessMediumLow
                    )
                )
        ) {
            Row(
                Modifier
                    .fillMaxWidth()
                    .clickable { expanded = !expanded }
                    .padding(16.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column(Modifier.weight(1f)) {
                    Text(
                        entry.title,
                        fontSize = 15.sp,
                        fontWeight = FontWeight.Medium,
                        color = MaterialTheme.colorScheme.onSurface
                    )
                    Spacer(Modifier.height(6.dp))
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Badge(entry.category, StatusWarning)
                        Spacer(Modifier.width(6.dp))
                        Badge(entry.grade.label, gradeColor)
                    }
                    Spacer(Modifier.height(6.dp))
                    Text(
                        entry.summary,
                        fontSize = 12.sp,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        lineHeight = 17.sp
                    )
                }
                Icon(
                    Icons.Filled.ExpandMore,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier
                        .size(20.dp)
                        .rotate(rotation)
                )
            }

            AnimatedVisibility(
                visible = expanded,
                enter = expandVertically(tween(240)) + fadeIn(tween(200)),
                exit = shrinkVertically(tween(200)) + fadeOut(tween(150))
            ) {
                Column(
                    Modifier
                        .fillMaxWidth()
                        .background(MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.35f))
                        .padding(16.dp)
                ) {
                    // 检测原理
                    SectionTitle("检测原理")
                    Text(
                        entry.detect,
                        fontSize = 12.sp,
                        fontFamily = FontFamily.Monospace,
                        lineHeight = 18.sp,
                        color = MaterialTheme.colorScheme.onSurface
                    )

                    Spacer(Modifier.height(16.dp))

                    // 解决方案
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        SectionTitle("解决方案")
                        Spacer(Modifier.width(8.dp))
                        Badge(entry.grade.label, gradeColor)
                    }
                    Spacer(Modifier.height(4.dp))
                    Text(
                        entry.solution,
                        fontSize = 12.sp,
                        lineHeight = 19.sp,
                        color = MaterialTheme.colorScheme.onSurface
                    )

                    // 关联检测项
                    if (entry.keys.isNotEmpty()) {
                        Spacer(Modifier.height(14.dp))
                        SectionTitle("关联检测项")
                        Spacer(Modifier.height(4.dp))
                        Text(
                            entry.keys.joinToString(" · "),
                            fontSize = 11.sp,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun SectionTitle(text: String) {
    Text(
        text,
        fontSize = 11.sp,
        fontWeight = FontWeight.SemiBold,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        letterSpacing = 0.3.sp
    )
}

@Composable
private fun Badge(text: String, color: Color) {
    Box(
        Modifier
            .background(color.copy(alpha = 0.14f), RoundedCornerShape(4.dp))
            .padding(horizontal = 6.dp, vertical = 2.dp)
    ) {
        Text(text, fontSize = 10.sp, color = color)
    }
}

private fun gradeColor(g: SolutionGrade): Color = when (g) {
    SolutionGrade.WORKING -> StatusClean
    SolutionGrade.PARTIAL -> StatusWarning
    SolutionGrade.THEORY  -> StatusInfo
    SolutionGrade.NONE    -> StatusDanger
}
