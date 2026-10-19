package com.ce11kjw.aegis

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.animation.*
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.ce11kjw.aegis.data.CheckReport
import com.ce11kjw.aegis.ui.screen.HomeScreen
import com.ce11kjw.aegis.ui.screen.KnowledgeScreen
import com.ce11kjw.aegis.ui.screen.SettingsScreen
import com.ce11kjw.aegis.ui.theme.AegisTheme
import com.ce11kjw.aegis.ui.theme.AegisTypography
import com.google.gson.Gson
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            AegisTheme {
                MaterialTheme(typography = AegisTypography) {
                    AegisApp()
                }
            }
        }
    }
}

enum class Tab(val label: String, val icon: ImageVector) {
    HOME("检测", Icons.Filled.Shield),
    KNOWLEDGE("知识库", Icons.Filled.MenuBook),
    SETTINGS("设置", Icons.Filled.Settings)
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AegisApp() {
    var tab by remember { mutableStateOf(Tab.HOME) }
    var report by remember { mutableStateOf<CheckReport?>(null) }
    var scanning by remember { mutableStateOf(true) }
    // 每次递增触发一次扫描。用 counter 而非 boolean，避免"连续点两次重新扫描"时
    // 第二次的 true 被第一次的 false 覆盖，导致 LaunchedEffect(scanning) 丢失触发。
    var scanTrigger by remember { mutableStateOf(0) }
    val gson = remember { Gson() }

    fun rescan() {
        if (scanning) return          // 正在扫描时忽略重复点击
        scanTrigger += 1
    }

    // 唯一的扫描入口：scanTrigger 变化时执行
    LaunchedEffect(scanTrigger) {
        scanning = true
        val json = withContext(Dispatchers.IO) {
            runCatching { AegisNative.runAll() }.getOrNull()
        }
        // 首次扫描让骨架屏至少显示 400ms，避免一闪而过
        if (scanTrigger == 0) delay(400)
        report = runCatching { gson.fromJson(json, CheckReport::class.java) }.getOrNull()
        scanning = false
    }

    Scaffold(
        containerColor = MaterialTheme.colorScheme.background,
        topBar = {
            TopAppBar(
                title = {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(
                            "Aegis",
                            fontWeight = FontWeight.SemiBold,
                            fontSize = 20.sp
                        )
                        if (report != null && !scanning) {
                            Spacer(Modifier.width(8.dp))
                            Box(
                                Modifier
                                    .background(
                                        MaterialTheme.colorScheme.primaryContainer,
                                        RoundedCornerShape(4.dp)
                                    )
                                    .padding(horizontal = 6.dp, vertical = 1.dp)
                            ) {
                                Text(
                                    "${report!!.count} 项",
                                    fontSize = 10.sp,
                                    color = MaterialTheme.colorScheme.onPrimaryContainer
                                )
                            }
                        }
                    }
                },
                actions = {
                    if (tab == Tab.HOME) {
                        IconButton(onClick = { if (!scanning) rescan() }) {
                            Icon(
                                if (scanning) Icons.Filled.HourglassEmpty else Icons.Filled.Refresh,
                                contentDescription = "重新扫描"
                            )
                        }
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.background
                )
            )
        },
        bottomBar = {
            NavigationBar(
                containerColor = MaterialTheme.colorScheme.surface,
                tonalElevation = 0.dp
            ) {
                Tab.entries.forEach { t ->
                    NavigationBarItem(
                        selected = tab == t,
                        onClick = { tab = t },
                        icon = { Icon(t.icon, contentDescription = t.label) },
                        label = { Text(t.label, fontSize = 11.sp) }
                    )
                }
            }
        }
    ) { padding ->
        Box(
            Modifier
                .fillMaxSize()
                .padding(padding)
        ) {
            AnimatedContent(
                targetState = tab,
                transitionSpec = {
                    (fadeIn(tween(220)) + slideInHorizontally(tween(280)) { it / 12 })
                        .togetherWith(fadeOut(tween(160)))
                },
                label = "tab"
            ) { current ->
                when (current) {
                    Tab.HOME -> HomeScreen(
                        report = report,
                        scanning = scanning,
                        onRescan = { rescan() }
                    )
                    Tab.KNOWLEDGE -> KnowledgeScreen()
                    Tab.SETTINGS -> SettingsScreen()
                }
            }
        }
    }
}
