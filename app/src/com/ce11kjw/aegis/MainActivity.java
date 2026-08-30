package com.ce11kjw.aegis;

import android.app.Activity;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.os.Bundle;
import android.view.Gravity;
import android.view.View;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;
import org.json.JSONArray;
import org.json.JSONObject;

import com.ce11kjw.aegis.ui.HomePage;
import com.ce11kjw.aegis.ui.KnowledgeBasePage;
import com.ce11kjw.aegis.ui.SettingsPage;

/**
 * MainActivity - 三页导航主界面
 * 🛡️ 检测 (结果一体) | 📚 知识库 | ⚙️ 设置
 */
public class MainActivity extends Activity {

    private FrameLayout contentArea;
    private HomePage homePage;
    private KnowledgeBasePage knowledgePage;
    private SettingsPage settingsPage;

    private TextView navHome, navKnowledge, navSettings;
    private static final int COLOR_ACTIVE = Color.parseColor("#22D3EE");
    private static final int COLOR_INACTIVE = Color.parseColor("#64748B");

    private JSONArray resultItems;
    private int lastScore = 0;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        GradientDrawable bg = new GradientDrawable(
            GradientDrawable.Orientation.TL_BR,
            new int[] { Color.parseColor("#0A0F1A"), Color.parseColor("#131B2E") });
        root.setBackground(bg);

        // ===== 内容区 =====
        contentArea = new FrameLayout(this);
        contentArea.setLayoutParams(new LinearLayout.LayoutParams(-1, 0, 1));
        root.addView(contentArea);

        homePage = new HomePage(this, new Runnable() {
            @Override public void run() { runScan(); }
        });
        knowledgePage = new KnowledgeBasePage(this);
        settingsPage = new SettingsPage(this, new Runnable() {
            @Override public void run() { exportReport(); }
        });

        contentArea.addView(homePage, new FrameLayout.LayoutParams(-1, -1));
        contentArea.addView(knowledgePage, new FrameLayout.LayoutParams(-1, -1));
        contentArea.addView(settingsPage, new FrameLayout.LayoutParams(-1, -1));
        knowledgePage.setVisibility(View.GONE);
        settingsPage.setVisibility(View.GONE);

        // ===== 底部导航 =====
        LinearLayout navBar = new LinearLayout(this);
        navBar.setOrientation(LinearLayout.HORIZONTAL);
        navBar.setGravity(Gravity.CENTER);
        navBar.setPadding(dp(8), dp(8), dp(8), dp(8));
        GradientDrawable navBg = new GradientDrawable();
        navBg.setColor(Color.parseColor("#0F1522"));
        navBg.setCornerRadius(dp(24));
        navBg.setStroke(dp(1), Color.parseColor("#1A22D3EE"));
        LinearLayout.LayoutParams navLp = new LinearLayout.LayoutParams(-1, dp(64));
        navLp.setMargins(dp(16), dp(0), dp(16), dp(16));
        root.addView(navBar, navLp);

        navHome = makeNavItem("🛡️ 检测", true);
        navKnowledge = makeNavItem("📚 知识库", false);
        navSettings = makeNavItem("⚙️ 设置", false);
        navBar.addView(navHome, new LinearLayout.LayoutParams(0, -1, 1));
        navBar.addView(navKnowledge, new LinearLayout.LayoutParams(0, -1, 1));
        navBar.addView(navSettings, new LinearLayout.LayoutParams(0, -1, 1));

        navHome.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) { switchPage(0); }
        });
        navKnowledge.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) { switchPage(1); }
        });
        navSettings.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) { switchPage(2); }
        });

        setContentView(root);
    }

    private TextView makeNavItem(String text, boolean active) {
        TextView tv = new TextView(this);
        tv.setText(text);
        tv.setGravity(Gravity.CENTER);
        tv.setTextSize(12);
        tv.setTypeface(Typeface.create("sans-serif-medium", Typeface.BOLD));
        tv.setTextColor(active ? COLOR_ACTIVE : COLOR_INACTIVE);
        tv.setBackground(roundRect(active ? Color.parseColor("#14232E") : Color.TRANSPARENT, dp(20)));
        return tv;
    }

    private void switchPage(int index) {
        homePage.setVisibility(index == 0 ? View.VISIBLE : View.GONE);
        knowledgePage.setVisibility(index == 1 ? View.VISIBLE : View.GONE);
        settingsPage.setVisibility(index == 2 ? View.VISIBLE : View.GONE);

        navHome.setTextColor(index == 0 ? COLOR_ACTIVE : COLOR_INACTIVE);
        navKnowledge.setTextColor(index == 1 ? COLOR_ACTIVE : COLOR_INACTIVE);
        navSettings.setTextColor(index == 2 ? COLOR_ACTIVE : COLOR_INACTIVE);
        navHome.setBackground(roundRect(index == 0 ? Color.parseColor("#14232E") : Color.TRANSPARENT, dp(20)));
        navKnowledge.setBackground(roundRect(index == 1 ? Color.parseColor("#14232E") : Color.TRANSPARENT, dp(20)));
        navSettings.setBackground(roundRect(index == 2 ? Color.parseColor("#14232E") : Color.TRANSPARENT, dp(20)));
    }

    /** 执行检测: 后台线程, 完成后首页原地更新 + 同步设置页 */
    private void runScan() {
        Toast.makeText(this, "检测中...", Toast.LENGTH_SHORT).show();
        new Thread(new Runnable() {
            @Override public void run() {
                try {
                    final String json = AegisNative.runAll();
                    final JSONObject obj = new JSONObject(json);
                    final int score = obj.getInt("score");
                    resultItems = obj.getJSONArray("items");
                    lastScore = score;

                    runOnUiThread(new Runnable() {
                        @Override public void run() {
                            homePage.showResults(score, resultItems);
                            settingsPage.updateReport(score, resultItems);
                            Toast.makeText(MainActivity.this,
                                "检测完成 · 得分 " + score + "/100", Toast.LENGTH_SHORT).show();
                        }
                    });
                } catch (final Exception e) {
                    runOnUiThread(new Runnable() {
                        @Override public void run() {
                            Toast.makeText(MainActivity.this,
                                "检测失败: " + e.getMessage(), Toast.LENGTH_LONG).show();
                        }
                    });
                }
            }
        }).start();
    }

    /** 导出报告到剪贴板 */
    private void exportReport() {
        if (resultItems == null) {
            Toast.makeText(this, "请先完成一次检测", Toast.LENGTH_SHORT).show();
            return;
        }
        StringBuilder sb = new StringBuilder();
        sb.append("=== AegisGuard 安全检测报告 ===\n");
        sb.append("得分: ").append(lastScore).append("/100\n");
        sb.append("检测项: ").append(resultItems.length()).append(" 项 / 8 模块\n\n");
        for (int i = 0; i < resultItems.length(); i++) {
            try {
                JSONObject item = resultItems.getJSONObject(i);
                sb.append("[").append(item.getInt("detected") == 1 ? "!!" : "--").append("] ");
                sb.append(item.getString("module_name")).append(" | ");
                sb.append(item.getString("name")).append(" | ");
                sb.append(item.getString("level_str")).append("\n");
                String ev = item.optString("evidence", "");
                if (ev.length() > 0) sb.append("    证据: ").append(ev).append("\n");
            } catch (Exception e) { }
        }
        ClipboardManager cm = (ClipboardManager) getSystemService(CLIPBOARD_SERVICE);
        cm.setPrimaryClip(ClipData.newPlainText("aegis_report", sb.toString()));
        Toast.makeText(this, "报告已复制到剪贴板", Toast.LENGTH_SHORT).show();
    }

    private android.graphics.drawable.GradientDrawable roundRect(int color, int radius) {
        android.graphics.drawable.GradientDrawable g =
            new android.graphics.drawable.GradientDrawable();
        g.setColor(color);
        g.setCornerRadius(radius);
        return g;
    }

    private int dp(float v) {
        return (int) (v * getResources().getDisplayMetrics().density + 0.5f);
    }
}
