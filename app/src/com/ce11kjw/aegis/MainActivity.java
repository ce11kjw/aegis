package com.ce11kjw.aegis;

import android.app.Activity;
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

/**
 * MainActivity - 两页导航主界面
 * 🛡️ 检测 (首页: 检测+结果一体) | 📚 知识库
 */
public class MainActivity extends Activity {

    private FrameLayout contentArea;
    private HomePage homePage;
    private KnowledgeBasePage knowledgePage;

    private TextView navHome, navKnowledge;
    private static final int COLOR_ACTIVE = Color.parseColor("#22D3EE");
    private static final int COLOR_INACTIVE = Color.parseColor("#64748B");

    private JSONArray resultItems;

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

        contentArea.addView(homePage, new FrameLayout.LayoutParams(-1, -1));
        contentArea.addView(knowledgePage, new FrameLayout.LayoutParams(-1, -1));
        knowledgePage.setVisibility(View.GONE);

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
        navBar.addView(navHome, new LinearLayout.LayoutParams(0, -1, 1));
        navBar.addView(navKnowledge, new LinearLayout.LayoutParams(0, -1, 1));

        navHome.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) { switchPage(0); }
        });
        navKnowledge.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) { switchPage(1); }
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

        navHome.setTextColor(index == 0 ? COLOR_ACTIVE : COLOR_INACTIVE);
        navKnowledge.setTextColor(index == 1 ? COLOR_ACTIVE : COLOR_INACTIVE);
        navHome.setBackground(roundRect(index == 0 ? Color.parseColor("#14232E") : Color.TRANSPARENT, dp(20)));
        navKnowledge.setBackground(roundRect(index == 1 ? Color.parseColor("#14232E") : Color.TRANSPARENT, dp(20)));
    }

    /** 执行检测: 后台线程, 完成后在首页原地更新 (不跳页) */
    private void runScan() {
        Toast.makeText(this, "检测中...", Toast.LENGTH_SHORT).show();
        new Thread(new Runnable() {
            @Override public void run() {
                try {
                    final String json = AegisNative.runAll();
                    final JSONObject obj = new JSONObject(json);
                    final int score = obj.getInt("score");
                    resultItems = obj.getJSONArray("items");

                    runOnUiThread(new Runnable() {
                        @Override public void run() {
                            homePage.showResults(score, resultItems);
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
