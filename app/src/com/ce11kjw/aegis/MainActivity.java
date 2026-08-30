package com.ce11kjw.aegis;

import android.app.Activity;
import android.os.Bundle;
import android.widget.*;
import android.view.View;
import android.view.ViewGroup;
import android.graphics.Color;
import android.graphics.Typeface;
import android.text.Html;
import org.json.JSONObject;
import org.json.JSONArray;

public class MainActivity extends Activity {
    private LinearLayout resultLayout;
    private TextView scoreText, countText, statusText;
    private Button scanBtn, exportBtn;
    private JSONArray items;
    private int score;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(24, 24, 24, 24);
        root.setBackgroundColor(Color.parseColor("#0D1117"));

        // 标题
        TextView title = new TextView(this);
        title.setText("Aegis 安全检测引擎 v1.0.1");
        title.setTextColor(Color.parseColor("#58A6FF"));
        title.setTextSize(20);
        title.setTypeface(null, Typeface.BOLD);
        title.setPadding(0, 0, 0, 16);
        root.addView(title);

        // 状态
        statusText = new TextView(this);
        statusText.setText("就绪 - 点击下方按钮开始检测");
        statusText.setTextColor(Color.parseColor("#8B949E"));
        statusText.setTextSize(14);
        statusText.setPadding(0, 0, 0, 24);
        root.addView(statusText);

        // 分数区
        scoreText = new TextView(this);
        scoreText.setText("得分: --/100");
        scoreText.setTextColor(Color.parseColor("#58A6FF"));
        scoreText.setTextSize(48);
        scoreText.setTypeface(null, Typeface.BOLD);
        scoreText.setGravity(android.view.Gravity.CENTER);
        scoreText.setPadding(0, 0, 0, 8);
        root.addView(scoreText);

        countText = new TextView(this);
        countText.setText("检测项: 0");
        countText.setTextColor(Color.parseColor("#8B949E"));
        countText.setTextSize(16);
        countText.setGravity(android.view.Gravity.CENTER);
        countText.setPadding(0, 0, 0, 32);
        root.addView(countText);

        // 扫描按钮
        scanBtn = new Button(this);
        scanBtn.setText("开始安全检测");
        scanBtn.setTextColor(Color.WHITE);
        scanBtn.setBackgroundColor(Color.parseColor("#238636"));
        scanBtn.setPadding(0, 16, 0, 16);
        scanBtn.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) { runScan(); }
        });
        root.addView(scanBtn);

        // 导出按钮
        exportBtn = new Button(this);
        exportBtn.setText("导出检测报告");
        exportBtn.setTextColor(Color.WHITE);
        exportBtn.setBackgroundColor(Color.parseColor("#1F6FEB"));
        exportBtn.setPadding(0, 16, 0, 16);
        exportBtn.setVisibility(View.GONE);
        exportBtn.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) { exportReport(); }
        });
        LinearLayout.LayoutParams expLp = new LinearLayout.LayoutParams(-1, -2);
        expLp.topMargin = 12;
        root.addView(exportBtn, expLp);

        // 结果列表
        resultLayout = new LinearLayout(this);
        resultLayout.setOrientation(LinearLayout.VERTICAL);
        resultLayout.setPadding(0, 16, 0, 0);
        root.addView(resultLayout);

        ScrollView sv = new ScrollView(this);
        sv.addView(root);
        setContentView(sv);
    }

    private void runScan() {
        statusText.setText("检测中...");
        scanBtn.setEnabled(false);
        new Thread(new Runnable() {
            @Override public void run() {
                try {
                    String json = AegisNative.runAll();
                    final JSONObject obj = new JSONObject(json);
                    score = obj.getInt("score");
                    items = obj.getJSONArray("items");
                    final int count = obj.getInt("count");
                    runOnUiThread(new Runnable() {
                        @Override public void run() {
                            scoreText.setText("得分: " + score + "/100");
                            countText.setText("检测项: " + count);
                            if (score < 30) scoreText.setTextColor(Color.parseColor("#3FB950"));
                            else if (score < 60) scoreText.setTextColor(Color.parseColor("#D29922"));
                            else scoreText.setTextColor(Color.parseColor("#F85149"));
                            exportBtn.setVisibility(View.VISIBLE);
                            showResults();
                            statusText.setText("检测完成");
                            scanBtn.setEnabled(true);
                        }
                    });
                } catch (Exception e) {
                    runOnUiThread(new Runnable() {
                        @Override public void run() {
                            statusText.setText("错误: " + e.getMessage());
                            scanBtn.setEnabled(true);
                        }
                    });
                }
            }
        }).start();
    }

    private void showResults() {
        resultLayout.removeAllViews();
        for (int i = 0; i < items.length(); i++) {
            try {
                JSONObject item = items.getJSONObject(i);
                final String name = item.getString("name");
                final String module = item.getString("module_name");
                final int detected = item.getInt("detected");
                final int level = item.getInt("level");
                final String evidence = item.optString("evidence", "");
                final String levelStr = item.getString("level_str");

                TextView tv = new TextView(this);
                String icon = detected == 1 ? "⚠️" : "✅";
                String alertColor = detected == 1 ? "#F85149" : "#3FB950";
                if (level <= 1) alertColor = "#8B949E";
                tv.setText(Html.fromHtml(
                    icon + " <b>" + name + "</b><br>" +
                    "<font color='" + alertColor + "'>" + module + " | " + levelStr + "</font>"
                ));
                tv.setTextColor(Color.parseColor("#C9D1D9"));
                tv.setTextSize(14);
                tv.setPadding(16, 12, 16, 12);
                tv.setBackgroundColor(Color.parseColor("#161B22"));
                LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(-1, -2);
                lp.bottomMargin = 6;
                resultLayout.addView(tv, lp);

                if (detected == 1 && evidence.length() > 0) {
                    TextView ev = new TextView(this);
                    ev.setText("→ " + evidence);
                    ev.setTextColor(Color.parseColor("#F0883E"));
                    ev.setTextSize(12);
                    ev.setPadding(32, 0, 16, 12);
                    ev.setBackgroundColor(Color.parseColor("#161B22"));
                    resultLayout.addView(ev, new LinearLayout.LayoutParams(-1, -2));
                }
            } catch (Exception e) { /* skip bad item */ }
        }
    }

    private void exportReport() {
        // 复制到剪贴板
        StringBuilder sb = new StringBuilder();
        sb.append("=== Aegis 安全检测报告 ===\n");
        sb.append("总分: ").append(score).append("/100\n");
        sb.append("检测项: ").append(items.length()).append("\n\n");
        for (int i = 0; i < items.length(); i++) {
            try {
                JSONObject item = items.getJSONObject(i);
                sb.append("[").append(item.getInt("detected") == 1 ? "!!" : "--").append("] ");
                sb.append(item.getString("module_name")).append(" | ");
                sb.append(item.getString("name")).append(" | ");
                sb.append(item.getString("level_str")).append("\n");
                String ev = item.optString("evidence", "");
                if (ev.length() > 0) sb.append("    证据: ").append(ev).append("\n");
            } catch (Exception e) { }
        }
        android.content.ClipboardManager cm = (android.content.ClipboardManager)
            getSystemService(CLIPBOARD_SERVICE);
        cm.setPrimaryClip(android.content.ClipData.newPlainText("report", sb.toString()));
        Toast.makeText(this, "报告已复制到剪贴板", Toast.LENGTH_SHORT).show();
    }
}
