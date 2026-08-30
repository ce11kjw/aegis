package com.ce11kjw.aegis.ui;

import android.content.Context;
import android.graphics.Color;
import android.graphics.Typeface;
import android.view.Gravity;
import android.view.View;
import android.widget.LinearLayout;
import android.widget.TextView;
import org.json.JSONArray;
import org.json.JSONObject;

/**
 * ResultsPage - 结果页
 * 7 大模块分组折叠 + 每个检测项点击展开详情
 */
public class ResultsPage extends LinearLayout {

    private JSONArray items;
    private boolean hasData = false;

    public ResultsPage(Context context) {
        super(context);
        setOrientation(LinearLayout.VERTICAL);
        setPadding(dp(20), dp(16), dp(20), dp(16));

        TextView title = new TextView(context);
        title.setText("检测结果");
        title.setTextColor(Color.parseColor("#F8FAFC"));
        title.setTextSize(24);
        title.setTypeface(Typeface.create("sans-serif-medium", Typeface.BOLD));
        addView(title);

        TextView empty = new TextView(context);
        empty.setText("尚未检测\n\n点击「首页」开始检测, 结果将按模块分组展示");
        empty.setTextColor(Color.parseColor("#64748B"));
        empty.setTextSize(14);
        empty.setGravity(Gravity.CENTER);
        empty.setPadding(0, dp(80), 0, 0);
        addView(empty);
    }

    /** 更新数据并渲染 */
    public void showResults(JSONArray resultItems) {
        this.items = resultItems;
        this.hasData = (resultItems != null && resultItems.length() > 0);
        removeAllViews();

        if (!hasData) return;

        // 标题
        TextView title = new TextView(getContext());
        title.setText("检测结果 · 点击模块展开");
        title.setTextColor(Color.parseColor("#F8FAFC"));
        title.setTextSize(24);
        title.setTypeface(Typeface.create("sans-serif-medium", Typeface.BOLD));
        addView(title);

        // 按模块分组渲染
        final int[] modules = {0,1,2,3,4,5,6};
        final String[] moduleNames = {"反调试","Frida注入","Xposed/Zygisk","完整性","模拟器","Root","系统环境"};
        for (int m = 0; m < modules.length; m++) {
            // 统计该模块命中数
            final int modIdx = modules[m];
            int hit = 0, total = 0;
            for (int i = 0; i < items.length(); i++) {
                try {
                    if (items.getJSONObject(i).optInt("module") == modIdx) {
                        total++;
                        if (items.getJSONObject(i).optInt("detected") == 1) hit++;
                    }
                } catch (Exception e) { }
            }
            if (total == 0) continue;

            // ===== 模块折叠卡 =====
            GlassCard moduleCard = new GlassCard(getContext());
            LinearLayout header = new LinearLayout(getContext());
            header.setOrientation(LinearLayout.HORIZONTAL);
            header.setGravity(Gravity.CENTER_VERTICAL);

            TextView dot = new TextView(getContext());
            dot.setText(hit > 0 ? "●" : "○");
            dot.setTextColor(hit > 0 ? Color.parseColor("#EF4444") : Color.parseColor("#34D399"));
            dot.setTextSize(14);
            header.addView(dot);

            TextView name = new TextView(getContext());
            name.setText(moduleNames[m]);
            name.setTextColor(Color.parseColor("#E2E8F0"));
            name.setTextSize(16);
            name.setTypeface(Typeface.create("sans-serif-medium", Typeface.BOLD));
            LinearLayout.LayoutParams nameLp = new LinearLayout.LayoutParams(0, -2, 1);
            nameLp.leftMargin = dp(10);
            header.addView(name, nameLp);

            TextView badge = new TextView(getContext());
            badge.setText(hit + "/" + total);
            badge.setTextColor(hit > 0 ? Color.parseColor("#FCA5A5") : Color.parseColor("#6EE7B7"));
            badge.setTextSize(12);
            badge.setTypeface(Typeface.MONOSPACE);
            badge.setGravity(Gravity.CENTER);
            badge.setPadding(dp(8), dp(3), dp(8), dp(3));
            badge.setBackground(roundRect(
                hit > 0 ? Color.parseColor("#331818") : Color.parseColor("#3306420E"),
                dp(10)));
            header.addView(badge);

            moduleCard.inner().addView(header);

            // 展开内容容器 (初始隐藏)
            final LinearLayout detailContainer = new LinearLayout(getContext());
            detailContainer.setOrientation(LinearLayout.VERTICAL);
            detailContainer.setVisibility(View.GONE);
            LinearLayout.LayoutParams detailLp = new LinearLayout.LayoutParams(-1, -2);
            detailLp.topMargin = dp(10);
            moduleCard.inner().addView(detailContainer, detailLp);

            // 该模块的检测项
            for (int i = 0; i < items.length(); i++) {
                try {
                    JSONObject it = items.getJSONObject(i);
                    if (it.optInt("module") != modIdx) continue;
                    final JSONObject item = it;
                    addItemRow(getContext(), detailContainer, item);
                } catch (Exception e) { }
            }

            // 点击模块卡折叠/展开
            final View toggle = moduleCard;
            header.setOnClickListener(new OnClickListener() {
                @Override public void onClick(View v) {
                    boolean show = detailContainer.getVisibility() == View.GONE;
                    detailContainer.setVisibility(show ? View.VISIBLE : View.GONE);
                }
            });

            LinearLayout.LayoutParams cardLp = new LinearLayout.LayoutParams(-1, -2);
            cardLp.topMargin = dp(14);
            addView(moduleCard, cardLp);
        }
    }

    /** 单个检测项行: 点击展开详情 */
    private void addItemRow(Context ctx, LinearLayout container, final JSONObject item) {
        try {
            final String name = item.getString("name");
            final int detected = item.getInt("detected");
            final int level = item.getInt("level");
            final String levelStr = item.getString("level_str");
            final String evidence = item.optString("evidence", "");

            // 行: 图标 + 名称 + 等级标签
            LinearLayout row = new LinearLayout(ctx);
            row.setOrientation(LinearLayout.HORIZONTAL);
            row.setGravity(Gravity.CENTER_VERTICAL);
            row.setPadding(dp(8), dp(8), dp(8), dp(8));
            row.setBackground(roundRect(Color.parseColor("#1E2433"), dp(12)));

            TextView icon = new TextView(ctx);
            icon.setText(detected == 1 ? "⚠" : "✓");
            icon.setTextColor(detected == 1 ? Color.parseColor("#EF4444") : Color.parseColor("#34D399"));
            icon.setTextSize(14);
            row.addView(icon);

            TextView tv = new TextView(ctx);
            tv.setText(name);
            tv.setTextColor(Color.parseColor("#CBD5E1"));
            tv.setTextSize(14);
            LinearLayout.LayoutParams tvLp = new LinearLayout.LayoutParams(0, -2, 1);
            tvLp.leftMargin = dp(10);
            row.addView(tv, tvLp);

            TextView lv = new TextView(ctx);
            lv.setText(levelStr);
            lv.setTextSize(11);
            lv.setTextColor(Color.parseColor(levelColor(level)));
            lv.setGravity(Gravity.CENTER);
            lv.setPadding(dp(6), dp(2), dp(6), dp(2));
            lv.setBackground(roundRect(Color.parseColor(levelBg(level)), dp(8)));
            row.addView(lv);

            LinearLayout.LayoutParams rowLp = new LinearLayout.LayoutParams(-1, -2);
            rowLp.topMargin = dp(6);
            container.addView(row, rowLp);

            // 详情面板 (初始隐藏)
            final LinearLayout detail = new LinearLayout(ctx);
            detail.setOrientation(LinearLayout.VERTICAL);
            detail.setPadding(dp(10), dp(10), dp(10), dp(10));
            detail.setBackground(roundRect(Color.parseColor("#151A26"), dp(10)));
            detail.setVisibility(View.GONE);

            addDetailLine(detail, "检测说明", detailDesc(item), "#94A3B8");
            addDetailLine(detail, "证据详情", evidence.length() > 0 ? evidence : "未检测到异常", "#E2E8F0");
            addDetailLine(detail, "风险等级", levelStr + " (Level " + level + ")", levelColor(level));
            addDetailLine(detail, "建议措施", detailAdvice(item), "#6EE7B7");

            LinearLayout.LayoutParams detailLp = new LinearLayout.LayoutParams(-1, -2);
            detailLp.leftMargin = dp(8);
            detailLp.rightMargin = dp(8);
            detailLp.topMargin = dp(4);
            container.addView(detail, detailLp);

            row.setOnClickListener(new OnClickListener() {
                @Override public void onClick(View v) {
                    boolean show = detail.getVisibility() == View.GONE;
                    detail.setVisibility(show ? View.VISIBLE : View.GONE);
                }
            });
        } catch (Exception e) { }
    }

    /** 详情内的一行: 标签 + 内容 */
    private void addDetailLine(LinearLayout parent, String label, String content, String color) {
        TextView l = new TextView(getContext());
        l.setText(label);
        l.setTextColor(Color.parseColor("#64748B"));
        l.setTextSize(10);
        l.setTypeface(Typeface.MONOSPACE);
        parent.addView(l);

        TextView c = new TextView(getContext());
        c.setText(content);
        c.setTextColor(Color.parseColor(color));
        c.setTextSize(13);
        c.setLineSpacing(dp(2), 1.1f);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(-1, -2);
        lp.topMargin = dp(2);
        lp.bottomMargin = dp(8);
        parent.addView(c, lp);
    }

    /** 检测项说明 (静态映射, 按名称匹配) */
    private String detailDesc(JSONObject item) {
        String n = item.optString("name", "");
        if (n.contains("TracerPid")) return "检查进程是否被调试器附加。TracerPid>0 表示有调试器正在跟踪当前进程。";
        if (n.contains("ptrace")) return "进程尝试 attach 自身。若返回 EPERM, 说明已被外部调试器抢占跟踪。";
        if (n.contains("父进程")) return "正常 App 由 zygote fork 产生。父进程异常说明被调试器或注入器拉起。";
        if (n.contains("时间差")) return "执行基准指令耗时异常, 说明代码被单步调试或指令被替换。";
        if (n.contains("调试器进程")) return "扫描 /proc 下所有进程, 查找 gdb/lldb/ida 等调试器进程。";
        if (n.contains("inline")) return "检查关键函数机器码是否被改写, 检测 inline hook 注入。";
        if (n.contains("内存映射")) return "扫描 /proc/self/maps, 查找 frida/xposed/zygisk 的库映射特征。";
        if (n.contains("特征线程")) return "frida 注入会创建 gum-js-loop/gmain 等特征线程。";
        if (n.contains("D-Bus")) return "frida-server 默认在 27042 端口监听 D-Bus 协议。";
        if (n.contains("特征文件")) return "检查 /data/local/tmp 等目录下的 frida 特征文件。";
        if (n.contains("环境变量")) return "检查进程环境变量是否含 FRIDA/GUM 等特征前缀。";
        if (n.contains("系统属性")) return "检查 native.bridge 属性, 该属性常被 Xposed 框架修改。";
        if (n.contains("模块路径")) return "检查 /data/adb/modules 下的 Xposed/LSPosed 模块目录。";
        if (n.contains("Zygisk")) return "检查进程内存是否加载了 Magisk Zygisk 模块。";
        if (n.contains("自身路径")) return "获取进程自身可执行文件路径, 用于后续完整性校验。";
        if (n.contains("匿名可执行")) return "检测 rwx 权限的匿名内存映射, 这是代码注入的标志。";
        if (n.contains("W+X")) return "检测 .so 是否同时可写可执行, 异常权限说明被动态修改。";
        if (n.contains("哈希")) return "计算自身文件 SHA-256, 与预期值比对校验完整性。";
        if (n.contains("Build")) return "检查设备型号是否匹配已知模拟器指纹。";
        if (n.contains("硬件平台")) return "检查 ro.hardware 是否为 goldfish/ranchu 等模拟器平台。";
        if (n.contains("属性联动")) return "对比品牌与硬件属性是否矛盾, 模拟器常伪造不一致。";
        if (n.contains("CPU核心")) return "真实手机 CPU 核心数通常 >=2, 模拟器常只有 1 核。";
        if (n.contains("传感器")) return "真实手机传感器通常 5+ 个, 模拟器几乎没有。";
        if (n.contains("运营商")) return "模拟器通常没有真实 SIM 卡, 运营商字段为空。";
        if (n.contains("su二进制")) return "检查常见路径下是否存在 su 可执行文件。";
        if (n.contains("Root管理器")) return "检查 /data/adb 下 Magisk/KernelSU/APatch 特征文件。";
        if (n.contains("test-keys")) return "系统签名使用 test-keys 说明是自定义 ROM。";
        if (n.contains("分区rw")) return "系统分区以 rw 挂载说明被 Root 修改过。";
        if (n.contains("su执行")) return "尝试 fork 执行 su 命令, 成功则说明有 Root 权限。";
        if (n.contains("调试状态")) return "检查系统 ro.debuggable 是否被开启。";
        if (n.contains("SELinux")) return "检查 SELinux 是否被禁用, 禁用说明系统被修改。";
        if (n.contains("编译类型")) return "检查系统编译类型是否为 eng/userdebug 非正式版。";
        if (n.contains("CapEff")) return "检查进程能力位, 普通 App 应为 0, 全 1 说明有特权。";
        if (n.contains("LD_PRELOAD")) return "检查是否通过 LD_PRELOAD 注入动态库。";
        return "当前检测项的详细说明。";
    }

    private String detailAdvice(JSONObject item) {
        String n = item.optString("name", "");
        if (n.contains("调试") || n.contains("ptrace") || n.contains("TracerPid"))
            return "检测到调试器附加, 建议立即终止敏感操作并上报服务器。";
        if (n.contains("Frida") || n.contains("注入") || n.contains("Zygisk") || n.contains("Xposed"))
            return "检测到注入行为, 建议退出当前页面, 并向安全团队告警。";
        if (n.contains("模拟器"))
            return "检测到模拟器环境, 建议禁止敏感操作(如支付/登录)。";
        if (n.contains("Root") || n.contains("su"))
            return "检测到 Root 环境, 建议提示用户关闭 Root 或限制功能。";
        if (n.contains("完整性") || n.contains("哈希") || n.contains("W+X"))
            return "检测到完整性异常, 建议校验安装包或重新安装。";
        return "根据风险等级评估是否阻断操作。";
    }

    private String levelColor(int level) {
        switch (level) {
            case 0: return "#64748B";  // 信息 灰
            case 1: return "#34D399";  // 低 绿
            case 2: return "#F59E0B";  // 中 黄
            case 3: return "#F97316";  // 高 橙
            default: return "#EF4444"; // 严重 红
        }
    }

    private String levelBg(int level) {
        switch (level) {
            case 0: return "#22334455";
            case 1: return "#3306420E";
            case 2: return "#33B45309";
            case 3: return "#33C2410C";
            default: return "#337F1D1D";
        }
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
