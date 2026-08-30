package com.ce11kjw.aegis.ui;

import android.content.Context;
import android.graphics.Color;
import android.graphics.Typeface;
import android.view.Gravity;
import android.view.View;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

/**
 * KnowledgeBasePage - 安全知识库 (第二页)
 * 7 大模块 37 项完整技术文档, 点击展开: 原理/攻击场景/证据解读/防御建议
 */
public class KnowledgeBasePage extends LinearLayout {

    public KnowledgeBasePage(Context context) {
        super(context);
        setOrientation(LinearLayout.VERTICAL);

        ScrollView scroll = new ScrollView(context);
        scroll.setFillViewport(true);
        scroll.setVerticalScrollBarEnabled(false);
        addView(scroll, new LayoutParams(-1, -1));

        LinearLayout content = new LinearLayout(context);
        content.setOrientation(LinearLayout.VERTICAL);
        content.setPadding(dp(20), dp(16), dp(20), dp(16));
        scroll.addView(content);

        // ===== 页头 =====
        TextView eyebrow = new TextView(context);
        eyebrow.setText("SECURITY KNOWLEDGE");
        eyebrow.setTextColor(Color.parseColor("#22D3EE"));
        eyebrow.setTextSize(11);
        eyebrow.setTypeface(Typeface.MONOSPACE);
        eyebrow.setLetterSpacing(0.15f);
        content.addView(eyebrow);

        TextView title = new TextView(context);
        title.setText("安全知识库");
        title.setTextColor(Color.parseColor("#F8FAFC"));
        title.setTextSize(26);
        title.setTypeface(Typeface.create("sans-serif-medium", Typeface.BOLD));
        content.addView(title);

        TextView sub = new TextView(context);
        sub.setText("7 大模块 · 37 项检测技术文档\n点击模块展开, 点击检测项查看完整原理与防御");
        sub.setTextColor(Color.parseColor("#94A3B8"));
        sub.setTextSize(13);
        sub.setLineSpacing(dp(2), 1.1f);
        LinearLayout.LayoutParams subLp = new LinearLayout.LayoutParams(-1, -2);
        subLp.bottomMargin = dp(16);
        content.addView(sub, subLp);

        // ===== 模块浏览卡片 =====
        int[] counts = {20, 20, 16, 17, 22, 36, 19, 6};
        for (int m = 0; m < 7; m++) {
            final int modIdx = m;
            final String modName = KnowledgeData.MODULE_NAMES[m];

            GlassCard card = new GlassCard(context);
            LinearLayout header = new LinearLayout(context);
            header.setOrientation(LinearLayout.HORIZONTAL);
            header.setGravity(Gravity.CENTER_VERTICAL);

            TextView icon = new TextView(context);
            icon.setText(moduleIcon(m));
            icon.setTextSize(20);
            header.addView(icon);

            TextView name = new TextView(context);
            name.setText(modName);
            name.setTextColor(Color.parseColor("#E2E8F0"));
            name.setTextSize(17);
            name.setTypeface(Typeface.create("sans-serif-medium", Typeface.BOLD));
            LinearLayout.LayoutParams nameLp = new LinearLayout.LayoutParams(0, -2, 1);
            nameLp.leftMargin = dp(12);
            header.addView(name, nameLp);

            TextView badge = new TextView(context);
            badge.setText(counts[m] + " 项");
            badge.setTextColor(Color.parseColor("#94A3B8"));
            badge.setTextSize(12);
            badge.setTypeface(Typeface.MONOSPACE);
            badge.setGravity(Gravity.CENTER);
            badge.setPadding(dp(8), dp(3), dp(8), dp(3));
            badge.setBackground(roundRect(Color.parseColor("#16202E"), dp(10)));
            header.addView(badge);

            TextView arrow = new TextView(context);
            arrow.setText("▾");
            arrow.setTextColor(Color.parseColor("#64748B"));
            arrow.setTextSize(14);
            LinearLayout.LayoutParams arrowLp = new LinearLayout.LayoutParams(-2, -2);
            arrowLp.leftMargin = dp(8);
            header.addView(arrow, arrowLp);

            card.inner().addView(header);

            // 该模块检测项列表 (初始隐藏)
            final LinearLayout list = new LinearLayout(context);
            list.setOrientation(LinearLayout.VERTICAL);
            list.setVisibility(View.GONE);
            LinearLayout.LayoutParams listLp = new LinearLayout.LayoutParams(-1, -2);
            listLp.topMargin = dp(10);
            card.inner().addView(list, listLp);

            // 该模块的检测项
            String[] items = moduleItems(m);
            for (int i = 0; i < items.length; i++) {
                addKnowledgeRow(list, items[i]);
            }

            header.setOnClickListener(new OnClickListener() {
                @Override public void onClick(View v) {
                    boolean show = list.getVisibility() == View.GONE;
                    list.setVisibility(show ? View.VISIBLE : View.GONE);
                }
            });

            LinearLayout.LayoutParams cardLp = new LinearLayout.LayoutParams(-1, -2);
            cardLp.topMargin = dp(12);
            content.addView(card, cardLp);
        }

        // ===== 页脚 =====
        TextView footer = new TextView(context);
        footer.setText("Aegis Knowledge Base\n检测原理基于公开安全研究与攻防实践");
        footer.setTextColor(Color.parseColor("#475569"));
        footer.setTextSize(11);
        footer.setGravity(Gravity.CENTER);
        footer.setLineSpacing(dp(2), 1.1f);
        footer.setPadding(0, dp(20), 0, dp(8));
        content.addView(footer);
    }

    /** 单个知识项: 点击展开完整文档 */
    private void addKnowledgeRow(LinearLayout container, final String name) {
        LinearLayout row = new LinearLayout(getContext());
        row.setOrientation(LinearLayout.HORIZONTAL);
        row.setGravity(Gravity.CENTER_VERTICAL);
        row.setPadding(dp(8), dp(8), dp(8), dp(8));
        row.setBackground(roundRect(Color.parseColor("#1E2433"), dp(12)));

        TextView bullet = new TextView(getContext());
        bullet.setText("◆");
        bullet.setTextColor(Color.parseColor("#22D3EE"));
        bullet.setTextSize(10);
        row.addView(bullet);

        TextView tv = new TextView(getContext());
        tv.setText(name);
        tv.setTextColor(Color.parseColor("#CBD5E1"));
        tv.setTextSize(14);
        LinearLayout.LayoutParams tvLp = new LinearLayout.LayoutParams(0, -2, 1);
        tvLp.leftMargin = dp(10);
        row.addView(tv, tvLp);

        TextView more = new TextView(getContext());
        more.setText("详情 ▸");
        more.setTextColor(Color.parseColor("#22D3EE"));
        more.setTextSize(12);
        row.addView(more);

        LinearLayout.LayoutParams rowLp = new LinearLayout.LayoutParams(-1, -2);
        rowLp.topMargin = dp(6);
        container.addView(row, rowLp);

        // 详情面板
        final String[] info = KnowledgeData.itemInfo(name);
        final LinearLayout detail = new LinearLayout(getContext());
        detail.setOrientation(LinearLayout.VERTICAL);
        detail.setPadding(dp(10), dp(10), dp(10), dp(10));
        detail.setBackground(roundRect(Color.parseColor("#151A26"), dp(10)));
        detail.setVisibility(View.GONE);

        addDocLine(detail, "检测原理", info[0]);
        addDocLine(detail, "攻击场景", info[1]);
        addDocLine(detail, "证据解读", info[2]);
        addDocLine(detail, "防御建议", info[3]);

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
    }

    private void addDocLine(LinearLayout parent, String label, String content) {
        TextView l = new TextView(getContext());
        l.setText(label);
        l.setTextColor(Color.parseColor("#64748B"));
        l.setTextSize(10);
        l.setTypeface(Typeface.MONOSPACE);
        parent.addView(l);

        TextView c = new TextView(getContext());
        c.setText(content);
        c.setTextColor(Color.parseColor("#CBD5E1"));
        c.setTextSize(13);
        c.setLineSpacing(dp(2), 1.15f);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(-1, -2);
        lp.topMargin = dp(2);
        lp.bottomMargin = dp(8);
        parent.addView(c, lp);
    }

    private String moduleIcon(int m) {
        switch (m) {
            case 0: return "🐞";
            case 1: return "💉";
            case 2: return "🧩";
            case 3: return "🔐";
            case 4: return "📱";
            case 5: return "👑";
            case 7: return "🌐";
            default: return "🖥️";
        }
    }

    private String[] moduleItems(int m) {
        switch (m) {
            case 0: return new String[]{"TracerPid调试跟踪","ptrace抢占检测","父进程审计","调试时间差检测","调试器进程扫描","inline hook检测"};
            case 1: return new String[]{"内存映射Frida特征","特征线程扫描","D-Bus端口探测","套接字特征","Frida特征文件","环境变量检测"};
            case 2: return new String[]{"内存映射Xposed特征","系统属性检测","Xposed模块路径","Zygisk注入检测"};
            case 3: return new String[]{"自身路径校验","匿名可执行映射","W+X so检测","so哈希校验"};
            case 4: return new String[]{"Build字段检测","硬件平台检测","属性联动检测","CPU核心数检测","传感器数量检测","运营商检测"};
            case 5: return new String[]{"su二进制检测","Root管理器特征","test-keys签名","系统分区rw挂载","su执行测试","magiskpolicy检测","KernelSU检测","APatch检测","busybox检测","Magisk镜像","dm-verity检测","DenyList检测","bootloader解锁","vbmeta校验","Magisk环境变量","内核cmdline","管理器APK","系统分区rw细查","Zygisk环境","magiskd守护进程","ksud守护进程","zygiskd守护进程","which su/magisk","Magisk隐藏挂载","模块枚举","Zygisk数据目录","KSU内核特征","APatch内核特征","SELinux不一致","build属性篡改"};
            case 7: return new String[]{"全局代理检测","VPN接口检测","用户CA证书检测","USB调试检测","ADB连接检测","可疑端口监听"};
            default: return new String[]{"系统调试状态","SELinux状态","编译类型","CapEff权限","LD_PRELOAD检测","属性联动检测"};
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
