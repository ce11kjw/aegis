/*
 * attack_all.js - 对 Aegis 引擎发起 Frida 攻击测试
 * 用途: 验证检测是否有效, 找出绕过点, 反哺引擎加固
 * 用法: frida -U -f com.ce11kjw.aegis -l attack_all.js
 */
"use strict";

// 检测当前注入状态
Java.perform(function () {
    console.log("[*] Frida 注入成功, 当前 PID: " + Process.id);
    console.log("[*] 平台: " + Process.platform + " / " + Process.arch);

    // 尝试 hook 关键检测函数 (如果引擎导出符号)
    var libaegis = Process.findModuleByName("libaegis.so");
    if (libaegis) {
        console.log("[*] 找到 libaegis.so @ " + libaegis.base);
        console.log("[*] 导出符号:");
        libaegis.enumerateSymbols().slice(0, 30).forEach(function (s) {
            console.log("    " + s.name);
        });
    } else {
        console.log("[!] 未找到 libaegis.so");
    }
});

// 尝试绕过 /proc/self/maps 扫描 (核心检测手段)
var readFile = Module.findExportByName(null, "fopen");
Interceptor.attach(readFile, {
    onEnter: function (args) {
        this.path = Memory.readUtf8String(args[0]);
        if (this.path && this.path.indexOf("/proc/self/maps") >= 0) {
            console.log("[!] 检测到 maps 读取: " + this.path);
            this.hooked = true;
        }
    }
});
