/*
 * anti_debug_bypass.js - 尝试绕过反调试检测
 * 思路: hook ptrace 让其返回成功, 伪造 TracerPid
 */
"use strict";
Java.perform(function () {
    console.log("[*] 尝试绕过反调试...");

    // hook ptrace
    var ptrace = Module.findExportByName(null, "ptrace");
    if (ptrace) {
        Interceptor.replace(ptrace, new NativeCallback(function (request, pid, addr, data) {
            console.log("[!] ptrace 被调用: request=" + request + " pid=" + pid);
            return 0;  // 假装成功
        }, 'int', ['int', 'int', 'pointer', 'pointer']));
        console.log("[*] ptrace 已 hook (返回 0)");
    }

    // hook fopen 伪造 /proc/self/status 的 TracerPid
    var fopen = Module.findExportByName(null, "fopen");
    Interceptor.attach(fopen, {
        onEnter: function (args) {
            this.path = Memory.readUtf8String(args[0]);
            if (this.path && this.path.indexOf("status") >= 0) {
                console.log("[!] 读取 status: " + this.path);
            }
        }
    });
});
