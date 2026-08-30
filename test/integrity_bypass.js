/*
 * integrity_bypass.js - 尝试绕过完整性校验
 * 思路: hook 文件读取返回伪造数据
 */
"use strict";
Java.perform(function () {
    console.log("[*] 完整性绕过测试...");

    // 尝试 hook fopen 观察完整性检测读取哪些文件
    var fopen = Module.findExportByName(null, "fopen");
    Interceptor.attach(fopen, {
        onEnter: function (args) {
            var path = Memory.readUtf8String(args[0]);
            if (path && (path.indexOf("dex") >= 0 || path.indexOf(".so") >= 0)) {
                console.log("[!] 完整性检测读取: " + path);
            }
        }
    });
});
