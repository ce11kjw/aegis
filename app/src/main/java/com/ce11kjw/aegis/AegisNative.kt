package com.ce11kjw.aegis

/**
 * JNI 桥接层
 * native 方法签名必须与 engine/src/jni_bridge.c 保持一致
 */
object AegisNative {
    init { System.loadLibrary("aegis") }

    /** 运行全部检测，返回 JSON */
    external fun runAll(): String?

    /** 运行单个模块（0-10），返回 JSON */
    external fun runModule(module: Int): String?

    /** 按模块集合运行（v4.1），返回 JSON */
    external fun runModules(modules: IntArray): String?
}
