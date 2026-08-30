package com.ce11kjw.aegis;

public class AegisNative {
    static {
        System.loadLibrary("aegis");
    }
    public static native String runAll();
    public static native String runModule(int module);
}
