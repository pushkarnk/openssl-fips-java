package com.canonical.openssl.util;

import java.lang.ref.Cleaner;

public class NativeMemoryCleaner {
    public static Cleaner cleaner = Cleaner.create();
}
