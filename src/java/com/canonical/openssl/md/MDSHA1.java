package com.canonical.openssl.md;

final public class MDSHA1 extends OpenSSLMD {
    public MDSHA1() {
        super("SHA-1");
    }

    @Override
    protected int engineGetDigestLength() {
        return 20;
    }
}
