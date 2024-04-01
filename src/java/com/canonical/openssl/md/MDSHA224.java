package com.canonical.openssl.md;

final public class MDSHA224 extends OpenSSLMD {
    public MDSHA224() {
        super("SHA-224");
    }

    @Override
    protected int engineGetDigestLength() {
        return 28;
    }
}
