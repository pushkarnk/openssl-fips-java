package com.canonical.openssl.md;

final public class MDSHA3_224 extends OpenSSLMD {
    public MDSHA3_224() {
        super("SHA3-224");
    }

    @Override
    protected int engineGetDigestLength() {
        return 28;
    }
}
