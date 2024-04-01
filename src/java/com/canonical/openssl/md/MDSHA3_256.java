package com.canonical.openssl.md;

final public class MDSHA3_256 extends OpenSSLMD {
    public MDSHA3_256() {
        super("SHA3-256");
    }

    @Override
    protected int engineGetDigestLength() {
        return 32;
    }
}
