package com.canonical.openssl.md;

final public class MDSHA256 extends OpenSSLMD {
    public MDSHA256() {
        super("SHA-256");
    }

    @Override
    protected int engineGetDigestLength() {
        return 32;
    }
}
