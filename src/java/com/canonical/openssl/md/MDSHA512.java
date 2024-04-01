package com.canonical.openssl.md;

final public class MDSHA512 extends OpenSSLMD {
    public MDSHA512() {
        super("SHA-512");
    }

    @Override
    protected int engineGetDigestLength() {
        return 64;
    }
}
