package com.canonical.openssl.md;

final public class MDSHA3_512 extends OpenSSLMD {
    public MDSHA3_512() {
        super("SHA3-512");
    }

    @Override
    protected int engineGetDigestLength() {
        return 64;
    }
}
