package com.canonical.openssl.md;

final public class MDSHA3_384 extends OpenSSLMD {
    public MDSHA3_384() {
        super("SHA3-384");
    }

    @Override
    protected int engineGetDigestLength() {
        return 48;
    }
}
