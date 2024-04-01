package com.canonical.openssl.md;

final public class MDSHA384 extends OpenSSLMD {
    public MDSHA384() {
        super("SHA-384");
    }

    @Override
    protected int engineGetDigestLength() {
        return 48;
    }
}
