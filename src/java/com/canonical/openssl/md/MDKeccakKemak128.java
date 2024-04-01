package com.canonical.openssl.md;

final public class MDKeccakKemak128 extends OpenSSLMD {
    public MDKeccakKemak128() {
        super("KECCAK-KEMAK-128");
    }

    @Override
    protected int engineGetDigestLength() {
        return 16;
    }
}
