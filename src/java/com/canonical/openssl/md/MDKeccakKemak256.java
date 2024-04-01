package com.canonical.openssl.md;

final public class MDKeccakKemak256 extends OpenSSLMD {
    public MDKeccakKemak256() {
        super("KECCAK-KEMAK-256");
    }

    @Override
    protected int engineGetDigestLength() {
        return 32;
    }
}
