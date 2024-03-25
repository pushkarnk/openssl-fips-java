package com.canonical.openssl.mac;

public final class KMAC256 extends OpenSSLMAC {
    protected String getAlgorithm() {
        return "KMAC-256";
    }

    protected String getCipherType() {
        return null;
    }

    protected String getDigestType() {
        return null;
    }

    protected byte[] getIV() {
        return null;
    }
}

