package com.canonical.openssl.mac;

public final class KMAC128 extends OpenSSLMAC {
    protected String getAlgorithm() {
        return "KMAC-128";
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

