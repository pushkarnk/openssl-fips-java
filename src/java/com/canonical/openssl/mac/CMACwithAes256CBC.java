package com.canonical.openssl.mac;

public final class CMACwithAes256CBC extends OpenSSLMAC {
    protected String getAlgorithm() {
        return "CMAC";
    } 

    protected String getCipherType() {
        return "AES-256-CBC";
    }

    protected String getDigestType() {
        return null;
    }

    protected byte[] getIV() {
        return null;
    }
}
