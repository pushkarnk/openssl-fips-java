package com.canonical.openssl.mac;

public final class HMACwithSHA3_512 extends OpenSSLMAC {
    protected String getAlgorithm() {
        return "HMAC";
    }

    protected String getCipherType() {
        return null; 
    }

    protected String getDigestType() {
        return "SHA3-512";
    }

    protected byte[] getIV() {
        return null;
    }
}

