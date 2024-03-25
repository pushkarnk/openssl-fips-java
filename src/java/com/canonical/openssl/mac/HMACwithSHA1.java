package com.canonical.openssl.mac;

public final class HMACwithSHA1 extends OpenSSLMAC {
    protected String getAlgorithm() {
        return "HMAC";
    }

    protected String getCipherType() {
        return null;
    }

    protected String getDigestType() {
        return "SHA1";
    }

    protected byte[] getIV() {
        return null; 
    }
}

