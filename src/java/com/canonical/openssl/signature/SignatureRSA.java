package com.canonical.openssl.signature;

public final class SignatureRSA extends OpenSSLSignature {
    protected String getSignatureName() {
        return "RSA";
    }
}
