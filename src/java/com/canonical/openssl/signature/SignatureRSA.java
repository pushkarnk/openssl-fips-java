package com.canonical.openssl.signature;

final class SignatureRSA extends OpenSSLSignature {
    protected String getSignatureName() {
        return "RSA";
    }
}
