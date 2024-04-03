package com.canonical.openssl.signature;

public final class SignatureED25519 extends OpenSSLSignature {
    protected String getSignatureName() {
        return "ED25519";
    }
}
