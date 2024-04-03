package com.canonical.openssl.signature;

public final class SignatureED448 extends OpenSSLSignature {
    protected String getSignatureName() {
        return "ED448";
    }
}
