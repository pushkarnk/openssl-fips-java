package com.canonical.openssl.signature;

final class SignatureED448 extends OpenSSLSignature {
    protected String getSignatureName() {
        return "ED448";
    }
}
