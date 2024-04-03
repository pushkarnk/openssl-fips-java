package com.canonical.openssl.keyagreement;

import java.security.Key;
import java.security.SecureRandom;

public final class ECDHKeyAgreement extends OpenSSLKeyAgreement {
    protected long initialize(Key key) {
        return engineInit0(OpenSSLKeyAgreement.AGREEMENT_ECDH, key.getEncoded());
    }

    @Override
    public String toString() {
        return "ECDHKeyAgreement-openssl";
    }

}
