package com.canonical.openssl.keyagreement;

import java.security.Key;
import java.security.SecureRandom;

final public class DHKeyAgreement extends OpenSSLKeyAgreement {
    protected long initialize(Key key) {
        return engineInit0(OpenSSLKeyAgreement.AGREEMENT_DH, key.getEncoded());
    }
}
