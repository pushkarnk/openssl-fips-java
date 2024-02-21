import java.security.Key;
import java.security.SecureRandom;

public class ECDHKeyAgreementSpi extends OpenSSLKeyAgreementSpi {
    long initialize(Key key) {
        return engineInit0(OpenSSLKeyAgreementSpi.AGREEMENT_ECDH, key.getEncoded());
    }
}
