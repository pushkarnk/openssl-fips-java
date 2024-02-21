import java.security.Key;
import java.security.SecureRandom;

public class DHKeyAgreementSpi extends OpenSSLKeyAgreementSpi {
    long initialize(Key key) {
        return engineInit0(OpenSSLKeyAgreementSpi.AGREEMENT_DH, key.getEncoded());
    }
}
