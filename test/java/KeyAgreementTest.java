import java.security.KeyPair;
import java.util.Arrays;
import java.security.KeyPairGenerator;

public class KeyAgreementTest {

    private static boolean runTest(KeyPairGenerator kpg, Class <? extends OpenSSLKeyAgreementSpi> spiClass) throws Exception {
        KeyPair aliceKp = kpg.generateKeyPair();
        KeyPair bobKp = kpg.generateKeyPair();
        OpenSSLKeyAgreementSpi aliceAgreement = spiClass.newInstance();
        OpenSSLKeyAgreementSpi bobAgreement = spiClass.newInstance();
        aliceAgreement.engineInit(aliceKp.getPrivate(), null);
        aliceAgreement.engineDoPhase(bobKp.getPublic(), true);
        bobAgreement.engineInit(bobKp.getPrivate(), null);
        bobAgreement.engineDoPhase(aliceKp.getPublic(), true);
        byte[] aliceSecret = aliceAgreement.engineGenerateSecret();
        byte[] bobSecret = bobAgreement.engineGenerateSecret();
        return Arrays.equals(aliceSecret, bobSecret);
   }

    public static void testDH() throws Exception {
        System.out.print("Test Key Agreement [Diffie-Hellman]: ");
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH");
        if (runTest(kpg, DHKeyAgreementSpi.class)) {
            System.out.println("PASSED");
        } else {
            System.out.println("FAILED");
        }
    }

    public static void testECDH() throws Exception {
        System.out.print("Test Key Agreement [Elliptic-Curve]: ");
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        if (runTest(kpg, ECDHKeyAgreementSpi.class)) {
            System.out.println("PASSED");
        } else {
            System.out.println("FAILED");
        }
    }

    public static void main(String[] args) throws Exception {
        testDH();
        testECDH();
    }
}
