import java.security.KeyPair;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.util.Arrays;
import java.security.KeyPairGenerator;
import javax.crypto.KEM;
import javax.crypto.KEM.Encapsulated;
import javax.crypto.KEM.Encapsulator;
import javax.crypto.KEM.Decapsulator;
import javax.crypto.SecretKey;
import java.security.Security;
import com.canonical.openssl.provider.OpenSSLFIPSProvider;

public class KeyEncapsulationApiTest {
    public static void main(String[] args) throws Exception {
        Security.addProvider(new OpenSSLFIPSProvider());
        System.out.print("Testing KEM with RSA: ");
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(4096);
        // Alice creates a key pair and shares the public key with Bob
        KeyPair aliceKeys = kpg.generateKeyPair();
        PublicKey alicePublicKey = aliceKeys.getPublic();
        PrivateKey alicePrivateKey = aliceKeys.getPrivate();

        // Bob generates a shared secret and wraps it using Alice's public key
        KEM bobKem = KEM.getInstance("RSA", "OpenSSLFIPSProvider");
        Encapsulator encapsulator = bobKem.newEncapsulator(alicePublicKey, null, null);
        int secretSize = encapsulator.secretSize();
        KEM.Encapsulated encapsulated = encapsulator.encapsulate(0, secretSize, "AES");
        SecretKey bobSecret = encapsulated.key();

        // Bob sends the encapsulated secret to Alice
        // Alice uses her RSA private key to unwrap the shared secret
        KEM aliceKem = KEM.getInstance("RSA", "OpenSSLFIPSProvider");
        Decapsulator decapsulator = aliceKem.newDecapsulator(alicePrivateKey, null);
        byte[] encapsulationBytes = encapsulated.encapsulation();
        SecretKey aliceSecret = decapsulator.decapsulate(encapsulationBytes, 0, encapsulationBytes.length, "AES");

        if (aliceSecret.equals(bobSecret)) {
            System.out.println("PASSED");
        } else {
            System.out.println("FAILED");
        }
    }
}
