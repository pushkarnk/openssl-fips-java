import java.security.PublicKey;
import java.security.PrivateKey;
import java.util.Arrays;
import java.security.SignatureSpi;

public class SignatureTest {
    static {
        System.loadLibrary("sigtest");
    }

    static String message = "Apollo is one of the Olympian deities in classical "
         + "Greek and Roman religion and Greek and Roman mythology. Apollo "
         + "has been recognized as a god of archery, music and dance, truth "
         + "and prophecy, healing and diseases, the Sun and light, poetry, "
         + "and more. One of the most important and complex of the Greek gods, "
         + "he is the son of Zeus and Leto, and the twin brother of Artemis, "
         + "goddess of the hunt. He is considered to be the most beautiful "
         + "god and is represented as the ideal of the kouros (ephebe, or a "
         + "beardless, athletic youth). Apollo is known in Greek-influenced "
         + "Etruscan mythology as Apulu.";

    private static void testRSA() throws Exception {
        RSAKeyPairGenerator gen = new RSAKeyPairGenerator();
        gen.generateKeyPair();
        testSignature("RSA", OpenSSLSignatureRSA.class, gen.pubKey, gen.privKey);
    }

    private static void testED25519() throws Exception {
        EdDSAPublicKey publicKey = new EdDSAPublicKey("test/keys/ed25519-pub.pem");
        EdDSAPrivateKey privateKey = new EdDSAPrivateKey("test/keys/ed25519-priv.pem");
        testSignature("ED25519", OpenSSLSignatureED25519.class, publicKey, privateKey);
    }

    private static void testSignature(String algo, Class<?> clazz, PublicKey publicKey, PrivateKey privateKey) throws Exception {
        System.out.print("Testing " + algo + " Signatures: ");
        OpenSSLSignatureSpi signer = (OpenSSLSignatureSpi) clazz.newInstance();
        if (algo.equals("RSA")) {
            signer.engineSetParameter("digest", "SHA-256"); // TODO: why does this work only with SHA-256? 
        }
        signer.engineInitSign(privateKey);
        byte[] bytes = message.getBytes();
        signer.engineUpdate(bytes, 0, bytes.length);
        byte[] sigBytes = signer.engineSign();

        OpenSSLSignatureSpi verifier = (OpenSSLSignatureSpi) clazz.newInstance();
        if (algo.equals("RSA")) {
            signer.engineSetParameter("digest", "SHA-256");
        }
        verifier.engineInitVerify(publicKey);
        verifier.engineUpdate(bytes, 0, bytes.length);
        System.out.println(verifier.engineVerify(sigBytes) ? "PASSED": "FAILED");
    }

    private static void testED448() throws Exception {
        EdDSAPublicKey publicKey = new EdDSAPublicKey("test/keys/ed448-pub.pem");
        EdDSAPrivateKey privateKey = new EdDSAPrivateKey("test/keys/ed448-priv.pem");
        testSignature("ED448", OpenSSLSignatureED448.class, publicKey, privateKey);
    }

    public static void main(String[] args) throws Exception {
        testRSA();
        testED25519();
        testED448();
    }
}

class TestKey {
    public byte[] getEncoded() {
        return null;
    }

    public String getFormat() {
        return null;
    }

    public String getAlgorithm() {
        return "";
    }
}
 
class EdDSAPublicKey extends TestKey implements OpenSSLPublicKey {
   long nativeKey = 0L; 
   public long getNativeKeyHandle() {
       return nativeKey;
   }

   EdDSAPublicKey(String filename) {
       nativeKey = readPubKeyFromPem0(filename);
   }

   native long readPubKeyFromPem0(String filename);
}

class EdDSAPrivateKey extends TestKey implements OpenSSLPrivateKey {
    long nativeKey = 0L;
    public long getNativeKeyHandle() {
        return nativeKey; 
    }

    EdDSAPrivateKey(String filename) {
        nativeKey = readPrivKeyFromPem0(filename);
    }

    native long readPrivKeyFromPem0(String filename);
}

class RSAPublicKey extends TestKey implements OpenSSLPublicKey {
    long nativeKey = 0L;

    public RSAPublicKey(long nativeKey) {
        this.nativeKey = nativeKey;
    }

    public long getNativeKeyHandle() {
        return nativeKey; 
    }
}

class RSAPrivateKey extends TestKey implements OpenSSLPrivateKey {
    long nativeKey = 0L;

    public RSAPrivateKey(long nativeKey) {
        this.nativeKey = nativeKey;
    }

    public long getNativeKeyHandle() {
        return nativeKey;
    }
}

class RSAKeyPairGenerator {
    long nativePrivKey = 0;
    long nativePubKey = 0;

    RSAPrivateKey privKey;
    RSAPublicKey pubKey;

    public void generateKeyPair() {
        generateKeyPair0();
        privKey = new RSAPrivateKey(nativePrivKey);
        pubKey = new RSAPublicKey(nativePubKey);
    }

    private native void generateKeyPair0();
}
