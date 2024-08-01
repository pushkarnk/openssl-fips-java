/*
 * Copyright (C) Canonical, Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 3.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */
import com.canonical.openssl.signature.*;
import com.canonical.openssl.key.OpenSSLKey;
import com.canonical.openssl.key.OpenSSLPublicKey;
import com.canonical.openssl.key.OpenSSLPrivateKey;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.util.Arrays;
import java.nio.ByteBuffer;
import java.security.spec.AlgorithmParameterSpec;
import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;

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
        testSignature("RSA", TestSignatureRSA.class, gen.pubKey, gen.privKey);
    }

    private static void testED25519() throws Exception {
        EdDSAPublicKey publicKey = new EdDSAPublicKey("test/keys/ed25519-pub.pem");
        EdDSAPrivateKey privateKey = new EdDSAPrivateKey("test/keys/ed25519-priv.pem");
        testSignature("ED25519", TestSignatureED25519.class, publicKey, privateKey);
    }

    private static void testED448() throws Exception {
        EdDSAPublicKey publicKey = new EdDSAPublicKey("test/keys/ed448-pub.pem");
        EdDSAPrivateKey privateKey = new EdDSAPrivateKey("test/keys/ed448-priv.pem");
        testSignature("ED448", TestSignatureED448.class, publicKey, privateKey);
    }

    private static void testSignature(String algo, Class<? extends TestSignature> clazz, PublicKey publicKey, PrivateKey privateKey) throws Exception {
        System.out.print("Testing " + algo + " Signatures: ");
        TestSignature signer = (TestSignature) clazz.newInstance();
        if (algo.equals("RSA")) {
            signer.engineSetParameter("digest", "SHA-256"); // TODO: why does this work only with SHA-256? 
        }
        signer.engineInitSign(privateKey);
        byte[] bytes = message.getBytes();
        signer.engineUpdate(bytes, 0, bytes.length);
        byte[] sigBytes = signer.engineSign();

        TestSignature verifier = (TestSignature) clazz.newInstance();
        if (algo.equals("RSA")) {
            signer.engineSetParameter("digest", "SHA-256");
        }
        verifier.engineInitVerify(publicKey);
        verifier.engineUpdate(bytes, 0, bytes.length);
        System.out.println(verifier.engineVerify(sigBytes) ? "PASSED": "FAILED");
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

abstract class TestSignature extends OpenSSLSignature {

    protected abstract String getSignatureName();

    @Override
    public Object engineGetParameter(String param) {
        return super.engineGetParameter(param);
    }

    @Override
    public void engineSetParameter(String param, Object value) {
        super.engineSetParameter(param, value);
    }

    @Override
    public void engineInitSign(PrivateKey key) throws InvalidKeyException {
        super.engineInitSign(key);
    }

    @Override
    public void engineInitSign(PrivateKey key, SecureRandom random) throws InvalidKeyException {
        super.engineInitSign(key, random);
    }

    @Override
    public void engineInitVerify(PublicKey key) throws InvalidKeyException {
        super.engineInitVerify(key);
    }

    @Override
    public AlgorithmParameters engineGetParameters() {
        return super.engineGetParameters();
    }

    @Override
    public void engineSetParameter(AlgorithmParameterSpec params) {
        super.engineSetParameter(params);
    }

    @Override
    public byte[] engineSign() {
        return super.engineSign();
    }

    @Override
    public int engineSign(byte[] outbuf, int offset, int len) {
        return super.engineSign(outbuf, offset, len);
    }

    @Override
    public void engineUpdate(byte b) throws SignatureException {
        super.engineUpdate(b);
    }

    @Override
    public void engineUpdate(byte[] b, int off, int len) throws SignatureException {
        super.engineUpdate(b, off, len);
    }

    @Override
    public void engineUpdate(ByteBuffer input) {
        super.engineUpdate(input);
    }

    @Override
    public boolean engineVerify(byte[] sigBytes) {
        return super.engineVerify(sigBytes);
    }

    @Override
    public boolean engineVerify(byte[] sigBytes, int offset, int length) {
        return super.engineVerify(sigBytes, offset, length);
    }
}

class TestSignatureED25519 extends TestSignature {
    public String getSignatureName() {
        return "ED25519";
    }
}

class TestSignatureED448 extends TestSignature {
    public String getSignatureName() {
        return "ED448";
    }
}

class TestSignatureRSA extends TestSignature {
    public String getSignatureName() {
        return "RSA";
    }
}
