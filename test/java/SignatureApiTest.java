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
import java.security.Security;
import java.security.Signature;
import com.canonical.openssl.provider.OpenSSLFIPSProvider;

public class SignatureApiTest {
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
        testSignature("RSA", gen.pubKey, gen.privKey);
    }

    private static void testED25519() throws Exception {
        EdDSAPublicKey publicKey = new EdDSAPublicKey("test/keys/ed25519-pub.pem");
        EdDSAPrivateKey privateKey = new EdDSAPrivateKey("test/keys/ed25519-priv.pem");
        testSignature("ED25519", publicKey, privateKey);
    }

    private static void testED448() throws Exception {
        EdDSAPublicKey publicKey = new EdDSAPublicKey("test/keys/ed448-pub.pem");
        EdDSAPrivateKey privateKey = new EdDSAPrivateKey("test/keys/ed448-priv.pem");
        testSignature("ED448", publicKey, privateKey);
    }

    private static void testSignature(String algo,  PublicKey publicKey, PrivateKey privateKey) throws Exception {
        System.out.print("Testing " + algo + " Signatures: ");
        Signature signer = Signature.getInstance(algo, "OpenSSLFIPSProvider");
        if (algo.equals("RSA")) {
            signer.setParameter("digest", "SHA-256"); // TODO: why does this work only with SHA-256? 
        }
        signer.initSign(privateKey);
        byte[] bytes = message.getBytes();
        signer.update(bytes, 0, bytes.length);
        byte[] sigBytes = signer.sign();

        Signature verifier = Signature.getInstance(algo, "OpenSSLFIPSProvider");
        if (algo.equals("RSA")) {
            verifier.setParameter("digest", "SHA-256");
        }
        verifier.initVerify(publicKey);
        verifier.update(bytes, 0, bytes.length);
        System.out.println(verifier.verify(sigBytes) ? "PASSED": "FAILED");
    }

    public static void main(String[] args) throws Exception {
        Security.addProvider(new OpenSSLFIPSProvider());
        testRSA();
        testED25519();
        testED448();
    }
}
