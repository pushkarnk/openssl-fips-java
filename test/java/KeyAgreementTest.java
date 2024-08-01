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
import com.canonical.openssl.keyagreement.*;
import java.security.Key;
import java.security.SecureRandom;
import java.security.KeyPair;
import java.util.Arrays;
import java.security.KeyPairGenerator;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.SecretKey;

public class KeyAgreementTest {

    private static boolean runTest(KeyPairGenerator kpg, Class <? extends TestOpenSSLKeyAgreement> spiClass) throws Exception {
        KeyPair aliceKp = kpg.generateKeyPair();
        KeyPair bobKp = kpg.generateKeyPair();
        TestOpenSSLKeyAgreement aliceAgreement = spiClass.newInstance();
        TestOpenSSLKeyAgreement bobAgreement = spiClass.newInstance();
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
        if (runTest(kpg, TestDHKeyAgreement.class)) {
            System.out.println("PASSED");
        } else {
            System.out.println("FAILED");
        }
    }

    public static void testECDH() throws Exception {
        System.out.print("Test Key Agreement [Elliptic-Curve]: ");
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        if (runTest(kpg, TestECDHKeyAgreement.class)) {
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

abstract class TestOpenSSLKeyAgreement extends OpenSSLKeyAgreement {
    public Key engineDoPhase(Key key, boolean lastPhase) {
        return super.engineDoPhase(key, lastPhase);
    }

    public byte[] engineGenerateSecret() {
        return super.engineGenerateSecret();
    }

    public int engineGenerateSecret(byte[] sharedSecret, int offset) {
        return super.engineGenerateSecret(sharedSecret, offset);
    }

    public SecretKey engineGenerateSecret(String algorithm) {
        return super.engineGenerateSecret(algorithm);
    }

    public void engineInit(Key key, SecureRandom random) {
        super.engineInit(key, random);
    }

    public void engineInit(Key key, AlgorithmParameterSpec params, SecureRandom random) {
        super.engineInit(key, params, random);
    }
}

class TestDHKeyAgreement extends TestOpenSSLKeyAgreement {
    protected long initialize(Key key) {
        return engineInit0(OpenSSLKeyAgreement.AGREEMENT_DH, key.getEncoded());
    }
}

class TestECDHKeyAgreement extends TestOpenSSLKeyAgreement {
    protected long initialize(Key key) {
        return engineInit0(OpenSSLKeyAgreement.AGREEMENT_ECDH, key.getEncoded());
    }
}
