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
import java.security.Key;
import java.security.SecureRandom;
import java.security.Security;
import java.security.KeyPair;
import java.util.Arrays;
import java.security.KeyPairGenerator;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.SecretKey;
import javax.crypto.KeyAgreement;
import com.canonical.openssl.provider.OpenSSLFIPSProvider;

public class KeyAgreementApiTest {

    private static boolean runTest(KeyPairGenerator kpg, String algo) throws Exception {
        KeyPair aliceKp = kpg.generateKeyPair();
        KeyPair bobKp = kpg.generateKeyPair();
        KeyAgreement aliceAgreement = KeyAgreement.getInstance(algo, "OpenSSLFIPSProvider");
        KeyAgreement bobAgreement = KeyAgreement.getInstance(algo, "OpenSSLFIPSProvider");
        aliceAgreement.init(aliceKp.getPrivate());
        aliceAgreement.doPhase(bobKp.getPublic(), true);
        bobAgreement.init(bobKp.getPrivate());
        bobAgreement.doPhase(aliceKp.getPublic(), true);
        byte[] aliceSecret = aliceAgreement.generateSecret();
        byte[] bobSecret = bobAgreement.generateSecret();
        return Arrays.equals(aliceSecret, bobSecret);
   }

    public static void testDH() throws Exception {
        System.out.print("Test Key Agreement [Diffie-Hellman]: ");
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH");
        if (runTest(kpg, "DH")) {
            System.out.println("PASSED");
        } else {
            System.out.println("FAILED");
        }
    }

    public static void testECDH() throws Exception {
        System.out.print("Test Key Agreement [Elliptic-Curve]: ");
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        if (runTest(kpg, "ECDH")) {
            System.out.println("PASSED");
        } else {
            System.out.println("FAILED");
        }
    }

    public static void main(String[] args) throws Exception {
        Security.addProvider(new OpenSSLFIPSProvider());
        testDH();
        testECDH();
    }
}
