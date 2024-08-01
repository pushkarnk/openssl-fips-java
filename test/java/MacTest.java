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
import com.canonical.openssl.mac.*;
import java.lang.FunctionalInterface;
import java.util.Arrays;
import java.util.function.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;
import java.nio.ByteBuffer;

@FunctionalInterface
interface TriFunction<A, B, C, D> {
    D apply(A op1, B op2, C op3);
}

public class MacTest {

    private static byte[] key = new byte[] {
        (byte)0x6c, (byte)0xde, (byte)0x14, (byte)0xf5, (byte)0xd5, (byte)0x2a, (byte)0x4a, (byte)0xdf,
        (byte)0x12, (byte)0x39, (byte)0x1e, (byte)0xbf, (byte)0x36, (byte)0xf9, (byte)0x6a, (byte)0x46,
        (byte)0x48, (byte)0xd0, (byte)0xb6, (byte)0x51, (byte)0x89, (byte)0xfc, (byte)0x24, (byte)0x85,
        (byte)0xa8, (byte)0x8d, (byte)0xdf, (byte)0x7e, (byte)0x80, (byte)0x14, (byte)0xc8, (byte)0xce,
        (byte)0x38, (byte)0xb5, (byte)0xb1, (byte)0xe0, (byte)0x82, (byte)0x2c, (byte)0x70, (byte)0xa4,
        (byte)0xc0, (byte)0x8e, (byte)0x5e, (byte)0xf9, (byte)0x93, (byte)0x9f, (byte)0xcf, (byte)0xf7,
        (byte)0x32, (byte)0x4d, (byte)0x0c, (byte)0xbd, (byte)0x31, (byte)0x12, (byte)0x0f, (byte)0x9a,
        (byte)0x15, (byte)0xee, (byte)0x82, (byte)0xdb, (byte)0x8d, (byte)0x29, (byte)0x54, (byte)0x14
    };

    private static byte[] input = """
       From that time on, the world was hers for the reading.
       She would never be lonely again, never miss the lack of intimate friends.
       Books became her friends and there was one for every mood.""".getBytes();

    private static byte[] input1 = """
       From that time on, the world was hers for the reading.
       She would never be lonely again, never miss the lack of intimate friends.
       Books became her friends and there was one for every mood""".getBytes();

    private static TriFunction<TestOpenSSLMAC, SecretKeySpec, byte[], byte[]> macCompute = (mac, keySpec, input) -> {
        mac.engineInit(keySpec, null);
        mac.engineUpdate(input, 0, input.length);
        return mac.engineDoFinal();
    };

    private static void runTest(String name, SecretKeySpec keySpec, Class<? extends TestOpenSSLMAC> macClass) throws Exception {
        System.out.print("Testing " + name + ": ");
        byte[] output1 = macCompute.apply(macClass.newInstance(), keySpec, input);
        byte[] output2 = macCompute.apply(macClass.newInstance(), keySpec, input);
        byte[] output3 = macCompute.apply(macClass.newInstance(), keySpec, input1);
        if (Arrays.equals(output1, output2) && !Arrays.equals(output2, output3)) {
            System.out.println("PASSED");
        } else {
            System.out.println("FAILED");
        }
    }

    private static void testCMAC_AES() throws Exception {
        runTest("CMAC[Cipher: AES-256-CBC]",
            new SecretKeySpec(Arrays.copyOfRange(key, 0, 32), "AES"),
            TestCMACwithAes256CBC.class);

    }

    private static void testGMAC_AES() throws Exception {
        runTest("GMAC[Cipher: AES-128-GCM]",
            new SecretKeySpec(Arrays.copyOfRange(key, 0, 16), "AES"),
            TestGMACWithAes128GCM.class);
    }

    private static void testHMAC_SHA1() throws Exception {
        runTest("HMAC[Digest: SHA1]",
            new SecretKeySpec(Arrays.copyOfRange(key, 0, 64), "HMAC"),
            TestHMACwithSHA1.class);
    }

    private static void testHMAC_SHA3_512() throws Exception {
        runTest("HMAC[Digest: SHA3-512]",
            new SecretKeySpec(Arrays.copyOfRange(key, 0, 64), "HMAC"),
            TestHMACwithSHA3_512.class);
    }

    private static void testKMAC_128() throws Exception {
        runTest("KMAC-128",
            new SecretKeySpec(Arrays.copyOfRange(key, 0, 4), "KMAC-128"),
            TestKMAC128.class);
    }

    private static void testKMAC_256() throws Exception {
        runTest("KMAC-256",
            new SecretKeySpec(Arrays.copyOfRange(key, 0, 32), "KMAC-256"),
            TestKMAC256.class);
    }
 
    public static void main(String[] args) throws Exception {
        testCMAC_AES();
        testGMAC_AES();
        testHMAC_SHA1();
        testHMAC_SHA3_512();
        testKMAC_128();
        testKMAC_256(); 
    }
}

abstract class TestOpenSSLMAC extends OpenSSLMAC {
    @Override
    protected byte[] engineDoFinal() {
        return super.engineDoFinal();
    }

    @Override
    protected int engineGetMacLength() {
        return super.engineGetMacLength();
    }

    @Override
    protected void engineInit(Key key, AlgorithmParameterSpec params) {
        super.engineInit(key, params);
    }

    @Override
    protected void engineReset() {
        super.engineReset();
    }

    @Override
    protected void engineUpdate(byte input) {
        super.engineUpdate(input);
    }

    @Override
    protected void engineUpdate(byte[] input, int offset, int len) {
        super.engineUpdate(input, offset, len);
    }

    @Override
    protected void engineUpdate(ByteBuffer input) {
        super.engineUpdate(input);
    }

    protected abstract String getAlgorithm();
    protected abstract String getCipherType();
    protected abstract String getDigestType();
    protected abstract byte[] getIV();

}

final class TestCMACwithAes256CBC extends TestOpenSSLMAC {
    protected String getAlgorithm() {
        return "CMAC";
    }

    protected String getCipherType() {
        return "AES-256-CBC";
    }

    protected String getDigestType() {
        return null;
    }

    protected byte[] getIV() {
        return null;
    }
}

final class TestGMACWithAes128GCM extends TestOpenSSLMAC {
    protected String getAlgorithm() {
        return "GMAC";
    }

    protected String getCipherType() {
        return "AES-128-GCM";
    }

    protected String getDigestType() {
        return null;
    }

    // TODO: a random IV?
    protected byte[] getIV() {
        return new byte[] { (byte)0xe0, (byte)0xe0, (byte)0x0f, (byte)0x19,
                            (byte)0xfe, (byte)0xd7, (byte)0xba, (byte)0x01,
                            (byte)0x36, (byte)0xa7, (byte)0x97, (byte)0xf3 };
    }
}

final class TestHMACwithSHA1 extends TestOpenSSLMAC {
    protected String getAlgorithm() {
        return "HMAC";
    }

    protected String getCipherType() {
        return null;
    }

    protected String getDigestType() {
        return "SHA1";
    }

    protected byte[] getIV() {
        return null;
    }
}

final class TestHMACwithSHA3_512 extends TestOpenSSLMAC {
    protected String getAlgorithm() {
        return "HMAC";
    }

    protected String getCipherType() {
        return null;
    }

    protected String getDigestType() {
        return "SHA3-512";
    }

    protected byte[] getIV() {
        return null;
    }
}

final class TestKMAC128 extends TestOpenSSLMAC {
    protected String getAlgorithm() {
        return "KMAC-128";
    }

    protected String getCipherType() {
        return null;
    }

    protected String getDigestType() {
        return null;
    }

    protected byte[] getIV() {
        return null;
    }
}

final class TestKMAC256 extends TestOpenSSLMAC {
    protected String getAlgorithm() {
        return "KMAC-256";
    }

    protected String getCipherType() {
        return null;
    }

    protected String getDigestType() {
        return null;
    }

    protected byte[] getIV() {
        return null;
    }
}
