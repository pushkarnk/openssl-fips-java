import java.lang.FunctionalInterface;
import java.util.Arrays;
import java.util.function.*;
import javax.crypto.spec.SecretKeySpec;

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

    private static TriFunction<OpenSSLMACSpi, SecretKeySpec, byte[], byte[]> macCompute = (mac, keySpec, input) -> {
        mac.engineInit(keySpec, null);
        mac.engineUpdate(input, 0, input.length);
        return mac.engineDoFinal();
    };

    private static void runTest(String name, SecretKeySpec keySpec, Class<? extends OpenSSLMACSpi> macClass) throws Exception {
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
            OpenSSLCMACAesSpi.class);

    }

    private static void testGMAC_AES() throws Exception {
        runTest("GMAC[Cipher: AES-128-GCM]",
            new SecretKeySpec(Arrays.copyOfRange(key, 0, 16), "AES"),
            OpenSSLGMACAesSpi.class);
    }

    private static void testHMAC_SHA1() throws Exception {
        runTest("HMAC[Digest: SHA1]",
            new SecretKeySpec(Arrays.copyOfRange(key, 0, 64), "HMAC"),
            OpenSSLHMACSHA1Spi.class); 
    }

    private static void testHMAC_SHA3_512() throws Exception {
        runTest("HMAC[Digest: SHA3-512]",
            new SecretKeySpec(Arrays.copyOfRange(key, 0, 64), "HMAC"),
            OpenSSLHMACSHA3512Spi.class);
    }

    private static void testKMAC_128() throws Exception {
        runTest("KMAC-128",
            new SecretKeySpec(Arrays.copyOfRange(key, 0, 4), "KMAC-128"),
            OpenSSLKMAC128Spi.class);
    }

    private static void testKMAC_256() throws Exception {
        runTest("KMAC-256",
            new SecretKeySpec(Arrays.copyOfRange(key, 0, 32), "KMAC-256"),
            OpenSSLKMAC256Spi.class);
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
