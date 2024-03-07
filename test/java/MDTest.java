import java.util.Arrays;
import java.util.function.*;
import java.util.List;

public class MDTest {

    private static byte[] input = """
       From that time on, the world was hers for the reading.
       She would never be lonely again, never miss the lack of intimate friends.
       Books became her friends and there was one for every mood.""".getBytes();

    private static byte[] input1 = """
       From that time on, the world was hers for the reading.
       She would never be lonely again, never miss the lack of intimate friends.
       Books became her friends and there was one for every mood""".getBytes();

    private static BiFunction<OpenSSLMDSpi, byte[], byte[]> macCompute = (md, input) -> {
        md.engineUpdate(input, 0, input.length);
        return md.engineDigest();
    };

    private static void runTest(String name) throws Exception {
        System.out.print("Testing " + name + ": ");
        byte[] output1 = macCompute.apply(new OpenSSLMDSpi(name), input);
        byte[] output2 = macCompute.apply(new OpenSSLMDSpi(name), input);
        byte[] output3 = macCompute.apply(new OpenSSLMDSpi(name), input1);
        if (Arrays.equals(output1, output2) && !Arrays.equals(output2, output3)) {
            System.out.println("PASSED");
        } else {
            System.out.println("FAILED");
        }
    }

    public static void main(String[] args) throws Exception {
        List<String> tests = List.of("SHA1", "SHA224", "SHA256", "SHA384", "SHA512",
                                    "SHA2-224", "SHA2-256", "SHA2-384", "SHA2-512",
                                    "SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512");
        for (var test: tests) {
            runTest(test);
        }
    }
}
