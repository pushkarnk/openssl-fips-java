import java.util.Arrays;
import java.security.spec.KeySpec;
import javax.crypto.SecretKey;
import javax.crypto.spec.PBEKeySpec;

public class PBKDFTest {

    private static void testPBKDF2() throws Exception {
        System.out.print("Testing OpenSSL/PBKDF2: ");
        String password = "Zaq12wsXCde34rfV";
        String salt = "NaClCommonSaltRockSaltSeaSalt";
        int iterationCount = 120000;

        char[] passwordChars = new char[16]; 
        password.getChars(0, 16, passwordChars, 0);
        PBEKeySpec keySpec = new PBEKeySpec(passwordChars, salt.getBytes(), iterationCount);

        OpenSSLPBKDF2Spi pbkdf = new OpenSSLPBKDF2Spi();
        SecretKey sk1 = pbkdf.engineGenerateSecret(keySpec);
        SecretKey sk2 = pbkdf.engineTranslateKey(sk1);
        if (sk1.getEncoded().length != 0 && Arrays.equals(sk1.getEncoded(), sk2.getEncoded())) {
            System.out.println("PASSED");
        } else {
            System.out.println("FAILED");
        }
    }

    public static void main(String[] args) throws Exception {
        testPBKDF2();
    }
}

