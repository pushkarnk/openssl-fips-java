import java.util.Arrays;
import java.security.spec.KeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.InvalidKeyException;
import java.security.Security;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import com.canonical.openssl.provider.OpenSSLFIPSProvider;

public class SecretKeyFactoryApiTest {

    private static void testPBKDF2() throws Exception {
        System.out.print("Testing OpenSSL/PBKDF2: ");
        String password = "Zaq12wsXCde34rfV";
        String salt = "NaClCommonSaltRockSaltSeaSalt";
        int iterationCount = 120000;

        char[] passwordChars = new char[16]; 
        password.getChars(0, 16, passwordChars, 0);
        PBEKeySpec keySpec = new PBEKeySpec(passwordChars, salt.getBytes(), iterationCount);

        SecretKeyFactory pbkdf = SecretKeyFactory.getInstance("PBKDF2", "OpenSSLFIPSProvider");
        SecretKey sk1 = pbkdf.generateSecret(keySpec);
        SecretKey sk2 = pbkdf.translateKey(sk1);
        if (sk1.getEncoded().length != 0 && Arrays.equals(sk1.getEncoded(), sk2.getEncoded())) {
            System.out.println("PASSED");
        } else {
            System.out.println("FAILED");
        }
    }

    public static void main(String[] args) throws Exception {
        Security.addProvider(new OpenSSLFIPSProvider());
        testPBKDF2();
    }
}
