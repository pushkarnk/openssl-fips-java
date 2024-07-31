import com.canonical.openssl.cipher.*;
import javax.crypto.CipherSpi;
import javax.crypto.Cipher;
import java.security.Key;
import java.security.AlgorithmParameters;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import javax.crypto.ShortBufferException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.BadPaddingException;
import javax.crypto.spec.IvParameterSpec;
import java.util.Arrays;
import java.security.spec.AlgorithmParameterSpec;

// TODO: refactoring
// failing CCM tests
class AesCipherTest extends CipherAes {
    public AesCipherTest(String nameKeySizeAndMode, String padding) {
        super(nameKeySizeAndMode, padding);
    }

    @Override
    public String getPadding() { return null; }

    @Override
    public String getMode() { return null; }

    @Override
    public int getKeySize() { return -1; }

    void init(int opmode, Key key, AlgorithmParameterSpec spec, SecureRandom random) {
        super.engineInit(opmode, key, spec, random);
    }

    byte[] update(byte[] input, int inputOffset, int inputLen) {
        return super.engineUpdate(input, inputOffset, inputLen);
    }

    byte[] final0(byte[] input, int inputOffset, int inputLen) throws IllegalBlockSizeException, BadPaddingException {
        return super.engineDoFinal(input, inputOffset, inputLen);
    }

    byte[] getIv() {
        return super.engineGetIV();
    }
}

public class CipherTest {

    static String [] paddings = {
        "NONE",
        "PKCS7" ,
        "PKCS5",
        "ISO10126-2",
        "X9.23",
        "ISO7816-4"
    };

    static String [] ciphers = {
        "AES-128-ECB",
        "AES-256-ECB",
        "AES-192-ECB",
        "AES-128-CBC",
        "AES-256-CBC",
        "AES-128-CFB1",
        "AES-256-CFB1",
        "AES-192-CFB1",
        "AES-128-CFB8",
        "AES-192-CFB8",
        "AES-256-CFB8",
        "AES-128-CTR",
        "AES-192-CTR",
        "AES-256-CTR",
        "AES-128-CCM",
        "AES-256-CCM",
        "AES-192-CCM",
        "AES-128-GCM",
        "AES-192-GCM",
        "AES-256-GCM"
    };
    
    public static void main(String[] args) throws Exception {
        testSingleUpdate();
        testMultipleUpdates();
    }

    private static void testSingleUpdate() throws Exception {
        System.out.print("Test with single encryption updates: ");
        boolean fails = false;
        for (String cipher : ciphers) {
	    // CCM tests currently fail
            // see https://github.com/openssl/openssl/issues/22773
            if (cipher.endsWith("CCM"))
                continue;
            for(String padding : paddings) {
                if (!runTestSingleUpdate(cipher, padding)) {
                    System.out.println(cipher + " " + padding);
                    fails = true;
                }
            }
        }
        if (fails == true) {
            System.out.println("FAILED");
            fails = false;
        } else {
            System.out.println("PASSED");
        }
    }

    private static void testMultipleUpdates() throws Exception {
        System.out.print("Test with multiple encryption updates [skipping CCM tests]: "); 

        boolean fails = false;
        for (String cipher : ciphers) {
            // CCM tests currently fail
            // see https://github.com/openssl/openssl/issues/22773
            if (cipher.endsWith("CCM"))
                continue;
            for(String padding : paddings) {
                if (!runTestMultipleUpdates(cipher, padding)) { 
                    System.out.println(cipher + " " + padding);
                    fails = true;
                }
            }
        }

        if (fails == true) {
            System.out.println("FAILED");
            fails = false; 
        } else {
            System.out.println("PASSED");
        }
    }

    private static boolean runTestMultipleUpdates(String nameKeySizeAndMode, String padding) throws Exception {
        SecureRandom sr = SecureRandom.getInstance("NativePRNG");

        byte[] key;
        String keySize = nameKeySizeAndMode.split("-")[1];
        if (keySize.equals("128")) {
            key = new byte[16];
        } else if (keySize.equals("192")) {
            key = new byte[24];
        } else if (keySize.equals("256")) {
            key = new byte[32];
        } else {
            System.out.println("Key size unsupported");
            return false;
        }

        sr.nextBytes(key);

        byte[] iv = new byte[8];
        sr.nextBytes(iv);

        byte[] input = new byte[16];
        sr.nextBytes(input);

        AlgorithmParameterSpec spec = new IvParameterSpec(iv);
        AesCipherTest cipher = new AesCipherTest(nameKeySizeAndMode, padding);
    
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), spec, sr);

        byte[] fullInput = new byte[32];
        System.arraycopy(input, 0, fullInput, 0, 16);
        System.arraycopy(input, 0, fullInput, 16, 16);

        byte[] fullEnc = new byte[128];
        int encLen = 0;
 
        byte[] enc1 = cipher.update(input, 0, input.length);
        System.arraycopy(enc1, 0, fullEnc, 0, enc1.length);
        encLen += enc1.length;
 
        byte[] enc2 = cipher.final0(input, 0, input.length);
        System.arraycopy(enc2, 0, fullEnc, encLen, enc2.length);
        encLen += enc2.length;

        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), spec, sr);
        byte[] output = cipher.final0(fullEnc, 0, encLen);

        return Arrays.equals(fullInput, output);
    }

    private static boolean runTestSingleUpdate(String nameKeySizeAndMode, String padding) throws Exception {
        SecureRandom sr = SecureRandom.getInstance("NativePRNG");

        byte[] key;
        String keySize = nameKeySizeAndMode.split("-")[1];
        if (keySize.equals("128")) {
            key = new byte[16];
        } else if (keySize.equals("192")) {
            key = new byte[24];
        } else if (keySize.equals("256")) {
            key = new byte[32];
        } else {
            System.out.println("Key size unsupported");
            return false;
        }

        sr.nextBytes(key);

        byte[] iv = new byte[8]; 
        sr.nextBytes(iv);

        AlgorithmParameterSpec spec = new IvParameterSpec(iv); 

        AesCipherTest cipher = new AesCipherTest(nameKeySizeAndMode, padding);
   
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), spec, sr);

        byte[] input = new byte[16];
        sr.nextBytes(input);

        byte[] outFinal = cipher.final0(input, 0, input.length);
    
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), spec, sr);
        byte[] output = cipher.final0(outFinal, 0, outFinal.length);

        return Arrays.equals(input, output);
    }
 
}
        


