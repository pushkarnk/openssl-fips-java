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
import com.canonical.openssl.kdf.*;
import java.util.Arrays;
import java.security.spec.KeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.InvalidKeyException;
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

        TestOpenSSLPBKDF2 pbkdf = new TestOpenSSLPBKDF2();
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

class TestOpenSSLPBKDF2 extends OpenSSLPBKDF2 {
    public SecretKey engineGenerateSecret(KeySpec keyspec) throws InvalidKeySpecException {
        return super.engineGenerateSecret(keyspec);
    }

    public KeySpec engineGetKeySpec(SecretKey key, Class<?> keyspec) throws InvalidKeySpecException {
        return super.engineGetKeySpec(key, keyspec);
    }

    public SecretKey engineTranslateKey(SecretKey key) throws InvalidKeyException {
        return super.engineTranslateKey(key);
    }
}
