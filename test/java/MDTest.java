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
import java.nio.ByteBuffer;
import java.security.DigestException;
import java.util.Arrays;
import java.util.function.*;
import java.util.List;
import com.canonical.openssl.md.OpenSSLMD;

public class MDTest {

    private static byte[] input = """
       From that time on, the world was hers for the reading.
       She would never be lonely again, never miss the lack of intimate friends.
       Books became her friends and there was one for every mood.""".getBytes();

    private static byte[] input1 = """
       From that time on, the world was hers for the reading.
       She would never be lonely again, never miss the lack of intimate friends.
       Books became her friends and there was one for every mood""".getBytes();

    private static BiFunction<TestOpenSSLMD, byte[], byte[]> macCompute = (md, input) -> {
        md.engineUpdate(input, 0, input.length);
        return md.engineDigest();
    };

    private static void runTest(Class <? extends TestOpenSSLMD> mdClass) throws Exception {
        
        System.out.print("Testing " + ((OpenSSLMD)(mdClass.newInstance())).getMDName() + ": ");
        byte[] output1 = macCompute.apply(mdClass.newInstance(), input);
        byte[] output2 = macCompute.apply(mdClass.newInstance(), input);
        byte[] output3 = macCompute.apply(mdClass.newInstance(), input1);
        if (Arrays.equals(output1, output2) && !Arrays.equals(output2, output3)) {
            System.out.println("PASSED");
        } else {
            System.out.println("FAILED");
        }
    }

    public static void main(String[] args) throws Exception {
        List<Class<? extends TestOpenSSLMD>> tests = List.of(TestMDSHA1.class, TestMDSHA224.class,
                                                        TestMDSHA3_384.class, TestMDSHA3_512.class);
        for (var test: tests) {
            runTest(test);
        }
    }
}

abstract class TestOpenSSLMD extends OpenSSLMD {

    public TestOpenSSLMD(String name) {
        super(name);
    } 

    @Override
    public byte[] engineDigest() {
        return super.engineDigest();
    }

    @Override
    public int engineDigest(byte[] buf, int offset, int len) throws DigestException {
        return super.engineDigest(buf, offset, len);
    }

    abstract protected int engineGetDigestLength();

    @Override
    public void engineReset() {
        super.engineReset();
    } 

    @Override
    public void engineUpdate(byte input) {
        super.engineUpdate(input);
    }
    
    @Override
    public void engineUpdate(byte[] input, int offset, int len) {
        super.engineUpdate(input, offset, len);
    }

    @Override
    public void engineUpdate(ByteBuffer data) {
        super.engineUpdate(data);
    }
}

class TestMDSHA1 extends TestOpenSSLMD {
    public TestMDSHA1() {
        super("SHA-1");
    }

    @Override
    public int engineGetDigestLength() {
        return 20;
    }
}

class TestMDSHA224 extends TestOpenSSLMD {
    public TestMDSHA224() {
        super("SHA-224");
    }

    @Override
    public int engineGetDigestLength() {
        return 28;
    }
}

class TestMDSHA3_384 extends TestOpenSSLMD {
    public TestMDSHA3_384() {
        super("SHA3-384");
    }

    @Override
    public int engineGetDigestLength() {
        return 48;
    }
}

class TestMDSHA3_512 extends TestOpenSSLMD {
    public TestMDSHA3_512() {
        super("SHA3-512");
    }

    @Override
    protected int engineGetDigestLength() {
        return 64;
    }
}

