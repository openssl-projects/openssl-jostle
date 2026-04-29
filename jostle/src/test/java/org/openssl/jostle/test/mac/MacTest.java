package org.openssl.jostle.test.mac;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.util.Arrays;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.stream.Stream;

public class MacTest
{
    private static Stream<String> newHmacAlgorithms()
    {
        // HmacMD5SHA1 is registered in ProvMac (legacy TLS-PRF combined hash) but
        // BouncyCastle does not expose a JCE Mac under this name, so it cannot be
        // included in agreement-with-BC parameterised tests.
        return Stream.of(
                "HmacSHA224",
                "HmacSHA384",
                "HmacSHA512/224",
                "HmacSHA512/256",
                "HmacSHA3-224",
                "HmacSHA3-256",
                "HmacSHA3-384",
                "HmacSHA3-512",
                "HmacMD5",
                "HmacRIPEMD160",
                "HmacSM3"

        );
    }


    private static final SecureRandom secureRandom = new SecureRandom();

    @BeforeAll
    static void before()
    {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    @Test
    public void testHmacSha256AgreementWithBC() throws Exception
    {
        byte[] key = new byte[33];
        secureRandom.nextBytes(key);

        byte[] msg = new byte[1025];
        secureRandom.nextBytes(msg);

        Mac jo = Mac.getInstance("HmacSHA256", JostleProvider.PROVIDER_NAME);
        jo.init(new SecretKeySpec(key, "HmacSHA256"));

        Mac bc = Mac.getInstance("HmacSHA256", BouncyCastleProvider.PROVIDER_NAME);
        bc.init(new SecretKeySpec(key, "HmacSHA256"));

        Assertions.assertArrayEquals(bc.doFinal(msg), jo.doFinal(msg));
    }

    @Test
    public void testHmacSha512ByteBuffer() throws Exception
    {
        byte[] key = new byte[33];
        secureRandom.nextBytes(key);

        byte[] msg = new byte[1025];
        secureRandom.nextBytes(msg);

        Mac jo = Mac.getInstance("HmacSHA512", JostleProvider.PROVIDER_NAME);
        jo.init(new SecretKeySpec(key, "HmacSHA512"));
        jo.update(ByteBuffer.wrap(msg));
        byte[] joOut = jo.doFinal();

        Mac bc = Mac.getInstance("HmacSHA512", BouncyCastleProvider.PROVIDER_NAME);
        bc.init(new SecretKeySpec(key, "HmacSHA512"));
        byte[] bcOut = bc.doFinal(msg);

        Assertions.assertArrayEquals(bcOut, joOut);
    }

    @Test
    public void testHmacReset() throws Exception
    {
        byte[] key = new byte[32];
        secureRandom.nextBytes(key);

        byte[] msg = new byte[1025];
        secureRandom.nextBytes(msg);

        //
        // Basic reuse, outputs should be the same
        //
        Mac jo = Mac.getInstance("HmacSHA1", JostleProvider.PROVIDER_NAME);
        jo.init(new SecretKeySpec(key, "HmacSHA1"));
        byte[] first = jo.doFinal(msg);

        // Update with empty final
        jo.update(msg);
        byte[] second = jo.doFinal();
        Assertions.assertArrayEquals(first, second);

        //
        // Reset after use yields different MAC with no update
        //

        jo.update(msg);
        first = jo.doFinal();
        second = jo.doFinal();
        Assertions.assertFalse(Arrays.areEqual(second, first));

    }

    @ParameterizedTest
    @MethodSource("newHmacAlgorithms")
    public void testAgreementWithBC(String algorithm) throws Exception
    {
        byte[] key = new byte[32];
        secureRandom.nextBytes(key);
        byte[] msg = new byte[1025];
        secureRandom.nextBytes(msg);

        Mac jo = Mac.getInstance(algorithm, JostleProvider.PROVIDER_NAME);
        jo.init(new SecretKeySpec(key, algorithm));
        jo.update(msg[0]);
        jo.update(msg[1]);
        jo.update(msg, 2, 3);
        jo.update(msg, 5, msg.length - 5);
        byte[] joOut = jo.doFinal();


        Mac bc = Mac.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME);
        bc.init(new SecretKeySpec(key, algorithm));
        bc.update(msg, 0, msg.length);
        byte[] bcOut = bc.doFinal();

        Assertions.assertArrayEquals(bcOut, joOut);
    }


    @Test
    public void testCMACAgreementWithBC() throws Exception
    {

        for (int ks:new int[]{16,24,32})
        {
            byte[] key = new byte[ks];
            secureRandom.nextBytes(key);
            byte[] msg = new byte[1025];
            secureRandom.nextBytes(msg);

            Mac jo = Mac.getInstance("AESCMAC", JostleProvider.PROVIDER_NAME);
            jo.init(new SecretKeySpec(key, "AES"));
            jo.update(msg[0]);
            jo.update(msg[1]);
            jo.update(msg, 2, 3);
            jo.update(msg, 5, msg.length - 5);
            byte[] joOut = jo.doFinal();


            Mac bc = Mac.getInstance("AESCMAC", BouncyCastleProvider.PROVIDER_NAME);
            bc.init(new SecretKeySpec(key, "AES"));
            bc.update(msg, 0, msg.length);
            byte[] bcOut = bc.doFinal();

            Assertions.assertArrayEquals(bcOut, joOut);

        }
    }





    @ParameterizedTest
    @MethodSource("newHmacAlgorithms")
    public void testAgreementWithBCZeroLenMSG(String algorithm) throws Exception
    {

        byte[] key = new byte[32];
        secureRandom.nextBytes(key);
        byte[] msg = new byte[0];


        Mac jo = Mac.getInstance(algorithm, JostleProvider.PROVIDER_NAME);
        jo.init(new SecretKeySpec(key, algorithm));
        jo.update(msg, 0, 0);
        byte[] joOut = jo.doFinal();

        Mac bc = Mac.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME);
        bc.init(new SecretKeySpec(key, algorithm));
        bc.update(msg, 0, 0);
        byte[] bcOut = bc.doFinal();

        Assertions.assertArrayEquals(bcOut, joOut);
    }

    @ParameterizedTest
    @MethodSource("newHmacAlgorithms")
    public void testRejectNullKey(String algorithm) throws Exception
    {
        Mac jo = Mac.getInstance(algorithm, JostleProvider.PROVIDER_NAME);
        InvalidKeyException ex = Assertions.assertThrows(InvalidKeyException.class, () -> jo.init(null));
        Assertions.assertEquals("key is null", ex.getMessage());
    }


    @Test
    public void testHmacReInitDifferentKey() throws Exception
    {
        byte[] key1 = new byte[32];
        byte[] key2 = new byte[64];
        secureRandom.nextBytes(key1);
        secureRandom.nextBytes(key2);
        byte[] msg = new byte[1025];
        secureRandom.nextBytes(msg);

        Mac jo = Mac.getInstance("HmacSHA256", JostleProvider.PROVIDER_NAME);
        jo.init(new SecretKeySpec(key1, "HmacSHA256"));
        byte[] m1 = jo.doFinal(msg);

        jo.init(new SecretKeySpec(key2, "HmacSHA256"));
        byte[] m2 = jo.doFinal(msg);

        Assertions.assertFalse(Arrays.areEqual(m1, m2));

        Mac bc = Mac.getInstance("HmacSHA256", BouncyCastleProvider.PROVIDER_NAME);
        bc.init(new SecretKeySpec(key1, "HmacSHA256"));
        Assertions.assertArrayEquals(bc.doFinal(msg), m1);
        bc.init(new SecretKeySpec(key2, "HmacSHA256"));
        Assertions.assertArrayEquals(bc.doFinal(msg), m2);
    }


    @Test
    public void testCMACReInitDifferentKeySize() throws Exception
    {
        byte[] msg = new byte[1025];
        secureRandom.nextBytes(msg);

        Mac jo = Mac.getInstance("AESCMAC", JostleProvider.PROVIDER_NAME);
        Mac bc = Mac.getInstance("AESCMAC", BouncyCastleProvider.PROVIDER_NAME);

        for (int ks: new int[]{16, 24, 32})
        {
            byte[] key = new byte[ks];
            secureRandom.nextBytes(key);

            jo.init(new SecretKeySpec(key, "AES"));
            byte[] joOut = jo.doFinal(msg);

            bc.init(new SecretKeySpec(key, "AES"));
            byte[] bcOut = bc.doFinal(msg);

            Assertions.assertArrayEquals(bcOut, joOut, "key size " + ks);
        }
    }


    @Test
    public void testExplicitReset() throws Exception
    {
        byte[] key = new byte[32];
        secureRandom.nextBytes(key);
        byte[] msg = new byte[1025];
        secureRandom.nextBytes(msg);

        Mac jo = Mac.getInstance("HmacSHA256", JostleProvider.PROVIDER_NAME);
        jo.init(new SecretKeySpec(key, "HmacSHA256"));

        // accumulate then explicitly reset, then compute MAC of msg
        jo.update(msg);
        jo.reset();
        byte[] afterReset = jo.doFinal(msg);

        Mac fresh = Mac.getInstance("HmacSHA256", JostleProvider.PROVIDER_NAME);
        fresh.init(new SecretKeySpec(key, "HmacSHA256"));
        Assertions.assertArrayEquals(fresh.doFinal(msg), afterReset);
    }


    @Test
    public void testHmacDirectByteBuffer() throws Exception
    {
        byte[] key = new byte[32];
        secureRandom.nextBytes(key);
        byte[] msg = new byte[1025];
        secureRandom.nextBytes(msg);

        Mac jo = Mac.getInstance("HmacSHA256", JostleProvider.PROVIDER_NAME);
        jo.init(new SecretKeySpec(key, "HmacSHA256"));

        ByteBuffer direct = ByteBuffer.allocateDirect(msg.length);
        direct.put(msg).flip();
        jo.update(direct);
        byte[] joOut = jo.doFinal();

        Mac bc = Mac.getInstance("HmacSHA256", BouncyCastleProvider.PROVIDER_NAME);
        bc.init(new SecretKeySpec(key, "HmacSHA256"));
        byte[] bcOut = bc.doFinal(msg);

        Assertions.assertArrayEquals(bcOut, joOut);
    }


    @Test
    public void testUnknownAlgorithm()
    {
        Assertions.assertThrows(NoSuchAlgorithmException.class,
                () -> Mac.getInstance("HmacUNKNOWN_FOOBAR", JostleProvider.PROVIDER_NAME));
    }


    @Test
    public void testHmacMD5SHA1KnownVector() throws Exception
    {
        // BouncyCastle does not expose HMAC over MD5-SHA1 via the JCE Mac interface,
        // so we anchor against an OpenSSL-CLI-computed vector instead. Vector generated with:
        //   echo -n "abc" | openssl mac -macopt hexkey:6b6579 -digest md5-sha1 HMAC
        // Output is 36 bytes (MD5 16 + SHA1 20). MD5-SHA1 is the legacy TLS 1.0 PRF
        // combined hash; HMAC over it is the proper HMAC of the combined digest, not a
        // concatenation of HMAC-MD5 || HMAC-SHA1.
        byte[] key = "key".getBytes(StandardCharsets.UTF_8);
        byte[] msg = "abc".getBytes(StandardCharsets.UTF_8);
        byte[] expected = Hex.decode("a76e5cc4bdaa99b87cc7de69e0606e7d74fd2771909f120bb3b9a4649bb99bea2b4cec32");

        Mac jo = Mac.getInstance("HmacMD5SHA1", JostleProvider.PROVIDER_NAME);
        jo.init(new SecretKeySpec(key, "HmacMD5SHA1"));
        byte[] actual = jo.doFinal(msg);

        Assertions.assertEquals(36, actual.length);
        Assertions.assertArrayEquals(expected, actual);
    }
}
