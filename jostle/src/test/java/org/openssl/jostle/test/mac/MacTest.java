package org.openssl.jostle.test.mac;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
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
import java.security.InvalidKeyException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.stream.Stream;

public class MacTest
{
    private static Stream<String> newHmacAlgorithms()
    {
        return Stream.of(
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
}
