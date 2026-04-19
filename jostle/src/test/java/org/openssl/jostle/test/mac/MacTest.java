package org.openssl.jostle.test.mac;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.openssl.jostle.jcajce.provider.JostleProvider;

import javax.crypto.Mac;
import java.security.InvalidKeyException;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
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
        byte[] key = "supersecretkey".getBytes("UTF-8");
        byte[] msg = "abc".getBytes("UTF-8");

        Mac jo = Mac.getInstance("HmacSHA256", JostleProvider.PROVIDER_NAME);
        jo.init(new SecretKeySpec(key, "HmacSHA256"));

        Mac bc = Mac.getInstance("HmacSHA256", BouncyCastleProvider.PROVIDER_NAME);
        bc.init(new SecretKeySpec(key, "HmacSHA256"));

        Assertions.assertArrayEquals(bc.doFinal(msg), jo.doFinal(msg));
    }

    @Test
    public void testHmacSha512ByteBuffer() throws Exception
    {
        byte[] key = "anothersecretkey".getBytes("UTF-8");
        byte[] msg = "message through bytebuffer".getBytes("UTF-8");

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
        byte[] key = "reset-key".getBytes("UTF-8");
        byte[] msg = "payload".getBytes("UTF-8");

        Mac jo = Mac.getInstance("HmacSHA1", JostleProvider.PROVIDER_NAME);
        jo.init(new SecretKeySpec(key, "HmacSHA1"));
        byte[] first = jo.doFinal(msg);
        byte[] second = jo.doFinal(msg);

        Assertions.assertArrayEquals(first, second);
    }

    @ParameterizedTest
    @MethodSource("newHmacAlgorithms")
    public void testNewHmacAlgorithmsAgreementWithBC(String algorithm) throws Exception
    {
        byte[] key = ("key-" + algorithm).getBytes("UTF-8");
        byte[] msg = ("message-for-" + algorithm).getBytes("UTF-8");

        Mac jo = Mac.getInstance(algorithm, JostleProvider.PROVIDER_NAME);
        jo.init(new SecretKeySpec(key, algorithm));
        jo.update(msg, 0, 3);
        jo.update(msg, 3, msg.length - 3);
        byte[] joOut = jo.doFinal();

        Mac bc = Mac.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME);
        bc.init(new SecretKeySpec(key, algorithm));
        bc.update(msg, 0, 3);
        bc.update(msg, 3, msg.length - 3);
        byte[] bcOut = bc.doFinal();

        Assertions.assertArrayEquals(bcOut, joOut);
    }

    @ParameterizedTest
    @MethodSource("newHmacAlgorithms")
    public void testNewHmacAlgorithmsRejectNullKey(String algorithm) throws Exception
    {
        Mac jo = Mac.getInstance(algorithm, JostleProvider.PROVIDER_NAME);

        InvalidKeyException ex = Assertions.assertThrows(InvalidKeyException.class, () -> jo.init(null));
        Assertions.assertEquals("key is null", ex.getMessage());
    }
}
