package org.openssl.jostle.test.digest;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;

import java.security.MessageDigest;
import java.security.Security;

public class MessageDigestMD5Test
{
    @BeforeAll
    static void setup()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    @Test
    public void testMD5_empty_and_abc() throws Exception
    {
        MessageDigest md = MessageDigest.getInstance("MD5", JostleProvider.PROVIDER_NAME);
        byte[] outEmpty = md.digest(new byte[0]);
        Assertions.assertEquals(
                "d41d8cd98f00b204e9800998ecf8427e",
                toHex(outEmpty));
        Assertions.assertEquals(16, outEmpty.length);

        md.reset();
        byte[] outAbc = md.digest("abc".getBytes("UTF-8"));
        Assertions.assertEquals(
                "900150983cd24fb0d6963f7d28e17f72",
                toHex(outAbc));
        Assertions.assertEquals(16, outAbc.length);
    }

    @Test
    public void testMD5_incremental_vs_oneshot() throws Exception
    {
        byte[] msg = "The quick brown fox jumps over the lazy dog".getBytes("UTF-8");

        MessageDigest one = MessageDigest.getInstance("MD5", JostleProvider.PROVIDER_NAME);
        byte[] oneShot = one.digest(msg);

        MessageDigest inc = MessageDigest.getInstance("MD5", JostleProvider.PROVIDER_NAME);
        for (byte b : msg)
        {
            inc.update(b);
        }
        byte[] incShot = inc.digest();

        Assertions.assertArrayEquals(oneShot, incShot);
    }

    private static String toHex(byte[] data)
    {
        StringBuilder sb = new StringBuilder(data.length * 2);
        for (byte b : data)
        {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
