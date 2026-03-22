package org.openssl.jostle.test.digest;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;

import java.security.MessageDigest;
import java.security.Security;

/**
 * Basic tests for MessageDigest via the Jostle provider.
 */
public class MessageDigestBasicTest
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
    public void testSha256_abc()
            throws Exception
    {
        byte[] msg = "abc".getBytes("UTF-8");
        MessageDigest md = MessageDigest.getInstance("SHA-256", JostleProvider.PROVIDER_NAME);
        byte[] out = md.digest(msg);

        String hex = toHex(out);
        // NIST SHA-256 of "abc"
        Assertions.assertEquals(
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                hex);
        Assertions.assertEquals(32, out.length);
    }

    @Test
    public void testSha384_empty()
            throws Exception
    {
        MessageDigest md = MessageDigest.getInstance("SHA-384", JostleProvider.PROVIDER_NAME);
        byte[] out = md.digest(new byte[0]);

        String hex = toHex(out);
        // NIST SHA-384 of empty string
        Assertions.assertEquals(
                "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da"
                        + "274edebfe76f65fbd51ad2f14898b95b",
                hex);
        Assertions.assertEquals(48, out.length);
    }

    @Test
    public void testSha512_abc()
            throws Exception
    {
        byte[] msg = "abc".getBytes("UTF-8");
        MessageDigest md = MessageDigest.getInstance("SHA-512", JostleProvider.PROVIDER_NAME);
        byte[] out = md.digest(msg);

        String hex = toHex(out);
        // NIST SHA-512 of "abc"
        Assertions.assertEquals(
                "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
                        + "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
                hex);
        Assertions.assertEquals(64, out.length);
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
