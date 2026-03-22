package org.openssl.jostle.test.digest;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;

import java.security.MessageDigest;
import java.security.Security;

public class MessageDigestSHA3Test
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
    public void testSHA3_224_empty_and_abc() throws Exception
    {
        MessageDigest md = MessageDigest.getInstance("SHA3-224", JostleProvider.PROVIDER_NAME);
        byte[] outEmpty = md.digest(new byte[0]);
        Assertions.assertEquals(
                "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7",
                toHex(outEmpty));
        Assertions.assertEquals(28, outEmpty.length);

        md.reset();
        byte[] outAbc = md.digest("abc".getBytes("UTF-8"));
        Assertions.assertEquals(
                "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf",
                toHex(outAbc));
        Assertions.assertEquals(28, outAbc.length);
    }

    @Test
    public void testSHA3_256_empty_and_abc() throws Exception
    {
        MessageDigest md = MessageDigest.getInstance("SHA3-256", JostleProvider.PROVIDER_NAME);
        byte[] outEmpty = md.digest(new byte[0]);
        Assertions.assertEquals(
                "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
                toHex(outEmpty));
        Assertions.assertEquals(32, outEmpty.length);

        md.reset();
        byte[] outAbc = md.digest("abc".getBytes("UTF-8"));
        Assertions.assertEquals(
                "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
                toHex(outAbc));
        Assertions.assertEquals(32, outAbc.length);
    }

    @Test
    public void testSHA3_384_empty_and_abc() throws Exception
    {
        MessageDigest md = MessageDigest.getInstance("SHA3-384", JostleProvider.PROVIDER_NAME);
        byte[] outEmpty = md.digest(new byte[0]);
        Assertions.assertEquals(
                "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2a"
                        + "c3713831264adb47fb6bd1e058d5f004",
                toHex(outEmpty));
        Assertions.assertEquals(48, outEmpty.length);

        md.reset();
        byte[] outAbc = md.digest("abc".getBytes("UTF-8"));
        Assertions.assertEquals(
                "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b2"
                        + "98d88cea927ac7f539f1edf228376d25",
                toHex(outAbc));
        Assertions.assertEquals(48, outAbc.length);
    }

    @Test
    public void testSHA3_512_empty_and_abc() throws Exception
    {
        MessageDigest md = MessageDigest.getInstance("SHA3-512", JostleProvider.PROVIDER_NAME);
        byte[] outEmpty = md.digest(new byte[0]);
        Assertions.assertEquals(
                "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6"
                        + "15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26",
                toHex(outEmpty));
        Assertions.assertEquals(64, outEmpty.length);

        md.reset();
        byte[] outAbc = md.digest("abc".getBytes("UTF-8"));
        Assertions.assertEquals(
                "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e"
                        + "10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0",
                toHex(outAbc));
        Assertions.assertEquals(64, outAbc.length);
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
