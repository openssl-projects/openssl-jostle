package org.openssl.jostle.test.md;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.Loader;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.util.encoders.Hex;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;

public class MDTest
{

    @BeforeEach
    public void before() throws Exception
    {
        Security.addProvider(new JostleProvider());
        Security.addProvider(new BouncyCastleProvider());
    }


    @Test
    public void testEmptyMD() throws Exception
    {
        Assumptions.assumeFalse(Loader.isFFI(), "JNI"); // TODO remove when FFI interface implemented

        String[][] vectors = new String[][]{

                {"SHA2-224", "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"},
                {"SHA2-256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
                {"SHA2-384", "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"},
                {"SHA2-512", "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"},
                {"SHA2-512/224", "6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4"},
                {"SHA2-512/256", "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a"},
                {"SHA1", "da39a3ee5e6b4b0d3255bfef95601890afd80709"},

                {"SHA3-224", "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"},
                {"SHA3-256", "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"},
                {"SHA3-384", "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"},
                {"SHA3-512", "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"},
                {"SHAKE-128", "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26"},
                {"SHAKE-256", "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be"},

                {"MD5", "d41d8cd98f00b204e9800998ecf8427e"},
                {"MD5-SHA1", "d41d8cd98f00b204e9800998ecf8427eda39a3ee5e6b4b0d3255bfef95601890afd80709"},
                {"SM3", "1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b"},
                {"RIPEMD-160", "9c1185a5c5e9fc54612808977ee8f548b2258d31"},
                {"BLAKE2S-256", "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"},
                {"BLAKE2B-512", "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"}
        };

        for (String[] v : vectors)
        {
            String name = v[0];
            byte[] expected = Hex.decode(v[1]);

            MessageDigest md = MessageDigest.getInstance(name, JostleProvider.PROVIDER_NAME);
            byte[] digest1 = md.digest();
            byte[] digest2 = md.digest(); // taking the digest resets the state

            if (!Arrays.equals(expected, digest1))
            {
                System.out.println(name);
                System.out.println("DIG: " + Hex.toHexString(digest1));
                System.out.println("Exp: " + Hex.toHexString(expected));
            }

            Assertions.assertArrayEquals(Hex.decode(v[1]), digest1, "Digest: " + name);

            Assertions.assertArrayEquals(digest1, digest2, "Digest after auto reset : " + name);
        }

    }

    @Test
    public void testAgreesWithBC() throws Exception
    {
        SecureRandom random = new SecureRandom();
        for (String digest : new String[]{
                "SHA2-224", "SHA2-256", "SHA2-384", "SHA2-512", "SHA2-512/224", "SHA2-512/256", "SHA1",
                "SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512", "SHAKE-128", "SHAKE-256", "MD5",
                "SM3", "RIPEMD-160", "BLAKE2S-256", "BLAKE2B-512"}) // Skipping "MD5-SHA1"
        {

            String bcName = digest;
            if (bcName.startsWith("SHA2-"))
            {
                bcName = bcName.replace("SHA2-", "SHA-");
            } else if (bcName.startsWith("SHAKE"))
            {
                bcName = bcName.replace("SHAKE-", "SHAKE");
            } else if (bcName.startsWith("RIPEMD-"))
            {
                bcName = bcName.replace("RIPEMD-", "RIPEMD");
            }

            MessageDigest joDigest = MessageDigest.getInstance(digest, JostleProvider.PROVIDER_NAME);
            MessageDigest joSplitDigest = MessageDigest.getInstance(digest, JostleProvider.PROVIDER_NAME);
            MessageDigest bcDigest = MessageDigest.getInstance(bcName, BouncyCastleProvider.PROVIDER_NAME);

            int fillCtr = 0;

            byte[] buf = new byte[1024];
            for (int t = 0; t < 50000; t++)
            {
                int sizeOfUpdate = random.nextInt(buf.length);

                for (int i = 0; i < sizeOfUpdate; i++)
                {
                    buf[i] = (byte) fillCtr++;
                }

                joDigest.update(buf, 0, sizeOfUpdate);
                bcDigest.update(buf, 0, sizeOfUpdate);


                //
                // Split update between bulk update and single byte update
                //
                if (sizeOfUpdate > 0)
                {
                    int split = random.nextInt(sizeOfUpdate);
                    int p = 0;
                    for (; p < split; p++)
                    {
                        joSplitDigest.update(buf[p]);
                    }
                    joSplitDigest.update(buf, p, sizeOfUpdate - p);
                } else
                {
                    joSplitDigest.update(buf, 0, sizeOfUpdate);
                }
            }

            byte[] expectedFromBC = bcDigest.digest();

            Assertions.assertArrayEquals(expectedFromBC, joDigest.digest(), "Bulk Update: " + digest);
            Assertions.assertArrayEquals(expectedFromBC, joSplitDigest.digest(), "Mixed Bytewise/Bulk Update" + digest);

        }
    }

    @Test
    public void testUseAfterTakingDigest() throws Exception
    {

        MessageDigest bcDigest = MessageDigest.getInstance("SHA-256", BouncyCastleProvider.PROVIDER_NAME);
        bcDigest.update("Hello".getBytes());
        byte[] bcDigest1 = bcDigest.digest(); // resets
        byte[] bcDigest2 = bcDigest.digest(); // takes empty digest

        MessageDigest joDigest = MessageDigest.getInstance("SHA-256", JostleProvider.PROVIDER_NAME);
        joDigest.update("Hello".getBytes());
        byte[] joDigest1 = joDigest.digest();
        byte[] joDigest2 = joDigest.digest();


        Assertions.assertArrayEquals(bcDigest1, joDigest1);
        Assertions.assertArrayEquals(bcDigest2, joDigest2);

    }


//    @Test
//    public void testDigestMethods() throws Exception
//    {
//
//        MessageDigest bcDigest = MessageDigest.getInstance("SHA-256", BouncyCastleProvider.PROVIDER_NAME);
//        bcDigest.update("Hello".getBytes());
//        byte[] expected = bcDigest.digest();
//
//
//    }


}
