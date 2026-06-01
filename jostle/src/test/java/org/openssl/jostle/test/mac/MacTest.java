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


    /**
     * Class-level seeding random — used to derive each test's local
     * SHA1PRNG seed. Per CLAUDE.md: "cache one SecureRandom per test
     * class, not per @Test method."
     */
    private static final SecureRandom RANDOM = new SecureRandom();

    /**
     * Per-test seeded random. The seed is logged on every call so a
     * flaky failure can be reproduced by re-running with the same
     * seed (per CLAUDE.md).
     */
    private static SecureRandom seededRandom(String testName) throws Exception
    {
        long seed = RANDOM.nextLong();
        System.out.println(testName + " seed=" + seed);
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        sr.setSeed(seed);
        return sr;
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
        SecureRandom sr = seededRandom("testHmacSha256AgreementWithBC");
        byte[] key = new byte[33];
        sr.nextBytes(key);

        byte[] msg = new byte[1025];
        sr.nextBytes(msg);

        Mac jo = Mac.getInstance("HmacSHA256", JostleProvider.PROVIDER_NAME);
        jo.init(new SecretKeySpec(key, "HmacSHA256"));

        Mac bc = Mac.getInstance("HmacSHA256", BouncyCastleProvider.PROVIDER_NAME);
        bc.init(new SecretKeySpec(key, "HmacSHA256"));

        Assertions.assertArrayEquals(bc.doFinal(msg), jo.doFinal(msg));
    }

    @Test
    public void testHmacSha512ByteBuffer() throws Exception
    {
        SecureRandom sr = seededRandom("testHmacSha512ByteBuffer");
        byte[] key = new byte[33];
        sr.nextBytes(key);

        byte[] msg = new byte[1025];
        sr.nextBytes(msg);

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
        SecureRandom sr = seededRandom("testHmacReset");
        byte[] key = new byte[32];
        sr.nextBytes(key);

        byte[] msg = new byte[1025];
        sr.nextBytes(msg);

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
        SecureRandom sr = seededRandom("testAgreementWithBC[" + algorithm + "]");
        byte[] key = new byte[32];
        sr.nextBytes(key);
        byte[] msg = new byte[1025];
        sr.nextBytes(msg);

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
        SecureRandom sr = seededRandom("testCMACAgreementWithBC");
        for (int ks:new int[]{16,24,32})
        {
            byte[] key = new byte[ks];
            sr.nextBytes(key);
            byte[] msg = new byte[1025];
            sr.nextBytes(msg);

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
        SecureRandom sr = seededRandom("testAgreementWithBCZeroLenMSG[" + algorithm + "]");
        byte[] key = new byte[32];
        sr.nextBytes(key);
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
        SecureRandom sr = seededRandom("testHmacReInitDifferentKey");
        byte[] key1 = new byte[32];
        byte[] key2 = new byte[64];
        sr.nextBytes(key1);
        sr.nextBytes(key2);
        byte[] msg = new byte[1025];
        sr.nextBytes(msg);

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
        SecureRandom sr = seededRandom("testCMACReInitDifferentKeySize");
        byte[] msg = new byte[1025];
        sr.nextBytes(msg);

        Mac jo = Mac.getInstance("AESCMAC", JostleProvider.PROVIDER_NAME);
        Mac bc = Mac.getInstance("AESCMAC", BouncyCastleProvider.PROVIDER_NAME);

        for (int ks: new int[]{16, 24, 32})
        {
            byte[] key = new byte[ks];
            sr.nextBytes(key);

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
        SecureRandom sr = seededRandom("testExplicitReset");
        byte[] key = new byte[32];
        sr.nextBytes(key);
        byte[] msg = new byte[1025];
        sr.nextBytes(msg);

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
        SecureRandom sr = seededRandom("testHmacDirectByteBuffer");
        byte[] key = new byte[32];
        sr.nextBytes(key);
        byte[] msg = new byte[1025];
        sr.nextBytes(msg);

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
    public void testGetMacLengthPerAlgorithm() throws Exception
    {
        Object[][] expected = new Object[][]{
                {"HmacSHA1", 20},
                {"HmacSHA224", 28},
                {"HmacSHA256", 32},
                {"HmacSHA384", 48},
                {"HmacSHA512", 64},
                {"HmacSHA512/224", 28},
                {"HmacSHA512/256", 32},
                {"HmacSHA3-224", 28},
                {"HmacSHA3-256", 32},
                {"HmacSHA3-384", 48},
                {"HmacSHA3-512", 64},
                {"HmacSM3", 32},
                {"HmacMD5", 16},
                {"HmacMD5SHA1", 36},
                {"HmacRIPEMD160", 20},
                {"AESCMAC", 16},
        };

        for (Object[] row : expected)
        {
            String name = (String) row[0];
            int expectedLen = (Integer) row[1];
            Mac mac = Mac.getInstance(name, JostleProvider.PROVIDER_NAME);
            Assertions.assertEquals(expectedLen, mac.getMacLength(), "mac length for " + name);
        }
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


    // -----------------------------------------------------------------
    // Adversarial-chunking matrix per CLAUDE.md "Vary the chunking, and
    // randomise the inputs". HMAC and CMAC are deterministic, so every
    // chunking pattern through update(...) MUST produce a byte-identical
    // tag. Catches buffering-layer bugs where the partial-block path
    // and the bulk path diverge.
    // -----------------------------------------------------------------

    /**
     * Adversarial chunking matrix for HMAC across all variants. Each
     * chunking strategy must produce the same tag as the one-shot call.
     * Pivots around the SHA-2 / SHA-3 block size (64 and 128 bytes are
     * the most common; the matrix covers both).
     */
    @ParameterizedTest
    @MethodSource("newHmacAlgorithms")
    public void testHmac_ChunkingMatrix_byteIdentical(String algorithm) throws Exception
    {
        SecureRandom sr = seededRandom("testHmac_ChunkingMatrix_byteIdentical[" + algorithm + "]");
        byte[] key = new byte[32];
        sr.nextBytes(key);
        byte[] msg = new byte[1024 + sr.nextInt(256)];
        sr.nextBytes(msg);

        byte[] reference = macWithChunking(algorithm, algorithm, key, msg, msg.length);

        // byte-by-byte
        Assertions.assertArrayEquals(reference,
                macWithChunking(algorithm, algorithm, key, msg, 1),
                algorithm + ": byte-by-byte tag diverged from one-shot");

        // Adversarial offsets around common digest block sizes.
        for (int chunk : new int[]{63, 64, 65, 127, 128, 129})
        {
            Assertions.assertArrayEquals(reference,
                    macWithChunking(algorithm, algorithm, key, msg, chunk),
                    algorithm + ": chunk=" + chunk + " tag diverged from one-shot");
        }

        // Random splits.
        for (int trial = 0; trial < 5; trial++)
        {
            Assertions.assertArrayEquals(reference,
                    macWithRandomSplits(algorithm, algorithm, key, msg, sr),
                    algorithm + ": random-split trial=" + trial + " tag diverged from one-shot");
        }
    }

    /**
     * Adversarial chunking matrix for AES-CMAC across all three key
     * lengths. Pivots around the AES block size (16 bytes). The Mac
     * algorithm name is "AESCMAC" but the SecretKeySpec carries the
     * raw cipher name "AES" — the helper signature reflects that.
     */
    @Test
    public void testCmac_ChunkingMatrix_byteIdentical() throws Exception
    {
        SecureRandom sr = seededRandom("testCmac_ChunkingMatrix_byteIdentical");
        for (int ks : new int[]{16, 24, 32})
        {
            byte[] key = new byte[ks];
            sr.nextBytes(key);
            byte[] msg = new byte[1024 + sr.nextInt(256)];
            sr.nextBytes(msg);

            byte[] reference = macWithChunking("AESCMAC", "AES", key, msg, msg.length);

            Assertions.assertArrayEquals(reference,
                    macWithChunking("AESCMAC", "AES", key, msg, 1),
                    "ks=" + ks + ": byte-by-byte CMAC diverged from one-shot");

            // Adversarial offsets around the AES block size.
            for (int chunk : new int[]{15, 16, 17, 31, 32, 33})
            {
                Assertions.assertArrayEquals(reference,
                        macWithChunking("AESCMAC", "AES", key, msg, chunk),
                        "ks=" + ks + " chunk=" + chunk + ": CMAC diverged from one-shot");
            }

            for (int trial = 0; trial < 5; trial++)
            {
                Assertions.assertArrayEquals(reference,
                        macWithRandomSplits("AESCMAC", "AES", key, msg, sr),
                        "ks=" + ks + " random-split trial=" + trial + ": CMAC diverged from one-shot");
            }
        }
    }

    private static byte[] macWithChunking(String macAlgo, String keyAlgo, byte[] key, byte[] msg, int chunk) throws Exception
    {
        Mac mac = Mac.getInstance(macAlgo, JostleProvider.PROVIDER_NAME);
        mac.init(new SecretKeySpec(key, keyAlgo));
        for (int off = 0; off < msg.length; off += chunk)
        {
            int len = Math.min(chunk, msg.length - off);
            mac.update(msg, off, len);
        }
        return mac.doFinal();
    }

    private static byte[] macWithRandomSplits(String macAlgo, String keyAlgo, byte[] key, byte[] msg, SecureRandom sr) throws Exception
    {
        Mac mac = Mac.getInstance(macAlgo, JostleProvider.PROVIDER_NAME);
        mac.init(new SecretKeySpec(key, keyAlgo));
        int pos = 0;
        while (pos < msg.length)
        {
            int remaining = msg.length - pos;
            int chunk = 1 + sr.nextInt(Math.max(1, remaining));
            chunk = Math.min(chunk, remaining);
            mac.update(msg, pos, chunk);
            pos += chunk;
        }
        return mac.doFinal();
    }
}
