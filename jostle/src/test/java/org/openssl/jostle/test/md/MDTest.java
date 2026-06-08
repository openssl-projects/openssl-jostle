/*
 *
 *   Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *   Licensed under the Apache License 2.0 (the "License"). You may not use
 *   this file except in compliance with the License.  You can obtain a copy
 *   in the file LICENSE in the source distribution or at
 *   https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.test.md;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.util.Arrays;
import org.openssl.jostle.util.encoders.Hex;

import java.nio.ByteBuffer;
import java.security.DigestException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;


public class MDTest
{
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
    public static void before() throws Exception
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }


    @Test
    public void testEmptyMD() throws Exception
    {

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

            if (!Arrays.areEqual(expected, digest1))
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
    public void testAgreeWithBCSlidingWindow() throws Exception
    {
        //
        // MD5-SHA1 is not supported by BC so it is skipped here
        //

        SecureRandom sr = seededRandom("testAgreeWithBCSlidingWindow");

        for (String digest : new String[]{
                "SHA2-224", "SHA2-256", "SHA2-384", "SHA2-512", "SHA2-512/224", "SHA2-512/256", "SHA1",
                "SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512", "SHAKE-128", "SHAKE-256", "MD5",
                "SM3", "RIPEMD-160", "BLAKE2S-256", "BLAKE2B-512"}) // Skipping "MD5-SHA1"
        {
            String bcName = digest;
            if (bcName.startsWith("SHA2-"))
            {
                bcName = bcName.replace("SHA2-", "SHA-");
            }
            else
            {
                if (bcName.startsWith("SHAKE"))
                {
                    bcName = bcName.replace("SHAKE-", "SHAKE");
                }
                else
                {
                    if (bcName.startsWith("RIPEMD-"))
                    {
                        bcName = bcName.replace("RIPEMD-", "RIPEMD");
                    }
                }
            }
            // Test over the same array

            byte[] joBuf = new byte[1024 * 4];
            sr.nextBytes(joBuf);

            byte[] bcBuf = Arrays.clone(joBuf);

            MessageDigest joDigest = MessageDigest.getInstance(digest, JostleProvider.PROVIDER_NAME);
            MessageDigest bcDigest = MessageDigest.getInstance(bcName, BouncyCastleProvider.PROVIDER_NAME);

            int joLen = joDigest.getDigestLength();
            int bcLen = bcDigest.getDigestLength();


            for (int t = 0; t < joBuf.length; t++)
            {
                joDigest.update(joBuf, t, joBuf.length - t);
                bcDigest.update(bcBuf, t, bcBuf.length - t);

                joDigest.digest(joBuf, Math.min(t, joBuf.length - joLen), bcLen);
                bcDigest.digest(bcBuf, Math.min(t, bcBuf.length - bcLen), bcLen);

                Assertions.assertArrayEquals(joBuf, bcBuf, "t: " + t + " " + digest);
            }

        }

    }


    @Test
    public void testAgreesWithBC() throws Exception
    {

        //
        // MD5-SHA1 is not supported by BC so it is skipped here
        //

        SecureRandom sr = seededRandom("testAgreesWithBC");
        for (String digest : new String[]{
                "SHA2-224", "SHA2-256", "SHA2-384", "SHA2-512", "SHA2-512/224", "SHA2-512/256", "SHA1",
                "SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512", "SHAKE-128", "SHAKE-256", "MD5",
                "SM3", "RIPEMD-160", "BLAKE2S-256", "BLAKE2B-512"}) // Skipping "MD5-SHA1"
        {

            String bcName = digest;
            if (bcName.startsWith("SHA2-"))
            {
                bcName = bcName.replace("SHA2-", "SHA-");
            }
            else
            {
                if (bcName.startsWith("SHAKE"))
                {
                    bcName = bcName.replace("SHAKE-", "SHAKE");
                }
                else
                {
                    if (bcName.startsWith("RIPEMD-"))
                    {
                        bcName = bcName.replace("RIPEMD-", "RIPEMD");
                    }
                }
            }

            MessageDigest joDigest = MessageDigest.getInstance(digest, JostleProvider.PROVIDER_NAME);
            MessageDigest joSplitDigest = MessageDigest.getInstance(digest, JostleProvider.PROVIDER_NAME);
            MessageDigest bcDigest = MessageDigest.getInstance(bcName, BouncyCastleProvider.PROVIDER_NAME);

            int fillCtr = 0;
            int len = 1 + (1024 * 4);

            for (int t = 0; t < len; t++)
            {
                byte[] buf = new byte[len];
                int sizeOfUpdate = t >> 1;

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
                    int split = sr.nextInt(sizeOfUpdate);
                    int p = 0;
                    for (; p < split; p++)
                    {
                        joSplitDigest.update(buf[p]);
                    }
                    joSplitDigest.update(buf, p, sizeOfUpdate - p);
                }
                else
                {
                    joSplitDigest.update(buf, 0, sizeOfUpdate);
                }
            }

            byte[] expectedFromBC = bcDigest.digest();

            Assertions.assertArrayEquals(expectedFromBC, joDigest.digest(), "Bulk Update: " + digest);
            Assertions.assertArrayEquals(expectedFromBC, joSplitDigest.digest(), "Mixed Bytewise/Bulk Update" + digest);

        }
    }

    //
    // Pin the JCA contract: an output buffer that's too small for the digest
    // result must surface as DigestException, not IllegalArgumentException.
    // Sun providers throw DigestException for this, and callers expect to
    // catch it via the declared `throws` on MessageDigest.digest(byte[],int,int).
    //
    @Test
    public void testDigestException_outputBufferTooSmall() throws Exception
    {
        MessageDigest md = MessageDigest.getInstance("SHA-256", JostleProvider.PROVIDER_NAME);
        md.update("hello".getBytes());

        byte[] tooSmall = new byte[16]; // SHA-256 needs 32

        try
        {
            md.digest(tooSmall, 0, tooSmall.length);
            Assertions.fail("expected DigestException for under-sized output buffer");
        }
        catch (DigestException e)
        {
            // expected
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

        Assertions.assertArrayEquals(joDigest2, Hex.decode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));

    }


    //
    // Alias / OID registrations: every spelling registered in ProvMD should
    // resolve to the same algorithm, observable as the same digest of the
    // same input. Catches table-registration regressions.
    //
    @Test
    public void testAliasesResolveSameAlgorithm() throws Exception
    {
        byte[] msg = "Hello".getBytes();

        // For SHA-256, pin a known hex literal AND verify each alias matches
        // it. For other groups, use the first alias as the reference and
        // assert each subsequent alias produces the same digest.
        byte[] expectedSha256 = Hex.decode("185f8db32271fe25f561a6fc938b2e264306ec304eda518007d1764826381969");
        for (String alias : new String[]{"SHA2-256", "SHA-256", "SHA256", "2.16.840.1.101.3.4.2.1"})
        {
            MessageDigest md = MessageDigest.getInstance(alias, JostleProvider.PROVIDER_NAME);
            md.update(msg);
            Assertions.assertArrayEquals(expectedSha256, md.digest(), "alias " + alias);
        }

        assertAliasesAgree(msg, "MD5", "SSL3-MD5", "1.2.840.113549.2.5");
        assertAliasesAgree(msg, "SHA1", "SHA-1", "SSL3-SHA1", "1.3.14.3.2.26");
        assertAliasesAgree(msg, "SHA2-512", "SHA-512", "SHA512", "2.16.840.1.101.3.4.2.3");
        assertAliasesAgree(msg, "SHAKE-128", "SHAKE128");
        assertAliasesAgree(msg, "SHAKE-256", "SHAKE256");
        assertAliasesAgree(msg, "BLAKE2B-512", "BLAKE2b512", "1.3.6.1.4.1.1722.12.2.1.16");
        assertAliasesAgree(msg, "BLAKE2S-256", "BLAKE2s256", "1.3.6.1.4.1.1722.12.2.2.8");
        assertAliasesAgree(msg, "RIPEMD-160", "RIPEMD160", "RIPEMD", "RMD160", "1.3.36.3.2.1");
    }

    private static void assertAliasesAgree(byte[] msg, String... aliases) throws Exception
    {
        if (aliases.length < 2)
        {
            return;
        }
        MessageDigest first = MessageDigest.getInstance(aliases[0], JostleProvider.PROVIDER_NAME);
        first.update(msg);
        byte[] reference = first.digest();
        for (int i = 1; i < aliases.length; i++)
        {
            MessageDigest md = MessageDigest.getInstance(aliases[i], JostleProvider.PROVIDER_NAME);
            md.update(msg);
            Assertions.assertArrayEquals(reference, md.digest(),
                    "alias " + aliases[i] + " disagrees with " + aliases[0]);
        }
    }


    //
    // Asking for an unknown algorithm must produce NoSuchAlgorithmException,
    // not e.g. an internal IllegalStateException leaking from the provider.
    //
    @Test
    public void testGetInstance_unknownAlgorithm() throws Exception
    {
        try
        {
            MessageDigest.getInstance("SHA-99", JostleProvider.PROVIDER_NAME);
            Assertions.fail("expected NoSuchAlgorithmException");
        }
        catch (NoSuchAlgorithmException e)
        {
            // expected
        }
    }


    //
    // Explicit reset() mid-stream must discard accumulated state. The
    // reset-after-digest behaviour is tested elsewhere; this pins the
    // standalone reset() contract that is otherwise easy to break silently.
    //
    @Test
    public void testExplicitResetMidStream() throws Exception
    {
        MessageDigest md = MessageDigest.getInstance("SHA-256", JostleProvider.PROVIDER_NAME);

        md.update("discard-me".getBytes());
        md.reset();
        md.update("Hello".getBytes());
        byte[] afterReset = md.digest();

        // Same as a fresh ctx digesting "Hello"
        MessageDigest fresh = MessageDigest.getInstance("SHA-256", JostleProvider.PROVIDER_NAME);
        fresh.update("Hello".getBytes());
        Assertions.assertArrayEquals(fresh.digest(), afterReset);
    }


    //
    // MessageDigest.clone() snapshots the running digest via EVP_MD_CTX_copy_ex
    // (gap #3 — required by TLS, which clones the transcript hash). The clone
    // must carry the absorbed-so-far state AND be fully independent of the
    // original: feeding different bytes to each after the split must produce
    // exactly the digests of the respective full inputs.
    //
    @Test
    public void testClone_snapshotAndIndependence() throws Exception
    {
        SecureRandom sr = seededRandom("testClone_snapshotAndIndependence");
        byte[] prefix = new byte[16 + sr.nextInt(64)];
        sr.nextBytes(prefix);
        byte[] suffixA = new byte[16 + sr.nextInt(64)];
        sr.nextBytes(suffixA);
        byte[] suffixB = new byte[16 + sr.nextInt(64)];
        sr.nextBytes(suffixB);
        // Force the two branches to differ so the independence check is meaningful.
        suffixB[0] ^= 0x01;

        MessageDigest md = MessageDigest.getInstance("SHA-256", JostleProvider.PROVIDER_NAME);
        md.update(prefix);

        MessageDigest copy = (MessageDigest) md.clone();

        md.update(suffixA);
        copy.update(suffixB);

        byte[] origOut = md.digest();
        byte[] copyOut = copy.digest();

        MessageDigest ref = MessageDigest.getInstance("SHA-256", JostleProvider.PROVIDER_NAME);
        ref.update(prefix);
        ref.update(suffixA);
        Assertions.assertArrayEquals(ref.digest(), origOut,
                "original digest changed by the clone (cross-talk)");

        ref.update(prefix);
        ref.update(suffixB);
        Assertions.assertArrayEquals(ref.digest(), copyOut,
                "clone did not carry the pre-split state");

        Assertions.assertFalse(Arrays.areEqual(origOut, copyOut),
                "distinct post-split inputs produced identical digests");
    }

    //
    // A clone taken mid-stream, then completed, must agree with BouncyCastle's
    // one-shot digest of the full input — cross-implementation confirmation
    // that the snapshot is the genuine intermediate state, not a reset.
    //
    @Test
    public void testClone_midStream_matchesBC() throws Exception
    {
        SecureRandom sr = seededRandom("testClone_midStream_matchesBC");
        byte[] prefix = new byte[16 + sr.nextInt(128)];
        sr.nextBytes(prefix);
        byte[] suffix = new byte[16 + sr.nextInt(128)];
        sr.nextBytes(suffix);

        MessageDigest md = MessageDigest.getInstance("SHA-256", JostleProvider.PROVIDER_NAME);
        md.update(prefix);
        MessageDigest copy = (MessageDigest) md.clone();
        copy.update(suffix);
        byte[] joClone = copy.digest();

        MessageDigest bc = MessageDigest.getInstance("SHA-256", BouncyCastleProvider.PROVIDER_NAME);
        bc.update(prefix);
        bc.update(suffix);
        Assertions.assertArrayEquals(bc.digest(), joClone,
                "cloned-then-completed digest disagrees with BouncyCastle");
    }

    //
    // Cloning must work for XOF-backed digests too (SHAKE256-512), where the
    // native context carries an xof flag and a fixed squeeze length that the
    // copy must preserve.
    //
    @Test
    public void testClone_xof_SHAKE256_512() throws Exception
    {
        SecureRandom sr = seededRandom("testClone_xof_SHAKE256_512");
        byte[] prefix = new byte[16 + sr.nextInt(64)];
        sr.nextBytes(prefix);
        byte[] suffix = new byte[16 + sr.nextInt(64)];
        sr.nextBytes(suffix);

        MessageDigest md = MessageDigest.getInstance("SHAKE256-512", JostleProvider.PROVIDER_NAME);
        md.update(prefix);
        MessageDigest copy = (MessageDigest) md.clone();
        copy.update(suffix);
        byte[] cloneOut = copy.digest();

        Assertions.assertEquals(64, cloneOut.length, "SHAKE256-512 must squeeze 64 bytes");

        MessageDigest ref = MessageDigest.getInstance("SHAKE256-512", JostleProvider.PROVIDER_NAME);
        ref.update(prefix);
        ref.update(suffix);
        Assertions.assertArrayEquals(ref.digest(), cloneOut,
                "cloned XOF digest did not match the equivalent direct digest");
    }


    //
    // MessageDigest.update(ByteBuffer) routes through the default
    // engineUpdate(ByteBuffer) impl which delegates to engineUpdate(byte[]).
    // Pins that this default delegation works end-to-end.
    //
    @Test
    public void testUpdateByteBuffer() throws Exception
    {
        SecureRandom sr = seededRandom("testUpdateByteBuffer");
        byte[] data = new byte[1024];
        sr.nextBytes(data);

        MessageDigest direct = MessageDigest.getInstance("SHA-256", JostleProvider.PROVIDER_NAME);
        direct.update(data);
        byte[] viaArray = direct.digest();

        MessageDigest viaBuffer = MessageDigest.getInstance("SHA-256", JostleProvider.PROVIDER_NAME);
        viaBuffer.update(ByteBuffer.wrap(data));
        Assertions.assertArrayEquals(viaArray, viaBuffer.digest());

        // Also exercise a slice with non-zero position
        MessageDigest sliced = MessageDigest.getInstance("SHA-256", JostleProvider.PROVIDER_NAME);
        ByteBuffer bb = ByteBuffer.wrap(data);
        bb.position(100);
        sliced.update(bb);
        MessageDigest expected = MessageDigest.getInstance("SHA-256", JostleProvider.PROVIDER_NAME);
        expected.update(data, 100, data.length - 100);
        Assertions.assertArrayEquals(expected.digest(), sliced.digest());
    }


    //
    // The one-shot digest(byte[]) convenience must produce the same bytes as
    // separate update + digest calls.
    //
    @Test
    public void testOneShotDigest() throws Exception
    {
        byte[] data = "Hello".getBytes();

        MessageDigest md = MessageDigest.getInstance("SHA-256", JostleProvider.PROVIDER_NAME);
        byte[] oneShot = md.digest(data);

        MessageDigest md2 = MessageDigest.getInstance("SHA-256", JostleProvider.PROVIDER_NAME);
        md2.update(data);
        byte[] twoStep = md2.digest();

        Assertions.assertArrayEquals(twoStep, oneShot);
        Assertions.assertArrayEquals(
                Hex.decode("185f8db32271fe25f561a6fc938b2e264306ec304eda518007d1764826381969"),
                oneShot);
    }


    //
    // Pin getDigestLength() per algorithm — protects against a registration
    // mix-up that swaps the reported length without breaking the digest
    // agreement test.
    //
    @Test
    public void testGetDigestLength_perAlgorithm() throws Exception
    {
        Object[][] expected = new Object[][]{
                {"SHA1", 20},
                {"SHA2-224", 28},
                {"SHA2-256", 32},
                {"SHA2-384", 48},
                {"SHA2-512", 64},
                {"SHA2-512/224", 28},
                {"SHA2-512/256", 32},
                {"SHA3-224", 28},
                {"SHA3-256", 32},
                {"SHA3-384", 48},
                {"SHA3-512", 64},
                {"SHAKE-128", 32}, // configured xofLen in ProvMD
                {"SHAKE-256", 64}, // configured xofLen in ProvMD
                {"MD5", 16},
                {"SM3", 32},
                {"RIPEMD-160", 20},
                {"BLAKE2S-256", 32},
                {"BLAKE2B-512", 64},
        };

        for (Object[] row : expected)
        {
            String name = (String) row[0];
            int expectedLen = (Integer) row[1];
            MessageDigest md = MessageDigest.getInstance(name, JostleProvider.PROVIDER_NAME);
            Assertions.assertEquals(expectedLen, md.getDigestLength(), "digest length for " + name);
        }
    }

    /**
     * Negative path per CLAUDE.md "Tests must exercise the negative
     * path". The BC-agreement tests confirm Jostle's digest matches BC
     * byte-for-byte on random inputs — strong protection against a
     * stub returning a fixed buffer. This test adds the complementary
     * differentiator check: for the same digest, two distinct inputs
     * must produce distinct outputs, AND a single-bit flip in the
     * input must change the digest. A digest implementation that
     * hashed only the first N bytes (or ignored some input bits)
     * would still agree with BC for inputs whose differences fell in
     * the ignored region; this test catches that class of bug.
     */
    @Test
    public void testDistinctInputsProduceDistinctDigests() throws Exception
    {
        SecureRandom sr = seededRandom("testDistinctInputsProduceDistinctDigests");
        String[] algorithms = {
                "SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512",
                "SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512",
                "SHA-512/224", "SHA-512/256",
                "SHAKE-128", "SHAKE-256",
                "MD5", "RIPEMD-160", "BLAKE2S-256", "BLAKE2B-512", "SM3",
        };
        for (String alg : algorithms)
        {
            MessageDigest md = MessageDigest.getInstance(alg, JostleProvider.PROVIDER_NAME);

            // Random pair of distinct messages → distinct digests.
            byte[] m1 = new byte[64];
            byte[] m2 = new byte[64];
            sr.nextBytes(m1);
            sr.nextBytes(m2);
            byte[] d1 = md.digest(m1);
            byte[] d2 = md.digest(m2);
            Assertions.assertFalse(Arrays.areEqual(d1, d2),
                    alg + ": two distinct random inputs produced identical digests");

            // Single-bit flip → different digest. Probes that the
            // implementation actually consumes every input byte (a
            // digest that hashed only the first 8 bytes would still
            // agree with BC for inputs whose differences sat past
            // byte 8 — this catches that).
            byte[] base = new byte[128];
            sr.nextBytes(base);
            byte[] flipped = base.clone();
            flipped[100] ^= (byte) 0x01;  // flip past the first block boundary for most digests
            byte[] dBase = md.digest(base);
            byte[] dFlip = md.digest(flipped);
            Assertions.assertFalse(Arrays.areEqual(dBase, dFlip),
                    alg + ": single-bit input change did not change the digest");

            // Same input twice → identical digest (digests are deterministic).
            Assertions.assertArrayEquals(dBase, md.digest(base),
                    alg + ": same input must produce the same digest");
        }
    }

}
