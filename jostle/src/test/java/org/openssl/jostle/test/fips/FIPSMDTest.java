/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.test.fips;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;
import org.openssl.jostle.util.Arrays;
import org.openssl.jostle.util.encoders.Hex;

import java.security.DigestException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;

/**
 * MessageDigest <b>behaviour</b> through the FIPS provider ("JSLFIPS"): clone
 * and reuse-after-reset, OID-alias resolution, and absence of the not-served
 * digests. Cross-provider byte-for-byte agreement over the approved set (vs the
 * non-FIPS provider and BouncyCastle) lives in the dedicated
 * {@code FIPSMDAgreementTest}. Gated on TEST_FIPS_LIB; skipped when unset.
 */
public class FIPSMDTest
{
    private static final SecureRandom RANDOM = new SecureRandom();

    private static final String[] NOT_SERVED_BY_MODULE = {
            "MD5", "MD5-SHA1", "SM3", "BLAKE2B-512", "BLAKE2S-256", "RIPEMD-160"
    };

    private static void ensureProviders()
    {
        FIPSTestUtil.assumeFipsProvider();
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
    public void cloneAndReuse()
        throws Exception
    {
        ensureProviders();

        byte[] message = new byte[512];
        RANDOM.nextBytes(message);

        MessageDigest md = MessageDigest.getInstance("SHA-256", JostleFIPSProvider.PROVIDER_NAME);
        byte[] expected = md.digest(message);

        // Reuse after a terminal digest: same instance, same answer.
        md.update(message);
        Assertions.assertArrayEquals(expected, md.digest(), "reuse after digest");

        // Clone mid-stream: both halves finish independently to the same
        // digest of the full message.
        md.update(message, 0, 256);
        MessageDigest cloned = (MessageDigest) md.clone();
        md.update(message, 256, 256);
        cloned.update(message, 256, 256);
        Assertions.assertArrayEquals(expected, md.digest(), "original after clone");
        Assertions.assertArrayEquals(expected, cloned.digest(), "clone");
    }

    @Test
    public void oidAliasesResolve()
        throws Exception
    {
        ensureProviders();

        byte[] message = new byte[64];
        RANDOM.nextBytes(message);
        byte[] byName = MessageDigest.getInstance("SHA-256", JostleFIPSProvider.PROVIDER_NAME)
                .digest(message);
        byte[] byOid = MessageDigest.getInstance("2.16.840.1.101.3.4.2.1", JostleFIPSProvider.PROVIDER_NAME)
                .digest(message);
        Assertions.assertArrayEquals(byName, byOid);
    }

    @Test
    public void digestsNotServedByModuleRejected()
        throws Exception
    {
        ensureProviders();

        for (String name : NOT_SERVED_BY_MODULE)
        {
            Assertions.assertThrows(NoSuchAlgorithmException.class,
                    () -> MessageDigest.getInstance(name, JostleFIPSProvider.PROVIDER_NAME),
                    name + " must not resolve through JSLFIPS");
        }

        // ... while the non-FIPS provider still serves them in the same JVM.
        Assertions.assertNotNull(MessageDigest.getInstance("MD5", JostleProvider.PROVIDER_NAME));
    }

    /**
     * Differentiator: the digest is a function of its input. Two distinct random
     * messages must produce distinct digests, and a one-byte change must change
     * the digest — proof the JSLFIPS digest is not a fixed or truncated buffer.
     * (Cross-provider byte-identity is asserted in {@code FIPSMDAgreementTest}.)
     */
    @Test
    public void distinctInputsProduceDistinctDigests()
        throws Exception
    {
        ensureProviders();

        byte[] a = new byte[64 + RANDOM.nextInt(256)];
        byte[] b = new byte[64 + RANDOM.nextInt(256)];
        RANDOM.nextBytes(a);
        RANDOM.nextBytes(b);

        MessageDigest md = MessageDigest.getInstance("SHA-256", JostleFIPSProvider.PROVIDER_NAME);
        byte[] digestA = md.digest(a);
        byte[] digestB = MessageDigest.getInstance("SHA-256", JostleFIPSProvider.PROVIDER_NAME).digest(b);
        Assertions.assertFalse(java.util.Arrays.equals(digestA, digestB),
                "distinct inputs produced identical digests");

        byte[] tampered = a.clone();
        tampered[RANDOM.nextInt(tampered.length)] ^= (byte) (1 + RANDOM.nextInt(255));
        byte[] digestTampered = MessageDigest.getInstance("SHA-256", JostleFIPSProvider.PROVIDER_NAME).digest(tampered);
        Assertions.assertFalse(java.util.Arrays.equals(digestA, digestTampered),
                "a one-byte change produced an identical digest");
    }

    //
    // Pin the JCA contract at the FIPS surface: an output buffer that's too
    // small for the digest result must surface as DigestException, not
    // IllegalArgumentException. Mirrors MDTest.testDigestException_outputBufferTooSmall.
    // The FIPS Limit test only proves the NI throws IllegalArgumentException;
    // this pins the SPI translation at engineDigest.
    //
    @Test
    public void digestIntoUndersizedBuffer_throwsDigestException()
        throws Exception
    {
        ensureProviders();

        MessageDigest md = MessageDigest.getInstance("SHA-256", JostleFIPSProvider.PROVIDER_NAME);
        byte[] message = new byte[64];
        RANDOM.nextBytes(message);
        md.update(message);

        byte[] tooSmall = new byte[16]; // SHA-256 needs 32

        Assertions.assertThrows(DigestException.class,
                () -> md.digest(tooSmall, 0, tooSmall.length),
                "expected DigestException for under-sized output buffer");
    }

    //
    // Pin getDigestLength() per approved algorithm — locks the ProvFIPSMD
    // registration table, in particular the hand-written SHAKE xof lengths and
    // the two fixed-output SHAKE aliases (SHAKE128-256, SHAKE256-512) that
    // ProvFIPSMD registers independently of ProvMD. Mirrors
    // MDTest.testGetDigestLength_perAlgorithm, approved set only.
    //
    @Test
    public void getDigestLengthPerApprovedAlgorithm()
        throws Exception
    {
        ensureProviders();

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
                {"SHAKE-128", 32}, // configured xofLen in ProvFIPSMD
                {"SHAKE-256", 64}, // configured xofLen in ProvFIPSMD
                {"SHAKE128-256", 32}, // fixed-output alias only ProvFIPSMD registers
                {"SHAKE256-512", 64}, // fixed-output alias only ProvFIPSMD registers
        };

        for (Object[] row : expected)
        {
            String name = (String) row[0];
            int expectedLen = (Integer) row[1];
            MessageDigest md = MessageDigest.getInstance(name, JostleFIPSProvider.PROVIDER_NAME);
            Assertions.assertEquals(expectedLen, md.getDigestLength(), "digest length for " + name);
        }
    }

    //
    // Cloning must work for XOF-backed digests too (SHAKE256-512), where the
    // native context carries an xof flag and a fixed squeeze length that the
    // copy must preserve. Feed DIFFERENT post-split bytes to the original and
    // the clone: both must finish to the digest of their respective full
    // inputs and differ (no shared EVP_MD_CTX cross-talk). Mirrors
    // MDTest.testClone_xof_SHAKE256_512.
    //
    @Test
    public void cloneXofShake256_512_snapshotAndIndependence()
        throws Exception
    {
        ensureProviders();

        byte[] prefix = new byte[16 + RANDOM.nextInt(64)];
        RANDOM.nextBytes(prefix);
        byte[] suffix = new byte[16 + RANDOM.nextInt(64)];
        RANDOM.nextBytes(suffix);
        byte[] suffixOrig = new byte[16 + RANDOM.nextInt(64)];
        RANDOM.nextBytes(suffixOrig);
        // Force the two post-split branches to differ so the independence
        // check below is meaningful even if the random lengths coincide.
        suffixOrig[0] ^= 0x01;

        MessageDigest md = MessageDigest.getInstance("SHAKE256-512", JostleFIPSProvider.PROVIDER_NAME);
        md.update(prefix);
        MessageDigest copy = (MessageDigest) md.clone();

        // Drive the original and the clone with DIFFERENT post-split data:
        // a clone that shared the underlying EVP_MD_CTX would cross-talk.
        md.update(suffixOrig);
        copy.update(suffix);
        byte[] cloneOut = copy.digest();
        byte[] origOut = md.digest();

        Assertions.assertEquals(64, cloneOut.length, "SHAKE256-512 must squeeze 64 bytes");

        MessageDigest ref = MessageDigest.getInstance("SHAKE256-512", JostleFIPSProvider.PROVIDER_NAME);
        ref.update(prefix);
        ref.update(suffix);
        Assertions.assertArrayEquals(ref.digest(), cloneOut,
                "cloned XOF digest did not match the equivalent direct digest");

        ref.update(prefix);
        ref.update(suffixOrig);
        Assertions.assertArrayEquals(ref.digest(), origOut,
                "original XOF digest changed by the clone (cross-talk)");

        Assertions.assertFalse(Arrays.areEqual(origOut, cloneOut),
                "distinct post-split inputs produced identical XOF digests (shared ctx?)");
    }

    //
    // Explicit reset() mid-stream must discard accumulated state. The FIPS
    // tests cover only terminal auto-reset; standalone reset() (buffer-clear +
    // EVP_DigestInit) is a distinct path. Mirrors MDTest.testExplicitResetMidStream.
    //
    @Test
    public void explicitResetMidStreamDiscardsState()
        throws Exception
    {
        ensureProviders();

        byte[] discard = new byte[64];
        byte[] message = new byte[64];
        RANDOM.nextBytes(discard);
        RANDOM.nextBytes(message);

        MessageDigest md = MessageDigest.getInstance("SHA-256", JostleFIPSProvider.PROVIDER_NAME);
        md.update(discard);
        md.reset();
        md.update(message);
        byte[] afterReset = md.digest();

        // Same as a fresh ctx digesting only the kept message.
        MessageDigest fresh = MessageDigest.getInstance("SHA-256", JostleFIPSProvider.PROVIDER_NAME);
        fresh.update(message);
        Assertions.assertArrayEquals(fresh.digest(), afterReset);
    }

    //
    // Empty-input KAT: pin exact digest bytes for every approved algorithm
    // (including the two fixed-output SHAKE aliases), anchoring the FIPS
    // surface to fixed published vectors independent of any other provider. A
    // second digest() after auto-reset must return the same bytes. Mirrors
    // MDTest.testEmptyMD / testUseAfterTakingDigest, approved set only.
    //
    @Test
    public void emptyInputKatPerApprovedAlgorithm()
        throws Exception
    {
        ensureProviders();

        String[][] vectors = new String[][]{
                {"SHA1", "da39a3ee5e6b4b0d3255bfef95601890afd80709"},
                {"SHA2-224", "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"},
                {"SHA2-256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
                {"SHA2-384", "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"},
                {"SHA2-512", "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"},
                {"SHA2-512/224", "6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4"},
                {"SHA2-512/256", "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a"},
                {"SHA3-224", "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"},
                {"SHA3-256", "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"},
                {"SHA3-384", "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"},
                {"SHA3-512", "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"},
                {"SHAKE-128", "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26"},
                {"SHAKE-256", "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be"},
                // Fixed-output SHAKE aliases only ProvFIPSMD registers: same
                // bytes as SHAKE-128 (32) / SHAKE-256 (64) at these lengths.
                {"SHAKE128-256", "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26"},
                {"SHAKE256-512", "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be"},
        };

        for (String[] v : vectors)
        {
            String name = v[0];
            byte[] expected = Hex.decode(v[1]);

            MessageDigest md = MessageDigest.getInstance(name, JostleFIPSProvider.PROVIDER_NAME);
            byte[] digest1 = md.digest();          // empty input
            byte[] digest2 = md.digest();          // taking the digest auto-resets the state

            Assertions.assertArrayEquals(expected, digest1, "empty digest: " + name);
            Assertions.assertArrayEquals(digest1, digest2, "empty digest after auto reset: " + name);
        }
    }
}
