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

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;

/**
 * MessageDigest <b>behaviour</b> through the FIPS provider ("JSLFIPS"): clone
 * and reuse-after-reset, OID-alias resolution, and rejection of the unapproved
 * digests. Cross-provider byte-for-byte agreement over the approved set (vs the
 * non-FIPS provider and BouncyCastle) lives in the dedicated
 * {@code FIPSMDAgreementTest}. Gated on TEST_FIPS_LIB; skipped when unset.
 */
public class FIPSMDTest
{
    private static final SecureRandom RANDOM = new SecureRandom();

    private static final String[] UNAPPROVED = {
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
    public void unapprovedDigestsRejected()
        throws Exception
    {
        ensureProviders();

        for (String name : UNAPPROVED)
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
}
