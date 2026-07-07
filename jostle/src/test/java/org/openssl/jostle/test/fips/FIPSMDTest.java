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
 * MessageDigest through the FIPS provider ("JSLFIPS"): the approved set
 * resolves and agrees byte-for-byte with the non-FIPS provider (and
 * BouncyCastle) in the same JVM, chunking and clone/reset behave, and the
 * unapproved digests are rejected. Gated on TEST_FIPS_LIB; skipped
 * when unset.
 */
public class FIPSMDTest
{
    private static final SecureRandom RANDOM = new SecureRandom();

    // The fips=yes digest set of the OpenSSL FIPS module, as registered by
    // ProvFIPSMD (canonical OpenSSL names plus the fixed-output SHAKEs).
    private static final String[] APPROVED = {
            "SHA1", "SHA2-224", "SHA2-256", "SHA2-384", "SHA2-512",
            "SHA2-512/224", "SHA2-512/256",
            "SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512",
            "SHAKE-128", "SHAKE-256", "SHAKE128-256", "SHAKE256-512"
    };

    // Names both BouncyCastle and Jostle register, for three-way agreement.
    private static final String[] BC_COMPARABLE = {
            "SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512", "SHA3-256", "SHA3-512"
    };

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
    public void approvedDigestsAgreeAcrossProviders()
        throws Exception
    {
        ensureProviders();

        for (String name : APPROVED)
        {
            for (int t = 0; t < 5; t++)
            {
                byte[] message = new byte[1 + RANDOM.nextInt(2048)];
                RANDOM.nextBytes(message);

                byte[] fips = MessageDigest.getInstance(name, JostleFIPSProvider.PROVIDER_NAME)
                        .digest(message);
                byte[] jsl = MessageDigest.getInstance(name, JostleProvider.PROVIDER_NAME)
                        .digest(message);
                Assertions.assertArrayEquals(jsl, fips, name + ": JSLFIPS vs JSL");

                // The operation actually transforms/differentiates: a
                // one-byte change must change the digest.
                byte[] tampered = message.clone();
                tampered[RANDOM.nextInt(tampered.length)] ^= (byte) (1 + RANDOM.nextInt(255));
                byte[] fipsTampered = MessageDigest.getInstance(name, JostleFIPSProvider.PROVIDER_NAME)
                        .digest(tampered);
                Assertions.assertFalse(java.util.Arrays.equals(fips, fipsTampered),
                        name + ": tampered input produced identical digest");
            }
        }

        for (String name : BC_COMPARABLE)
        {
            byte[] message = new byte[1 + RANDOM.nextInt(2048)];
            RANDOM.nextBytes(message);
            byte[] fips = MessageDigest.getInstance(name, JostleFIPSProvider.PROVIDER_NAME)
                    .digest(message);
            byte[] bc = MessageDigest.getInstance(name, BouncyCastleProvider.PROVIDER_NAME)
                    .digest(message);
            Assertions.assertArrayEquals(bc, fips, name + ": JSLFIPS vs BC");
        }
    }

    @Test
    public void chunkingVariantsAgree()
        throws Exception
    {
        ensureProviders();

        for (String name : new String[]{"SHA-256", "SHA3-256", "SHAKE128-256"})
        {
            byte[] message = new byte[257 + RANDOM.nextInt(1024)];
            RANDOM.nextBytes(message);

            MessageDigest oneShot = MessageDigest.getInstance(name, JostleFIPSProvider.PROVIDER_NAME);
            byte[] expected = oneShot.digest(message);

            MessageDigest byteWise = MessageDigest.getInstance(name, JostleFIPSProvider.PROVIDER_NAME);
            for (byte b : message)
            {
                byteWise.update(b);
            }
            Assertions.assertArrayEquals(expected, byteWise.digest(), name + ": byte-wise");

            MessageDigest randomSplit = MessageDigest.getInstance(name, JostleFIPSProvider.PROVIDER_NAME);
            int offset = 0;
            while (offset < message.length)
            {
                int chunk = Math.min(1 + RANDOM.nextInt(97), message.length - offset);
                randomSplit.update(message, offset, chunk);
                offset += chunk;
            }
            Assertions.assertArrayEquals(expected, randomSplit.digest(), name + ": random splits");
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
}
