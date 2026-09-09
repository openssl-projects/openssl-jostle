/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.test.provider;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.util.Arrays;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.security.Security;

/**
 * MT-83: the PKCS#5 {@code hmacWith*} OIDs must resolve as a Mac.
 *
 * <h2>Why an internal parity guard cannot find this</h2>
 *
 * <p>{@code FIPSOidCrossProviderParityTest} compares JSL's OID set against
 * JSLFIPS's, so a gap BOTH providers share is invisible to it by construction
 * — and this gap was shared. Only a reference outside our own two surfaces can
 * see it, so the list below is transcribed from RFC 8018 Appendix B.1.1 rather
 * than derived from anything we register. bc-java's
 * {@code JcePBMac1CalculatorBuilder} resolves a Mac by exactly these OIDs and
 * never by name, so before this the provider was unusable to it.
 *
 * <h2>Deliberate superset on the last two</h2>
 *
 * <p>BouncyCastle serves {@code .12} and {@code .13} (SHA-512/224 and
 * SHA-512/256) under NEITHER OID, measured against bcprov 1.85.2 — we do,
 * because both Macs are served by name on every provider here and RFC 8018
 * B.1.1 defines the OIDs. This is a superset of BC BY DESIGN. A future parity
 * sweep must not remove them on the grounds that BC lacks them.
 */
public class MacOidCoverageTest
{
    /**
     * RFC 8018 Appendix B.1.1, on the {@code digestAlgorithm} arc
     * {@code 1.2.840.113549.2}: {@code id-hmacWithSHA1 ::= {digestAlgorithm 7}}
     * through {@code id-hmacWithSHA512-256 ::= {digestAlgorithm 13}}.
     */
    public static final String[][] PKCS5_HMAC_OIDS = {
            {"1.2.840.113549.2.7", "HMACSHA1"},
            {"1.2.840.113549.2.8", "HMACSHA224"},
            {"1.2.840.113549.2.9", "HMACSHA256"},
            {"1.2.840.113549.2.10", "HMACSHA384"},
            {"1.2.840.113549.2.11", "HMACSHA512"},
            {"1.2.840.113549.2.12", "HMACSHA512/224"},
            {"1.2.840.113549.2.13", "HMACSHA512/256"},
    };

    private static final SecureRandom RANDOM = new SecureRandom();

    @BeforeAll
    public static void setUp()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    /**
     * Each OID must resolve AND compute the same tag as its named algorithm.
     * Resolution alone would pass against an alias pointing at the wrong
     * digest — a wrong OID accepted is worse than one absent.
     */
    @Test
    public void everyPkcs5HmacOidResolvesToItsNamedAlgorithm() throws Exception
    {
        byte[] keyBytes = new byte[32];
        RANDOM.nextBytes(keyBytes);
        byte[] msg = new byte[1 + RANDOM.nextInt(128)];
        RANDOM.nextBytes(msg);

        for (String[] row : PKCS5_HMAC_OIDS)
        {
            String oid = row[0];
            String name = row[1];

            Mac byName = Mac.getInstance(name, JostleProvider.PROVIDER_NAME);
            byName.init(new SecretKeySpec(keyBytes, name));
            byte[] expected = byName.doFinal(msg);

            Mac byOid = Mac.getInstance(oid, JostleProvider.PROVIDER_NAME);
            byOid.init(new SecretKeySpec(keyBytes, name));
            byte[] actual = byOid.doFinal(msg);

            Assertions.assertTrue(Arrays.areEqual(expected, actual),
                    oid + " must compute the same tag as " + name);
        }
    }

    /**
     * The tags must differ between digests, or the previous test would pass
     * against seven aliases all pointing at one algorithm.
     */
    @Test
    public void theSevenOidsDoNotAllResolveToTheSameAlgorithm() throws Exception
    {
        byte[] keyBytes = new byte[32];
        RANDOM.nextBytes(keyBytes);
        byte[] msg = "the same message for every digest".getBytes("UTF-8");

        byte[] previous = null;
        for (String[] row : PKCS5_HMAC_OIDS)
        {
            Mac m = Mac.getInstance(row[0], JostleProvider.PROVIDER_NAME);
            m.init(new SecretKeySpec(keyBytes, row[1]));
            byte[] tag = m.doFinal(msg);
            if (previous != null)
            {
                Assertions.assertFalse(Arrays.areEqual(previous, tag),
                        row[0] + " produced the same tag as the preceding OID");
            }
            previous = tag;
        }
    }
}
