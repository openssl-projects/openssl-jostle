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

package org.openssl.jostle.test.ec;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.test.util.EcCurves;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.Security;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.util.HashSet;
import java.util.Set;

/**
 * SunEC as ORACLE (test-time use of a JDK provider is allowed, per the plan):
 * for every curve JSL serves AND SunEC knows on this JDK, the
 * SubjectPublicKeyInfo our new {@code makePublicFromComponents} path
 * produces is byte-equal to SunEC's own encoding of the identical raw
 * point. {@link ECPublicKeySpecBeyondSunECTest} covers the complementary
 * set — curves JSL serves that SunEC does not know at all.
 */
public class ECPublicKeySpecEncodingParityTest
{
    /**
     * Curves where {@code ECPublicKey.getW()} itself fails today —
     * {@code ec_get_component} draws RAND for affine-coordinate retrieval
     * and {@code ni_getComponent} carries no RandSource. Pre-existing,
     * outside this arc's scope (see reviews/follow-ups-2026-09-14.md);
     * skipped explicitly rather than absorbed into a broad catch.
     */
    private static final Set<String> KNOWN_INTROSPECTION_GAPS = new HashSet<>(java.util.Arrays.asList("SM2"));

    @BeforeAll
    static void ensureProviders()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    @Test
    public void rebuiltEncodingMatchesSunECByteForByte() throws Exception
    {
        int compared = 0;
        int skippedGaps = 0;
        for (String curve : EcCurves.BUILTIN)
        {
            if (KNOWN_INTROSPECTION_GAPS.contains(curve))
            {
                skippedGaps++;
                continue;
            }

            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", "JSL");
            try
            {
                kpg.initialize(new ECGenParameterSpec(curve));
            }
            catch (InvalidAlgorithmParameterException notServedByJsl)
            {
                continue;
            }
            KeyPair jslPair = kpg.generateKeyPair();
            ECPublicKey jslPub = (ECPublicKey) jslPair.getPublic();
            ECPublicKeySpec rawSpec = new ECPublicKeySpec(jslPub.getW(), jslPub.getParams());

            byte[] sunEncoded;
            try
            {
                KeyFactory sunKf = KeyFactory.getInstance("EC", "SunEC");
                PublicKey sunPub = sunKf.generatePublic(rawSpec);
                sunEncoded = sunPub.getEncoded();
            }
            catch (InvalidKeySpecException notKnownToSunEC)
            {
                // ECPublicKeySpecBeyondSunECTest's territory.
                continue;
            }

            KeyFactory jslKf = KeyFactory.getInstance("EC", "JSL");
            PublicKey rebuilt = jslKf.generatePublic(rawSpec);
            Assertions.assertArrayEquals(sunEncoded, rebuilt.getEncoded(),
                    curve + ": SPKI must match SunEC's byte-for-byte");
            compared++;
        }
        System.out.println("ECPublicKeySpecEncodingParityTest: compared " + compared
                + " curve(s) against SunEC; skipped " + skippedGaps + " known introspection gap(s)");
        Assertions.assertTrue(compared > 0,
                "compared " + compared + " curves against SunEC; must be > 0");
    }
}
