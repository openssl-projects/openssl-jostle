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

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.test.util.EcCurves;
import org.openssl.jostle.util.Arrays;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashSet;
import java.util.Set;
import java.util.TreeSet;

/**
 * The complementary set to {@link ECPublicKeySpecEncodingParityTest}: for
 * every curve JSL serves that SunEC does NOT know on this JDK, the
 * {@link ECPublicKeySpec} path now succeeds and round-trips to the
 * {@link X509EncodedKeySpec} form. Skips, never fails, when the set is
 * empty on the running JDK.
 *
 * <p>Byte-equality is the assertion — with one PINNED exception. OpenSSL
 * names several curves by one parameter set (a WAP-specific alias re-using
 * a standard binary curve, e.g.); {@code ECParameterSpec} carries no name,
 * so {@code ECComponents.findCurveName} (shared by both component paths)
 * returns whichever name its table lists first for that parameter set, not
 * necessarily the caller's original name. Where byte equality fails, the
 * divergence must be EXACTLY that shape — same algorithm OID, same point
 * bytes, same domain parameters, and the rebuilt key still verifies a
 * signature from the original private key — and the curve name must be in
 * {@link #SAME_PARAMETER_ALIASES}, measured once and pinned so a NEW alias
 * (or a lost one) fails loudly rather than silently widening the exemption.
 */
public class ECPublicKeySpecBeyondSunECTest
{
    /**
     * Measured 2026-09-16: curves whose rebuilt SPKI differs from the
     * original only by namedCurve OID, because OpenSSL's curve table lists
     * more than one name for the identical (field, a, b, G, order,
     * cofactor) tuple.
     */
    private static final Set<String> SAME_PARAMETER_ALIASES =
            new HashSet<>(java.util.Arrays.asList("wap-wsg-idm-ecid-wtls5"));

    /**
     * Curves where {@code ECPublicKey.getW()} itself fails today —
     * {@code ec_get_component} draws RAND for affine-coordinate retrieval
     * and {@code ni_getComponent} carries no RandSource (same as
     * {@code ECPublicKeySpecEncodingParityTest}). Skipped explicitly rather
     * than absorbed into a broad catch.
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
    public void rawSpecWorksAndRoundTripsWhereSunECRefuses() throws Exception
    {
        int exercised = 0;
        Set<String> aliasedCurves = new TreeSet<>();
        for (String curve : EcCurves.BUILTIN)
        {
            if (KNOWN_INTROSPECTION_GAPS.contains(curve))
            {
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

            try
            {
                KeyFactory.getInstance("EC", "SunEC").generatePublic(rawSpec);
                // SunEC knows this curve — ECPublicKeySpecEncodingParityTest's territory.
                continue;
            }
            catch (InvalidKeySpecException notKnownToSunEC)
            {
                // Exactly the set this test exists for.
            }

            KeyFactory jslKf = KeyFactory.getInstance("EC", "JSL");
            PublicKey rebuilt = jslKf.generatePublic(rawSpec);

            byte[] originalEnc = jslPub.getEncoded();
            byte[] rebuiltEnc = rebuilt.getEncoded();
            if (Arrays.areEqual(originalEnc, rebuiltEnc))
            {
                exercised++;
                continue;
            }

            // Not byte-equal — must be EXACTLY the pinned alias shape.
            aliasedCurves.add(curve);

            SubjectPublicKeyInfo origSpki = SubjectPublicKeyInfo.getInstance(originalEnc);
            SubjectPublicKeyInfo rebSpki = SubjectPublicKeyInfo.getInstance(rebuiltEnc);
            Assertions.assertEquals(origSpki.getAlgorithm().getAlgorithm(), rebSpki.getAlgorithm().getAlgorithm(),
                    curve + ": algorithm OID must still be id-ecPublicKey in both");
            Assertions.assertNotEquals(origSpki.getAlgorithm().getParameters(), rebSpki.getAlgorithm().getParameters(),
                    curve + ": expected the divergence to be the namedCurve OID itself");
            Assertions.assertArrayEquals(
                    origSpki.getPublicKeyData().getBytes(), rebSpki.getPublicKeyData().getBytes(),
                    curve + ": point bytes must be identical between the two spellings");

            ECPublicKey rebuiltEcPub = (ECPublicKey) rebuilt;
            Assertions.assertEquals(jslPub.getParams().getCofactor(), rebuiltEcPub.getParams().getCofactor(),
                    curve + ": cofactor must match — same parameter set");
            Assertions.assertEquals(jslPub.getParams().getOrder(), rebuiltEcPub.getParams().getOrder(),
                    curve + ": order must match — same parameter set");
            Assertions.assertEquals(jslPub.getParams().getCurve(), rebuiltEcPub.getParams().getCurve(),
                    curve + ": field/a/b must match — same parameter set");
            Assertions.assertEquals(jslPub.getParams().getGenerator(), rebuiltEcPub.getParams().getGenerator(),
                    curve + ": generator must match — same parameter set");

            byte[] msg = new byte[32];
            new SecureRandom().nextBytes(msg);
            Signature signer = Signature.getInstance("NONEwithECDSA", "JSL");
            signer.initSign(jslPair.getPrivate());
            signer.update(msg);
            byte[] sig = signer.sign();
            Signature verifier = Signature.getInstance("NONEwithECDSA", "JSL");
            verifier.initVerify(rebuilt);
            verifier.update(msg);
            Assertions.assertTrue(verifier.verify(sig),
                    curve + ": rebuilt key must verify a signature made by the original private key");

            exercised++;
        }
        System.out.println("ECPublicKeySpecBeyondSunECTest: exercised " + exercised
                + " curve(s) beyond SunEC's knowledge on this JDK; aliased=" + aliasedCurves);
        Assumptions.assumeTrue(exercised > 0,
                "no curve beyond SunEC's knowledge on this JDK — nothing to exercise here");
        Assertions.assertEquals(SAME_PARAMETER_ALIASES, aliasedCurves,
                "the set of curves whose rebuilt SPKI differs only by namedCurve OID must match the pinned list "
                        + "exactly — a new or lost alias must be investigated, not silently absorbed");
    }
}
