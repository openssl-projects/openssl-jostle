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

package org.openssl.jostle.test.xec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.util.Arrays;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.interfaces.XECPrivateKey;
import java.security.interfaces.XECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.NamedParameterSpec;
import java.security.spec.XECPrivateKeySpec;
import java.security.spec.XECPublicKeySpec;

/**
 * Finding B's closure witness: jostle's X25519/X448 keys are readable AND
 * writable through the JDK's own interfaces and specs.
 *
 * <h2>Why this lives in src/test/java11</h2>
 *
 * <p>{@code XECPublicKey}, {@code XECPublicKeySpec} and their private twins are
 * Java 11 APIs, so this cannot compile in the release-8 baseline test set. More
 * importantly it must RUN on a JDK 11 launcher: the classes under test are
 * {@code src/main/java11} overrides, and only a JDK-11 run proves the
 * multi-release jar serves that copy rather than a later one. {@code unitTest11}
 * and {@code integrationTest11} consume this source set.
 *
 * <h2>The BouncyCastle leg</h2>
 *
 * <p>BC 1.86 ACCEPTS both JDK specs: tag {@code r1rv86},
 * {@code prov/src/main/jdk1.11/org/bouncycastle/jcajce/provider/asymmetric/edec/XDHKeys.java}
 * branches on {@code XECPrivateKeySpec} at :220 and {@code XECPublicKeySpec} at
 * :261. Acceptance is not agreement, though, and the two halves differ:
 * measured, the SPKI is byte-identical, while BC's PKCS#8 attaches the public
 * half in RFC 5958 v2 where ours is v1 without it. So the X25519/X448 rows are
 * CELLS in {@code PublicKeySpkiParityTest} and PINS in
 * {@code PrivateKeyPkcs8ParityTest}.
 *
 * <p>Dated past measurement, kept because it is why those rows were blocked:
 * BC 1.85.2 refused both specs with "key spec not recognized"
 * ({@code BaseKeyFactorySpi:57} via {@code edec/KeyFactorySpi:301}).
 *
 * <p>BC is used here as an INSTANCE and is never added to {@code Security}, so
 * the four cells below still prove jostle serves these keys on its own.
 */
public class XECJdkSpecRoundTripTest
{
    private static Provider jsl;

    @BeforeAll
    public static void setUp()
    {
        jsl = new JostleProvider();
        Security.addProvider(jsl);
    }

    /** 2^255 - 19 (RFC 7748 section 4.1). */
    private static final BigInteger X25519_P =
            BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(19));

    /** 2^448 - 2^224 - 1 (RFC 7748 section 4.2). */
    private static final BigInteger X448_P =
            BigInteger.ONE.shiftLeft(448)
                    .subtract(BigInteger.ONE.shiftLeft(224))
                    .subtract(BigInteger.ONE);

    private static BigInteger prime(String alg)
    {
        return "X448".equals(alg) ? X448_P : X25519_P;
    }

    private static int rawLen(String alg)
    {
        return "X448".equals(alg) ? 56 : 32;
    }

    /**
     * The READ side: the keys implement the JDK interfaces and report sane
     * values. Before this change {@code JOXECPublicKey} implemented only
     * {@code PublicKey}, {@code XDHKey} and {@code OSSLKey}, so the cast below
     * threw {@code ClassCastException}.
     */
    @Test
    public void keysImplementTheJdkInterfacesAndReportTheirValues() throws Exception
    {
        for (String alg : new String[]{"X25519", "X448"})
        {
            KeyPair kp = KeyPairGenerator.getInstance(alg, jsl).generateKeyPair();

            XECPublicKey pub = (XECPublicKey) kp.getPublic();
            XECPrivateKey pri = (XECPrivateKey) kp.getPrivate();

            Assertions.assertEquals(alg, ((NamedParameterSpec) pub.getParams()).getName(),
                    alg + ": public getParams must name the curve");
            Assertions.assertEquals(alg, ((NamedParameterSpec) pri.getParams()).getName(),
                    alg + ": private getParams must name the curve");

            BigInteger u = pub.getU();
            Assertions.assertNotNull(u, alg + ": getU returned null");
            Assertions.assertTrue(u.signum() >= 0, alg + ": getU must be unsigned");
            Assertions.assertTrue(u.compareTo(prime(alg)) < 0,
                    alg + ": getU must be reduced; RFC 7748 section 5 masks the top bit"
                            + " on receipt for X25519, so a value >= p means the mask"
                            + " or the little-endian read is wrong");

            byte[] scalar = pri.getScalar().orElseThrow(
                    () -> new AssertionError(alg + ": getScalar must be present"));
            Assertions.assertEquals(rawLen(alg), scalar.length,
                    alg + ": scalar length per RFC 7748 section 5");
        }
    }

    /**
     * The WRITE side, and the round-trip that closes finding B: a key rebuilt
     * from the JDK spec must encode to the SAME bytes as the key it came from —
     * for both halves. Comparing against the GENERATED key's encoding, not
     * against another spec-built key, is what makes this a witness: it pins the
     * spec route to what OpenSSL itself produces.
     */
    @Test
    public void jdkSpecsRebuildTheSameKeyBothHalves() throws Exception
    {
        for (String alg : new String[]{"X25519", "X448"})
        {
            KeyPair kp = KeyPairGenerator.getInstance(alg, jsl).generateKeyPair();
            XECPublicKey pub = (XECPublicKey) kp.getPublic();
            XECPrivateKey pri = (XECPrivateKey) kp.getPrivate();

            PublicKey rebuiltPub = KeyFactory.getInstance(alg, jsl)
                    .generatePublic(new XECPublicKeySpec(pub.getParams(), pub.getU()));
            Assertions.assertTrue(
                    Arrays.areEqual(kp.getPublic().getEncoded(), rebuiltPub.getEncoded()),
                    alg + ": SPKI from XECPublicKeySpec differs from the generated key");

            PrivateKey rebuiltPri = KeyFactory.getInstance(alg, jsl)
                    .generatePrivate(new XECPrivateKeySpec(
                            pri.getParams(), pri.getScalar().orElseThrow()));
            Assertions.assertTrue(
                    Arrays.areEqual(kp.getPrivate().getEncoded(), rebuiltPri.getEncoded()),
                    alg + ": PKCS#8 from XECPrivateKeySpec differs from the generated key");
        }
    }

    /**
     * RFC 7748 section 5: "Implementations MUST accept non-canonical values and
     * process them as if they had been reduced modulo the field prime."
     *
     * <p>So a u-coordinate outside [0, p) is NOT an error — it must be accepted
     * and reduced. This is the OPPOSITE of the Edwards rule (RFC 8032 section
     * 5.1.3 makes an out-of-range y a decoding failure), and a limit test
     * asserting rejection here would pin a spec violation.
     */
    @Test
    public void nonCanonicalUIsAcceptedAndReduced() throws Exception
    {
        for (String alg : new String[]{"X25519", "X448"})
        {
            KeyPair kp = KeyPairGenerator.getInstance(alg, jsl).generateKeyPair();
            XECPublicKey pub = (XECPublicKey) kp.getPublic();
            BigInteger u = pub.getU();
            BigInteger p = prime(alg);

            byte[] canonical = KeyFactory.getInstance(alg, jsl)
                    .generatePublic(new XECPublicKeySpec(pub.getParams(), u))
                    .getEncoded();

            // u + p is congruent to u, and outside the canonical range.
            byte[] viaPlusP = KeyFactory.getInstance(alg, jsl)
                    .generatePublic(new XECPublicKeySpec(pub.getParams(), u.add(p)))
                    .getEncoded();
            Assertions.assertTrue(Arrays.areEqual(canonical, viaPlusP),
                    alg + ": u+p must reduce to the same key (RFC 7748 section 5"
                            + " MUST-accept), not be refused or mis-read");
        }
    }

    /**
     * The claim this class used to make in prose, asserted instead: BC reads
     * the same JDK specs, and what it then emits is pinned per half.
     *
     * <p>The public half AGREES byte-for-byte. The private half does not, and
     * the difference is structural rather than cryptographic — BC emits RFC
     * 5958 v2 with the public key attached, ours v1 without it. Asserting the
     * length inequality rather than equality is deliberate: a later BC that
     * dropped the attachment must fail here and be re-measured, not pass
     * quietly.
     *
     * <p>BC is constructed here and NOT registered, so every other cell in this
     * class still runs with jostle as the only installed provider.
     *
     * <p>Both providers are handed the SAME spec object — two constructions
     * agreeing would measure the constructions, not the encoders — and the
     * public result is anchored to the GENERATED key's encoding, so neither
     * provider can define correctness for itself.
     */
    @Test
    public void bouncyCastleAgreesThroughTheSameJdkSpecs() throws Exception
    {
        Provider bc = new BouncyCastleProvider();

        for (String alg : new String[]{"X25519", "X448"})
        {
            KeyPair kp = KeyPairGenerator.getInstance(alg, jsl).generateKeyPair();
            XECPublicKey pub = (XECPublicKey) kp.getPublic();
            XECPrivateKey pri = (XECPrivateKey) kp.getPrivate();

            XECPublicKeySpec pubSpec = new XECPublicKeySpec(pub.getParams(), pub.getU());
            Assertions.assertTrue(Arrays.areEqual(
                            kp.getPublic().getEncoded(),
                            KeyFactory.getInstance(alg, bc).generatePublic(pubSpec).getEncoded()),
                    alg + ": BC's SPKI from XECPublicKeySpec differs from the generated key");

            XECPrivateKeySpec priSpec = new XECPrivateKeySpec(
                    pri.getParams(), pri.getScalar().orElseThrow());
            byte[] ourPk8 = kp.getPrivate().getEncoded();
            byte[] bcPk8 = KeyFactory.getInstance(alg, bc)
                    .generatePrivate(priSpec).getEncoded();
            Assertions.assertFalse(Arrays.areEqual(ourPk8, bcPk8),
                    alg + ": the PKCS#8 divergence has closed — re-measure"
                            + " PrivateKeyPkcs8ParityTest.xecPinVersionAndAttachedPublicKey");
            Assertions.assertTrue(ourPk8.length < bcPk8.length,
                    alg + ": ours must be the shorter form — BC attaches the public half");
        }
    }

    /** Typed refusals on the new spec path. */
    @Test
    public void malformedJdkSpecsAreRefusedTyped() throws Exception
    {
        KeyFactory kf = KeyFactory.getInstance("X25519", jsl);

        Assertions.assertThrows(InvalidKeySpecException.class,
                () -> kf.generatePublic(new XECPublicKeySpec(
                        new NamedParameterSpec("NoSuchCurve"), BigInteger.ONE)),
                "an unknown parameter spec must be refused typed");

        // A scalar of the wrong length for the named curve: X448's 56 octets
        // handed to X25519.
        Assertions.assertThrows(InvalidKeySpecException.class,
                () -> kf.generatePrivate(new XECPrivateKeySpec(
                        NamedParameterSpec.X25519, new byte[56])),
                "a wrong-length scalar must be refused typed");

        Assertions.assertThrows(InvalidKeySpecException.class,
                () -> kf.generatePrivate(new XECPrivateKeySpec(
                        NamedParameterSpec.X25519, new byte[0])),
                "an empty scalar must be refused typed");
    }
}
