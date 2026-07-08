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

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.openssl.jostle.jcajce.provider.OpenSSLException;
import org.openssl.jostle.jcajce.provider.ec.ECServiceNI;
import org.openssl.jostle.jcajce.provider.fips.FIPSNISelector;
import org.openssl.jostle.jcajce.spec.SpecNI;
import org.openssl.jostle.rand.RandSource;
import org.openssl.jostle.test.TestUtil;
import org.openssl.jostle.util.asn1.Asn1Ni;
import org.openssl.jostle.util.asn1.PrivateKeyOptions;

/**
 * Input-validation limit tests at the FIPS ASN.1 encoder/decoder NI surface
 * ({@link FIPSNISelector#Asn1NI}). The FIPS JNI glue is the base asn1_ni_jni.c
 * re-included under renamed symbols, so the bridge's null / range / type checks
 * and typed-error mapping are identical by construction — this pins that they
 * survived into the FIPS interface library with the same messages. Mirrors the
 * base {@code Asn1LimitTest}.
 *
 * <p>FIPS divergence: the base test drives the encode/decode paths with ML-DSA
 * keys, which the FIPS 3.1.2 module does not serve. This version substitutes a
 * <b>P-256 EC</b> keypair (FIPS-approved), and produces the valid DER for the
 * decode round-trips by encoding that key through the FIPS Asn1 bridge itself
 * (self-contained, no BouncyCastle dependency). Real decode failures
 * (corrupted / truncated DER) are prefix-matched on {@code "OpenSSL Error:"}
 * rather than the base's key-type-specific queue text, per the Limit-test
 * message-pinning rule for genuine OpenSSL failures.
 *
 * <p>Runs under the {@code integrationTest*} tasks; gated on
 * {@code TEST_FIPS_LIB} (whole class skips when unset). Adds
 * {@code Integer.MIN_VALUE} alongside {@code -1} on the negative-int probes
 * (testing.md).
 */
public class FIPSAsn1LimitTest
{
    private static final RandSource RND = TestUtil.RNDSrc;

    private static Asn1Ni asn1;
    private static SpecNI specNI;
    private static ECServiceNI ec;

    /** Class-wide P-256 keypair spec (source of the reference DER). */
    private static long ecKeyRef = 0;
    /** Valid SubjectPublicKeyInfo / PrivateKeyInfo DER of {@link #ecKeyRef}. */
    private static byte[] pubDer;
    private static byte[] privDer;

    @BeforeAll
    public static void beforeAll()
    {
        Assumptions.assumeFalse(TestUtil.skipFipsTests(),
                "TEST_FIPS_LIB not set (full path to the FIPS module library)");
        TestUtil.addFipsProvider();
        asn1 = FIPSNISelector.Asn1NI;
        specNI = FIPSNISelector.SpecNI;
        ec = FIPSNISelector.ECServiceNI;
        ecKeyRef = ec.generateKeyPair("P-256", RND);
        pubDer = encode(false);
        privDer = encode(true);
    }

    @AfterAll
    public static void afterAll()
    {
        if (ecKeyRef != 0)
        {
            specNI.dispose(ecKeyRef);
            ecKeyRef = 0;
        }
    }

    /** Encode the class keypair through the FIPS Asn1 bridge into DER. */
    private static byte[] encode(boolean priv)
    {
        long a = asn1.allocate();
        try
        {
            int len = priv
                    ? asn1.encodePrivateKey(a, ecKeyRef, PrivateKeyOptions.DEFAULT.getValue())
                    : asn1.encodePublicKey(a, ecKeyRef);
            byte[] der = new byte[len];
            asn1.getData(a, der);
            return der;
        }
        finally
        {
            asn1.dispose(a);
        }
    }

    // -----------------------------------------------------------------
    // alloc / dispose
    // -----------------------------------------------------------------

    @Test
    public void allocDeallocTest()
    {
        long ref = asn1.allocate();
        try
        {
            // dispose(0) must be a no-op, not a SIGSEGV.
            asn1.dispose(0);
        }
        finally
        {
            asn1.dispose(ref);
        }
    }

    // -----------------------------------------------------------------
    // encode — null key ref / spec with null key
    // -----------------------------------------------------------------

    @Test
    public void encodePrivateKey_keyRefIsZero()
    {
        long a = asn1.allocate();
        try
        {
            assertIAE("key reference is null",
                    () -> asn1.encodePrivateKey(a, 0, PrivateKeyOptions.DEFAULT.getValue()));
        }
        finally
        {
            asn1.dispose(a);
        }
    }

    @Test
    public void encodePublicKey_keyRefIsZero()
    {
        long a = asn1.allocate();
        try
        {
            assertIAE("key reference is null", () -> asn1.encodePublicKey(a, 0));
        }
        finally
        {
            asn1.dispose(a);
        }
    }

    @Test
    public void encodePublicKey_specNullKeyTest()
    {
        long a = asn1.allocate();
        long specRef = specNI.allocate();
        try
        {
            assertIAE("key spec has null key", () -> asn1.encodePublicKey(a, specRef));
        }
        finally
        {
            asn1.dispose(a);
            specNI.dispose(specRef);
        }
    }

    @Test
    public void encodePrivateKey_specNullKeyTest()
    {
        long a = asn1.allocate();
        long specRef = specNI.allocate();
        try
        {
            assertIAE("key spec has null key",
                    () -> asn1.encodePrivateKey(a, specRef, PrivateKeyOptions.DEFAULT.getValue()));
        }
        finally
        {
            asn1.dispose(a);
            specNI.dispose(specRef);
        }
    }

    @Test
    public void encodePrivateKey_keyNullInSpec()
    {
        long a = asn1.allocate();
        long specRef = specNI.allocate();
        try
        {
            assertIAE("key spec has null key",
                    () -> asn1.encodePrivateKey(a, specRef, PrivateKeyOptions.DEFAULT.getValue()));
        }
        finally
        {
            asn1.dispose(a);
            specNI.dispose(specRef);
        }
    }

    // -----------------------------------------------------------------
    // encode — getData output-buffer size must match exactly
    // -----------------------------------------------------------------

    @Test
    public void encodePublicKey_output_wrong_size()
    {
        long a = asn1.allocate();
        try
        {
            final int len = asn1.encodePublicKey(a, ecKeyRef);
            // Too long by one, then too small by one — both out of range.
            assertIAE("output offset + length is out of range", () -> asn1.getData(a, new byte[len + 1]));
            assertIAE("output offset + length is out of range", () -> asn1.getData(a, new byte[len - 1]));
        }
        finally
        {
            asn1.dispose(a);
        }
    }

    @Test
    public void encodePrivateKey_output_wrong_size()
    {
        long a = asn1.allocate();
        try
        {
            final int len = asn1.encodePrivateKey(a, ecKeyRef, PrivateKeyOptions.DEFAULT.getValue());
            assertIAE("output offset + length is out of range", () -> asn1.getData(a, new byte[len + 1]));
            assertIAE("output offset + length is out of range", () -> asn1.getData(a, new byte[len - 1]));
        }
        finally
        {
            asn1.dispose(a);
        }
    }

    // -----------------------------------------------------------------
    // encode — key-type / encoding-option guards
    // -----------------------------------------------------------------

    @Test
    public void encodePrivateKey_seedOnly_unsupportedAlgorithm()
    {
        // seed_only_encoder handles only ML-DSA / ML-KEM. An EC key returns
        // JO_INCORRECT_KEY_TYPE which the bridge surfaces as
        // IllegalArgumentException("invalid key type").
        long a = asn1.allocate();
        try
        {
            assertIAE("invalid key type",
                    () -> asn1.encodePrivateKey(a, ecKeyRef, PrivateKeyOptions.SEED_ONLY.getValue()));
        }
        finally
        {
            asn1.dispose(a);
        }
    }

    @Test
    public void encodePublicKey_unknown_encoding_option()
    {
        // An unrecognised option string is rejected before the key type
        // matters → "invalid key encoding option".
        long a = asn1.allocate();
        try
        {
            assertIAE("invalid key encoding option",
                    () -> asn1.encodePrivateKey(a, ecKeyRef, "unknown"));
        }
        finally
        {
            asn1.dispose(a);
        }
    }

    // -----------------------------------------------------------------
    // fromPrivateKeyInfo — null / negative / range (+ MIN_VALUE) + valid decode
    // -----------------------------------------------------------------

    @Test
    public void fromPrivateKeyInfo_inIsNull()
    {
        assertNPE("input is null", () -> asn1.fromPrivateKeyInfo(null, 0, 0));
    }

    @Test
    public void fromPrivateKeyInfo_inOffNeg()
    {
        for (int off : new int[]{-1, Integer.MIN_VALUE})
        {
            assertIAE("input offset is negative", () -> asn1.fromPrivateKeyInfo(new byte[0], off, 0));
        }
    }

    @Test
    public void fromPrivateKeyInfo_inLenNeg()
    {
        for (int len : new int[]{-1, Integer.MIN_VALUE})
        {
            assertIAE("input len is negative", () -> asn1.fromPrivateKeyInfo(new byte[0], 0, len));
        }
    }

    @Test
    public void fromPrivateKeyInfo_inOutOfRange()
    {
        // Boundary + 1: 1 + 16 > 16, and 0 + 17 > 16.
        assertIAE("input offset + length is out of range", () -> asn1.fromPrivateKeyInfo(new byte[16], 1, 16));
        assertIAE("input offset + length is out of range", () -> asn1.fromPrivateKeyInfo(new byte[16], 0, 17));

        // Positive companion: a valid PrivateKeyInfo decodes at offset 0 and at
        // a non-zero offset.
        specNI.dispose(asn1.fromPrivateKeyInfo(privDer, 0, privDer.length));
        byte[] shifted = new byte[privDer.length + 1];
        System.arraycopy(privDer, 0, shifted, 1, privDer.length);
        specNI.dispose(asn1.fromPrivateKeyInfo(shifted, 1, privDer.length));
    }

    @Test
    public void fromPrivateKey_dodgyData()
    {
        byte[] bad = privDer.clone();
        bad[0] ^= 1;
        OpenSSLException ex = Assertions.assertThrows(OpenSSLException.class,
                () -> asn1.fromPrivateKeyInfo(bad, 0, bad.length));
        Assertions.assertTrue(ex.getMessage().startsWith("OpenSSL Error:"),
                "unexpected message: " + ex.getMessage());
    }

    @Test
    public void fromPrivateKey_dodgyDataTooShort()
    {
        // Valid data in the array but the declared length is too short.
        OpenSSLException ex = Assertions.assertThrows(OpenSSLException.class,
                () -> asn1.fromPrivateKeyInfo(privDer, 0, privDer.length - 10));
        Assertions.assertTrue(ex.getMessage().startsWith("OpenSSL Error:"),
                "unexpected message: " + ex.getMessage());
    }

    // -----------------------------------------------------------------
    // fromPublicKeyInfo — null / negative / range (+ MIN_VALUE) + valid decode
    // -----------------------------------------------------------------

    @Test
    public void fromPublicKeyInfo_inIsNull()
    {
        assertNPE("input is null", () -> asn1.fromPublicKeyInfo(null, 0, 0));
    }

    @Test
    public void fromPublicKeyInfo_inOffNeg()
    {
        for (int off : new int[]{-1, Integer.MIN_VALUE})
        {
            assertIAE("input offset is negative", () -> asn1.fromPublicKeyInfo(new byte[0], off, 0));
        }
    }

    @Test
    public void fromPublicKeyInfo_inLenNeg()
    {
        for (int len : new int[]{-1, Integer.MIN_VALUE})
        {
            assertIAE("input len is negative", () -> asn1.fromPublicKeyInfo(new byte[0], 0, len));
        }
    }

    @Test
    public void fromPublicKeyInfo_inOutOfRange()
    {
        assertIAE("input offset + length is out of range", () -> asn1.fromPublicKeyInfo(new byte[16], 1, 16));
        assertIAE("input offset + length is out of range", () -> asn1.fromPublicKeyInfo(new byte[16], 0, 17));

        specNI.dispose(asn1.fromPublicKeyInfo(pubDer, 0, pubDer.length));
        byte[] shifted = new byte[pubDer.length + 1];
        System.arraycopy(pubDer, 0, shifted, 1, pubDer.length);
        specNI.dispose(asn1.fromPublicKeyInfo(shifted, 1, pubDer.length));
    }

    @Test
    public void fromPublicKey_dodgyData()
    {
        byte[] bad = pubDer.clone();
        bad[0] ^= 1;
        OpenSSLException ex = Assertions.assertThrows(OpenSSLException.class,
                () -> asn1.fromPublicKeyInfo(bad, 0, bad.length));
        Assertions.assertTrue(ex.getMessage().startsWith("OpenSSL Error:"),
                "unexpected message: " + ex.getMessage());
    }

    @Test
    public void fromPublicKey_dodgyDataTooShort()
    {
        OpenSSLException ex = Assertions.assertThrows(OpenSSLException.class,
                () -> asn1.fromPublicKeyInfo(pubDer, 0, pubDer.length - 10));
        Assertions.assertTrue(ex.getMessage().startsWith("OpenSSL Error:"),
                "unexpected message: " + ex.getMessage());
    }

    // -----------------------------------------------------------------
    // helpers
    // -----------------------------------------------------------------

    private static void assertIAE(String message, Executable action)
    {
        IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class, action);
        Assertions.assertEquals(message, e.getMessage());
    }

    private static void assertNPE(String message, Executable action)
    {
        NullPointerException e = Assertions.assertThrows(NullPointerException.class, action);
        Assertions.assertEquals(message, e.getMessage());
    }
}
