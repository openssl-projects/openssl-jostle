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

package org.openssl.jostle.test.mlxkem;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.mlxkem.MLXKEMServiceNI;
import org.openssl.jostle.jcajce.spec.MLXKEMParameterSpec;
import org.openssl.jostle.jcajce.spec.SpecNI;
import org.openssl.jostle.test.TestUtil;
import org.openssl.jostle.test.crypto.TestNISelector;

import java.security.Security;

/**
 * Input validation at the hybrid KEM NI surface, driven directly so the bridge
 * checks are exercised rather than the SPI's.
 *
 * <p>Every one of these would otherwise reach a util {@code jo_assert} and
 * abort the JVM — invisible to every positive test, and exactly what a hostile
 * or careless NI caller hits. Runs on BOTH bridges via {@code TestNISelector};
 * the two validate separately and must return identical codes.
 */
public class MLXKEMLimitTest
{
    private final MLXKEMServiceNI ni = TestNISelector.getMLXKEMNI();
    private final SpecNI specNI = TestNISelector.getSpecNI();

    private static final int KS_TYPE = MLXKEMParameterSpec.x25519_mlkem768.getKeyType().getKsType();

    @BeforeAll
    public static void beforeAll()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    // -----------------------------------------------------------------
    // Native handles
    // -----------------------------------------------------------------

    /**
     * A 0 handle at EVERY entry point that takes one. Doing it per entry point
     * rather than once matters: each bridge function validates independently,
     * and the defect this guards against is one function checking a handle its
     * neighbour asserts.
     */
    @Test
    public void nullKeySpecHandle_rejectedTypedAtEveryEntryPoint()
    {
        assertTyped(IllegalArgumentException.class, "key spec is null",
                () -> ni.getPublicKey(0, null));
        assertTyped(IllegalArgumentException.class, "key spec is null",
                () -> ni.getPublicKey(0, new byte[16]));
        assertTyped(IllegalArgumentException.class, "key spec is null",
                () -> ni.getPrivateKey(0, null));
        assertTyped(IllegalArgumentException.class, "key spec is null",
                () -> ni.getPrivateKey(0, new byte[16]));
        assertTyped(IllegalArgumentException.class, "key spec is null",
                () -> ni.decode_publicKey(0, KS_TYPE, new byte[16], 0, 16));
        assertTyped(IllegalArgumentException.class, "key spec is null",
                () -> ni.decode_privateKey(0, KS_TYPE, new byte[16], 0, 16));
    }

    /**
     * Keygen consumes entropy, so a null RandSource must be refused before any
     * OpenSSL call rather than reaching the util layer.
     */
    @Test
    public void nullRandSource_rejectedTyped()
    {
        assertTyped(IllegalArgumentException.class, "supplied random source was null",
                () -> ni.generateKeyPair(KS_TYPE, null));
    }

    /**
     * A key type outside the hybrid set. Pins the family-specific message the
     * NI substitutes for the generic "invalid key type" — a caller who passed
     * an ML-KEM type here needs to be told which family rejected it.
     */
    @Test
    public void wrongKeyType_rejectedTyped()
    {
        int mlkem768 = org.openssl.jostle.jcajce.spec.OSSLKeyType.ML_KEM_768.getKsType();
        assertTyped(IllegalArgumentException.class, "invalid key type for a hybrid ML-KEM",
                () -> ni.generateKeyPair(mlkem768, TestUtil.RNDSrc));

        long spec = specNI.allocate();
        try
        {
            assertTyped(IllegalArgumentException.class, "invalid key type for a hybrid ML-KEM",
                    () -> ni.decode_publicKey(spec, mlkem768, new byte[16], 0, 16));
            assertTyped(IllegalArgumentException.class, "invalid key type for a hybrid ML-KEM",
                    () -> ni.decode_privateKey(spec, mlkem768, new byte[16], 0, 16));
        }
        finally
        {
            specNI.dispose(spec);
        }
    }

    // -----------------------------------------------------------------
    // Input arrays
    // -----------------------------------------------------------------

    /**
     * A null input array with {@code off == len == 0} — the exact combination
     * that slips past both range checks (a zero-length window into a
     * zero-length buffer is in range) and would otherwise reach a util
     * assert. A non-zero length is caught earlier by the range check, so this
     * is the case that actually exercises the null-pointer guard.
     */
    @Test
    public void nullInput_atZeroOffsetAndLength_rejectedTyped()
    {
        long spec = specNI.allocate();
        try
        {
            assertTyped(NullPointerException.class, "input is null",
                    () -> ni.decode_publicKey(spec, KS_TYPE, null, 0, 0));
            assertTyped(NullPointerException.class, "input is null",
                    () -> ni.decode_privateKey(spec, KS_TYPE, null, 0, 0));
        }
        finally
        {
            specNI.dispose(spec);
        }
    }

    /**
     * Negative offsets and lengths, singly and together. A negative jint cast
     * straight to size_t becomes huge-but-positive and passes any
     * {@code len > 0} check downstream.
     */
    @Test
    public void negativeOffsetsAndLengths_rejectedTyped()
    {
        long spec = specNI.allocate();
        try
        {
            byte[] in = new byte[16];

            assertTyped(IllegalArgumentException.class, "input offset is negative",
                    () -> ni.decode_publicKey(spec, KS_TYPE, in, -1, 16));
            assertTyped(IllegalArgumentException.class, "input offset is negative",
                    () -> ni.decode_publicKey(spec, KS_TYPE, in, Integer.MIN_VALUE, 16));
            assertTyped(IllegalArgumentException.class, "input len is negative",
                    () -> ni.decode_publicKey(spec, KS_TYPE, in, 0, -1));
            assertTyped(IllegalArgumentException.class, "input len is negative",
                    () -> ni.decode_publicKey(spec, KS_TYPE, in, 0, Integer.MIN_VALUE));
            // Both negative: the offset check fires first, and must still fire.
            assertTyped(IllegalArgumentException.class, "input offset is negative",
                    () -> ni.decode_publicKey(spec, KS_TYPE, in, -1, -1));

            assertTyped(IllegalArgumentException.class, "input offset is negative",
                    () -> ni.decode_privateKey(spec, KS_TYPE, in, -1, 16));
            assertTyped(IllegalArgumentException.class, "input len is negative",
                    () -> ni.decode_privateKey(spec, KS_TYPE, in, 0, -1));
        }
        finally
        {
            specNI.dispose(spec);
        }
    }

    /**
     * The range check, probed at exactly {@code boundary + 1} on both the
     * offset side and the length side. An arbitrary far-past-the-end value
     * would be rejected by an off-by-100 check too.
     */
    @Test
    public void offsetPlusLengthPastEnd_rejectedAtTheBoundary()
    {
        long spec = specNI.allocate();
        try
        {
            byte[] in = new byte[16];

            // 1 + 16 = 17 > 16: the offset side.
            assertTyped(IllegalArgumentException.class, "input offset + length is out of range",
                    () -> ni.decode_publicKey(spec, KS_TYPE, in, 1, 16));
            // 0 + 17 = 17 > 16: the length side.
            assertTyped(IllegalArgumentException.class, "input offset + length is out of range",
                    () -> ni.decode_publicKey(spec, KS_TYPE, in, 0, 17));
            // Offset one past the end, zero length.
            assertTyped(IllegalArgumentException.class, "input offset + length is out of range",
                    () -> ni.decode_publicKey(spec, KS_TYPE, in, 17, 0));

            assertTyped(IllegalArgumentException.class, "input offset + length is out of range",
                    () -> ni.decode_privateKey(spec, KS_TYPE, in, 1, 16));
            assertTyped(IllegalArgumentException.class, "input offset + length is out of range",
                    () -> ni.decode_privateKey(spec, KS_TYPE, in, 0, 17));
        }
        finally
        {
            specNI.dispose(spec);
        }
    }

    /**
     * The positive companion to the boundary probes: {@code off == len} at the
     * exact end of the buffer is IN range, so it must pass the bridge and be
     * refused by OpenSSL for the content instead. Without this the boundary
     * tests above could pass against a check that rejects one value too many.
     */
    @Test
    public void offsetAtExactEndWithZeroLength_passesTheRangeCheck()
    {
        long spec = specNI.allocate();
        try
        {
            byte[] in = new byte[16];
            // Not IllegalArgumentException("input offset + length is out of
            // range") — an empty share is rejected on content, deeper in.
            RuntimeException e = Assertions.assertThrows(RuntimeException.class,
                    () -> ni.decode_publicKey(spec, KS_TYPE, in, 16, 0));
            Assertions.assertNotEquals("input offset + length is out of range", e.getMessage(),
                    "off == buffer.length with len == 0 is in range and must reach the decoder");
        }
        finally
        {
            specNI.dispose(spec);
        }
    }

    // -----------------------------------------------------------------
    // Private-export canary
    // -----------------------------------------------------------------

    /**
     * Canary on the provider's split behaviour: it releases hybrid private
     * material for the X25519 / X448 groups and refuses it for the SecP ones
     * ({@code EVP_PKEY_get_octet_string_param(OSSL_PKEY_PARAM_PRIV_KEY)}
     * returns 0 without raising, measured in
     * {@code fips-c-review/probes/hybrid_kem_probe.c}).
     *
     * <p>Nothing in the JCE surface depends on either half — no key class
     * offers a private getter, precisely BECAUSE the behaviour is split — so
     * this is the only test that would notice the day OpenSSL changes it. It
     * asserts both directions, so a provider that started releasing SecP
     * material, or stopped releasing X material, fails here rather than
     * silently changing what {@code JO_HYBRID_PRIVATE_EXPORT_UNSUPPORTED}
     * means.
     */
    @Test
    public void privateExportIsRefusedOnSecPAndServedOnTheXGroups()
    {
        for (MLXKEMParameterSpec spec : MLXKEMParameterSpec.all())
        {
            long ref = ni.generateKeyPair(spec.getKeyType().getKsType(), TestUtil.RNDSrc);
            try
            {
                // The LENGTH query answers on all four groups - it asks the
                // key how big the private param would be, which the SecP
                // keymgmt still reports. Only the FETCH is refused, so the
                // probe has to fetch. Measured, not assumed: the first version
                // of this test probed the length and saw no refusal at all.
                int len = ni.getPrivateKey(ref, null);
                Assertions.assertTrue(len > 0, spec.getName() + ": expected a private length");

                byte[] out = new byte[len];
                if (spec.getName().startsWith("SecP"))
                {
                    Assertions.assertEquals(
                            "this hybrid variant does not expose its private key material",
                            Assertions.assertThrows(UnsupportedOperationException.class,
                                    () -> ni.getPrivateKey(ref, out)).getMessage(),
                            spec.getName());
                    Assertions.assertTrue(allZero(out),
                            spec.getName() + ": a refused export must leave the buffer untouched");
                }
                else
                {
                    Assertions.assertEquals(len, ni.getPrivateKey(ref, out), spec.getName());
                    Assertions.assertFalse(allZero(out), spec.getName() + ": private material is all zero");
                }
            }
            finally
            {
                specNI.dispose(ref);
            }
        }
    }

    private static boolean allZero(byte[] b)
    {
        for (byte x : b)
        {
            if (x != 0)
            {
                return false;
            }
        }
        return true;
    }

    // -----------------------------------------------------------------

    private static void assertTyped(Class<? extends RuntimeException> type, String message,
                                    org.junit.jupiter.api.function.Executable call)
    {
        Assertions.assertEquals(message, Assertions.assertThrows(type, call).getMessage());
    }
}
