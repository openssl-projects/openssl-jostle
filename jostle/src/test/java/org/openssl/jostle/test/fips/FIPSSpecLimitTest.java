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

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.openssl.jostle.jcajce.provider.OpenSSLException;
import org.openssl.jostle.jcajce.provider.cert.X509NI;
import org.openssl.jostle.jcajce.provider.fips.FIPSNISelector;
import org.openssl.jostle.jcajce.spec.OSSLKeyType;
import org.openssl.jostle.jcajce.spec.SpecNI;
import org.openssl.jostle.rand.RandSource;
import org.openssl.jostle.test.TestUtil;
import org.openssl.jostle.test.certpath.PkitsCertificates;
import org.openssl.jostle.test.spec.SpecLimitTest;

/**
 * Input validation at the key-spec NI surface of the FIPS interface library
 * ({@link FIPSNISelector#SpecNI}), mirroring {@code SpecLimitTest}.
 * <p>
 * The FIPS glue is the base bridge re-included under renamed symbols, so the
 * checks are identical by construction — this pins that they survived into the
 * other library with the same codes and the same messages. Both bridges
 * validate separately, so it runs on JNI and FFM.
 * <p>
 * Most cells reject at the BRIDGE, before any module call, so they run on both
 * supported modules. The encap/decap cells need an ML-KEM key and say so;
 * {@link #theRegistrationAgreesWithTheModule} keeps that skip honest.
 * <p>
 * Runs under the {@code integrationTest*} tasks; gated on
 * {@code TEST_FIPS_LIB}.
 */
public class FIPSSpecLimitTest
{
    private static final RandSource RND = TestUtil.RNDSrc;

    private final SpecNI ni = FIPSNISelector.SpecNI;

    private static final int KT_512 = OSSLKeyType.ML_KEM_512.getKsType();

    @BeforeAll
    public static void beforeAll()
    {
        Assumptions.assumeFalse(TestUtil.skipFipsTests(),
                "TEST_FIPS_LIB not set (full path to the FIPS module library)");
        TestUtil.addFipsProvider();
    }

    private static boolean moduleServesMlKem()
    {
        return FIPSTestUtil.moduleServesKeyMgmt("ML-KEM-768");
    }

    private static void assumeMlKem()
    {
        Assumptions.assumeTrue(moduleServesMlKem(),
                "the loaded FIPS module implements no ML-KEM (3.1.2)");
    }

    /** An ML-KEM keypair handle in the FIPS library. Caller disposes. */
    private long mlKemKey()
    {
        return FIPSNISelector.MLKEMServiceNI.generateKeyPair(KT_512, RND);
    }

    @Test
    public void theRegistrationAgreesWithTheModule()
    {
        boolean registered = FIPSTestUtil.assumeFipsProvider()
                .getService("KeyPairGenerator", "ML-KEM-768") != null;
        Assertions.assertEquals(moduleServesMlKem(), registered,
                "the module and JSLFIPS disagree about ML-KEM: module says "
                        + moduleServesMlKem() + ", provider says " + registered);
    }

    // -----------------------------------------------------------------
    // allocate. A null or zero-length err array skips the write and returns a
    // usable, disposable handle — no abort, no ArrayIndexOutOfBoundsException
    // stranding the freshly allocated key_spec. The zero-length case is the
    // one native-code.md names as CORRUPTING rather than aborting, because
    // GetIntArrayElements answers a valid pointer for it, so the length is
    // checked before the pointer is taken.
    // -----------------------------------------------------------------
    @Test
    public void allocate_nullErr_noAbort()
    {
        long ref = ni.ni_allocate(null);
        Assertions.assertTrue(ref != 0L, "allocate returned a null handle");
        ni.ni_dispose(ref);
    }

    @Test
    public void allocate_zeroLenErr_noAbortNoLeak()
    {
        long ref = ni.ni_allocate(new int[0]);
        Assertions.assertTrue(ref != 0L, "allocate returned a null handle");
        ni.ni_dispose(ref);
    }

    @Test
    public void allocate_writesTheSuccessCode()
    {
        int[] err = new int[1];
        long ref = ni.ni_allocate(err);
        try
        {
            Assertions.assertTrue(ref > 0, "allocate returned no handle");
            Assertions.assertEquals(0, err[0], "allocate did not write the success code");
        }
        finally
        {
            ni.dispose(ref);
        }
    }

    // -----------------------------------------------------------------
    // getName / getKeyProvider
    // -----------------------------------------------------------------

    /** An unusable handle answers null here — measured, not a throw. */
    @Test
    public void getName_unusableHandles_answerNull()
    {
        Assertions.assertNull(ni.getName(0));

        long ref = ni.allocate();
        try
        {
            Assertions.assertNull(ni.getName(ref));
        }
        finally
        {
            ni.dispose(ref);
        }
    }

    @Test
    public void getName_realKey_namesTheParameterSet()
    {
        assumeMlKem();
        long ref = mlKemKey();
        try
        {
            Assertions.assertEquals("ML-KEM-512", ni.getName(ref));
        }
        finally
        {
            ni.dispose(ref);
        }
    }

    /** A handle with no key answers null rather than throwing or aborting. */
    @Test
    public void getKeyProvider_unusableHandles_answerNull()
    {
        Assertions.assertNull(ni.ni_getKeyProvider(0));

        long ref = ni.allocate();
        try
        {
            Assertions.assertNull(ni.ni_getKeyProvider(ref));
        }
        finally
        {
            ni.dispose(ref);
        }
    }

    /**
     * The residency check {@code FIPSModuleIsActuallyUsedTest} relies on: a key
     * made by this library must report the FIPS provider, not "default".
     * Asserting merely non-null would pass while the work happened in mainline.
     */
    @Test
    public void getKeyProvider_realKey_namesTheFipsProvider()
    {
        assumeMlKem();
        long ref = mlKemKey();
        try
        {
            Assertions.assertEquals("fips", ni.ni_getKeyProvider(ref),
                    "a JSLFIPS-generated key is not resident in the module");
        }
        finally
        {
            ni.dispose(ref);
        }
    }

    // -----------------------------------------------------------------
    // encap
    // -----------------------------------------------------------------

    @Test
    public void encap_unusableKeySpecHandles_rejectedTyped()
    {
        assertTyped(IllegalArgumentException.class, "key spec is null",
                () -> ni.encap(0, null, new byte[32], 0, 32, new byte[1024], 0, 1024, RND));

        long ref = ni.allocate();
        try
        {
            assertTyped(IllegalArgumentException.class, "key spec has null key",
                    () -> ni.encap(ref, null, new byte[32], 0, 32, new byte[1024], 0, 1024, RND));
        }
        finally
        {
            ni.dispose(ref);
        }
    }

    @Test
    public void encapSecretLength_unusableKeySpecHandles_rejectedTyped()
    {
        assertTyped(IllegalArgumentException.class, "key spec is null",
                () -> ni.encapSecretLength(0, null, RND));

        long ref = ni.allocate();
        try
        {
            assertTyped(IllegalArgumentException.class, "key spec has null key",
                    () -> ni.encapSecretLength(ref, null, RND));
        }
        finally
        {
            ni.dispose(ref);
        }
    }

    @Test
    public void encapSecretLength_nullRandSrc_rejectedTyped()
    {
        assumeMlKem();
        long ref = mlKemKey();
        try
        {
            assertTyped(IllegalArgumentException.class, "supplied random source was null",
                    () -> ni.encapSecretLength(ref, null, null));
        }
        finally
        {
            ni.dispose(ref);
        }
    }

    /**
     * The query answers the shared secret's length: a secret window of exactly that length is accepted, one
     * byte less is refused.
     */
    @Test
    public void encapSecretLength_isTheSmallestWindowEncapAccepts()
    {
        assumeMlKem();
        long ref = mlKemKey();
        try
        {
            int secretLen = ni.encapSecretLength(ref, null, RND);
            Assertions.assertEquals(32, secretLen);
            int encLen = ni.encap(ref, null, new byte[secretLen], 0, secretLen, null, 0, 0, RND);
            Assertions.assertEquals(encLen, ni.encap(ref, null, new byte[secretLen], 0, secretLen,
                    new byte[encLen], 0, encLen, RND));
            assertTyped(IllegalArgumentException.class, "output too small",
                    () -> ni.encap(ref, null, new byte[secretLen - 1], 0, secretLen - 1, new byte[encLen], 0,
                            encLen, RND));
        }
        finally
        {
            ni.dispose(ref);
        }
    }

    @Test
    public void encap_nullBuffers_rejectedTyped()
    {
        assumeMlKem();
        long ref = mlKemKey();
        try
        {
            // A null array with off == len == 0 passes both range checks, so
            // only an explicit null check catches it.
            assertTyped(NullPointerException.class, "input is null",
                    () -> ni.encap(ref, null, null, 0, 0, new byte[1024], 0, 1024, RND));
        }
        finally
        {
            ni.dispose(ref);
        }
    }

    @Test
    public void encap_negativeOffsetsAndLengths_rejectedTyped()
    {
        assumeMlKem();
        long ref = mlKemKey();
        try
        {
            byte[] secret = new byte[32];
            byte[] out = new byte[1024];
            assertTyped(IllegalArgumentException.class, "input offset is negative",
                    () -> ni.encap(ref, null, secret, -1, 32, out, 0, 1024, RND));
            assertTyped(IllegalArgumentException.class, "input offset is negative",
                    () -> ni.encap(ref, null, secret, Integer.MIN_VALUE, 32, out, 0, 1024, RND));
            assertTyped(IllegalArgumentException.class, "input len is negative",
                    () -> ni.encap(ref, null, secret, 0, -1, out, 0, 1024, RND));
            assertTyped(IllegalArgumentException.class, "output offset is negative",
                    () -> ni.encap(ref, null, secret, 0, 32, out, -1, 1024, RND));
            assertTyped(IllegalArgumentException.class, "output len negative",
                    () -> ni.encap(ref, null, secret, 0, 32, out, 0, -1, RND));
        }
        finally
        {
            ni.dispose(ref);
        }
    }

    @Test
    public void encap_rangesPastEnd_rejectedAtTheBoundary()
    {
        assumeMlKem();
        long ref = mlKemKey();
        try
        {
            byte[] secret = new byte[32];
            byte[] out = new byte[1024];
            assertTyped(IllegalArgumentException.class, "input offset + length is out of range",
                    () -> ni.encap(ref, null, secret, 1, 32, out, 0, 1024, RND));
            assertTyped(IllegalArgumentException.class, "input offset + length is out of range",
                    () -> ni.encap(ref, null, secret, 0, 33, out, 0, 1024, RND));
            assertTyped(IllegalArgumentException.class, "output offset + length is out of range",
                    () -> ni.encap(ref, null, secret, 0, 32, out, 1, 1024, RND));
            assertTyped(IllegalArgumentException.class, "output offset + length is out of range",
                    () -> ni.encap(ref, null, secret, 0, 32, out, 0, 1025, RND));
        }
        finally
        {
            ni.dispose(ref);
        }
    }

    @Test
    public void encap_nullRandSource_rejectedTyped()
    {
        assumeMlKem();
        long ref = mlKemKey();
        try
        {
            assertTyped(IllegalArgumentException.class, "supplied random source was null",
                    () -> ni.encap(ref, null, new byte[32], 0, 32, new byte[1024], 0, 1024, null));
        }
        finally
        {
            ni.dispose(ref);
        }
    }

    /** Aliasing the two buffers is refused rather than silently corrupting. */
    @Test
    public void encap_inputAndOutputAliased_rejectedTyped()
    {
        assumeMlKem();
        long ref = mlKemKey();
        try
        {
            byte[] shared = new byte[2048];
            assertTyped(IllegalArgumentException.class, "input and output must not be the same array",
                    () -> ni.encap(ref, null, shared, 0, 32, shared, 0, 2048, RND));
        }
        finally
        {
            ni.dispose(ref);
        }
    }

    // -----------------------------------------------------------------
    // decap
    // -----------------------------------------------------------------

    @Test
    public void decap_unusableKeySpecHandles_rejectedTyped()
    {
        assertTyped(IllegalArgumentException.class, "key spec is null",
                () -> ni.decap(0, null, new byte[800], 0, 800, new byte[32], 0, 32, RND));

        long ref = ni.allocate();
        try
        {
            assertTyped(IllegalArgumentException.class, "key spec has null key",
                    () -> ni.decap(ref, null, new byte[800], 0, 800, new byte[32], 0, 32, RND));
        }
        finally
        {
            ni.dispose(ref);
        }
    }

    @Test
    public void decap_nullBuffers_rejectedTyped()
    {
        assumeMlKem();
        long ref = mlKemKey();
        try
        {
            assertTyped(NullPointerException.class, "input is null",
                    () -> ni.decap(ref, null, null, 0, 0, new byte[32], 0, 32, RND));
        }
        finally
        {
            ni.dispose(ref);
        }
    }

    @Test
    public void decap_negativeOffsetsAndLengths_rejectedTyped()
    {
        assumeMlKem();
        long ref = mlKemKey();
        try
        {
            byte[] in = new byte[800];
            byte[] out = new byte[32];
            assertTyped(IllegalArgumentException.class, "input offset is negative",
                    () -> ni.decap(ref, null, in, -1, 800, out, 0, 32, RND));
            assertTyped(IllegalArgumentException.class, "input len is negative",
                    () -> ni.decap(ref, null, in, 0, -1, out, 0, 32, RND));
            assertTyped(IllegalArgumentException.class, "output offset is negative",
                    () -> ni.decap(ref, null, in, 0, 800, out, -1, 32, RND));
            assertTyped(IllegalArgumentException.class, "output len negative",
                    () -> ni.decap(ref, null, in, 0, 800, out, 0, -1, RND));
        }
        finally
        {
            ni.dispose(ref);
        }
    }

    @Test
    public void decap_rangesPastEnd_rejectedAtTheBoundary()
    {
        assumeMlKem();
        long ref = mlKemKey();
        try
        {
            byte[] in = new byte[800];
            byte[] out = new byte[32];
            assertTyped(IllegalArgumentException.class, "input offset + length is out of range",
                    () -> ni.decap(ref, null, in, 1, 800, out, 0, 32, RND));
            assertTyped(IllegalArgumentException.class, "input offset + length is out of range",
                    () -> ni.decap(ref, null, in, 0, 801, out, 0, 32, RND));
            assertTyped(IllegalArgumentException.class, "output offset + length is out of range",
                    () -> ni.decap(ref, null, in, 0, 800, out, 1, 32, RND));
            assertTyped(IllegalArgumentException.class, "output offset + length is out of range",
                    () -> ni.decap(ref, null, in, 0, 800, out, 0, 33, RND));
        }
        finally
        {
            ni.dispose(ref);
        }
    }

    @Test
    public void decap_nullRandSource_rejectedTyped()
    {
        assumeMlKem();
        long ref = mlKemKey();
        try
        {
            assertTyped(IllegalArgumentException.class, "supplied random source was null",
                    () -> ni.decap(ref, null, new byte[800], 0, 800, new byte[32], 0, 32, null));
        }
        finally
        {
            ni.dispose(ref);
        }
    }

    @Test
    public void decap_inputAndOutputAliased_rejectedTyped()
    {
        assumeMlKem();
        long ref = mlKemKey();
        try
        {
            byte[] shared = new byte[2048];
            assertTyped(IllegalArgumentException.class, "input and output must not be the same array",
                    () -> ni.decap(ref, null, shared, 0, 800, shared, 900, 32, RND));
        }
        finally
        {
            ni.dispose(ref);
        }
    }

    /**
     * The positive control for every refusal above: a real encap/decap round
     * trip through the FIPS library recovers the same secret, so the cells are
     * proven to refuse only what they should.
     */
    @Test
    public void encapDecapRoundTripSucceeds()
    {
        assumeMlKem();
        long ref = mlKemKey();
        try
        {
            int encLen = ni.encap(ref, null, new byte[32], 0, 32, null, 0, 0, RND);
            Assertions.assertTrue(encLen > 0, "the encapsulation size query must answer");

            byte[] secret = new byte[32];
            byte[] enc = new byte[encLen];
            Assertions.assertTrue(ni.encap(ref, null, secret, 0, 32, enc, 0, enc.length, RND) >= 0);

            byte[] recovered = new byte[32];
            Assertions.assertTrue(
                    ni.decap(ref, null, enc, 0, enc.length, recovered, 0, 32, RND) >= 0);
            Assertions.assertArrayEquals(secret, recovered,
                    "decapsulation recovered a different secret");
        }
        finally
        {
            ni.dispose(ref);
        }
    }

    /** An RSA-2048 keypair handle in the FIPS library, for RSASVE, which both modules serve. Caller disposes. */
    private long rsaKey()
    {
        long ref = FIPSNISelector.RSAServiceNI.generateKeyPair(2048, new byte[]{1, 0, 1}, RND);
        Assertions.assertTrue(ref > 0);
        return ref;
    }

    @Test
    public void aliasedArrays_refusedBeforeTheHandle()
    {
        long keyless = ni.allocate();
        try
        {
            for (long handle : new long[]{0, keyless})
            {
                byte[] shared = new byte[2048];
                assertTyped(IllegalArgumentException.class, "input and output must not be the same array",
                        () -> ni.encap(handle, null, shared, 0, 32, shared, 32, 1024, RND));
                assertTyped(IllegalArgumentException.class, "input and output must not be the same array",
                        () -> ni.decap(handle, null, shared, 0, 768, shared, 1024, 32, RND));
                assertTyped(IllegalArgumentException.class, handle == 0 ? "key spec is null" : "key spec has null key",
                        () -> ni.encap(handle, null, new byte[32], 0, 32, new byte[1024], 0, 1024, RND));
            }
        }
        finally
        {
            ni.dispose(keyless);
        }
    }

    @Test
    public void wrongKindHandle_refused() throws Exception
    {
        X509NI x509NI = FIPSNISelector.X509NI;
        byte[] der = PkitsCertificates.der("GoodCACert.crt");
        long cert = x509NI.allocate(der, 0, der.length, der.length, new int[1]);
        Assertions.assertTrue(cert != 0);
        try
        {
            assertTyped(IllegalArgumentException.class, "handle is not a key spec",
                    () -> ni.encap(cert, null, new byte[32], 0, 32, new byte[1024], 0, 1024, RND));
            assertTyped(IllegalArgumentException.class, "handle is not a key spec",
                    () -> ni.decap(cert, null, new byte[768], 0, 768, new byte[32], 0, 32, RND));
            assertTyped(IllegalArgumentException.class, "handle is not a key spec",
                    () -> ni.encapSecretLength(cert, null, RND));
            Assertions.assertNull(ni.getName(cert));
            Assertions.assertNull(ni.getKeyProvider(cert));

            // Dispose frees nothing on the wrong kind: the certificate still answers afterwards.
            ni.dispose(cert);
            Assertions.assertTrue(x509NI.fieldsLen(cert) > 0);
        }
        finally
        {
            x509NI.dispose(cert);
        }
    }

    /** Every KEM key type the module serves; a type it does not serve is recorded, not skipped silently. */
    @Test
    public void kemSizeQueries_matchTheSpecification()
    {
        int measured = 0;
        StringBuilder unserved = new StringBuilder();
        for (OSSLKeyType type : new OSSLKeyType[]{OSSLKeyType.ML_KEM_512, OSSLKeyType.ML_KEM_768,
                OSSLKeyType.ML_KEM_1024, OSSLKeyType.X25519MLKEM768, OSSLKeyType.X448MLKEM1024,
                OSSLKeyType.SecP256r1MLKEM768, OSSLKeyType.SecP384r1MLKEM1024})
        {
            boolean hybrid = type.name().contains("MLKEM");
            String keyMgmt = hybrid ? type.name() : type.name().replace('_', '-');
            if (!FIPSTestUtil.moduleServesKeyMgmt(keyMgmt))
            {
                unserved.append(' ').append(keyMgmt);
                continue;
            }
            long key = hybrid
                    ? FIPSNISelector.MLXKEMServiceNI.generateKeyPair(type.getKsType(), RND)
                    : FIPSNISelector.MLKEMServiceNI.generateKeyPair(type.getKsType(), RND);
            try
            {
                SpecLimitTest.assertSizes(ni, key, type, null, RND);
                measured++;
            }
            finally
            {
                ni.dispose(key);
            }
        }
        System.out.println("[kem sizes] measured=" + measured + " unserved:" + unserved);
        Assertions.assertEquals(moduleServesMlKem(), measured > 0,
                "ML-KEM served by the module must be measured here");
    }

    @Test
    public void decap_wrongLengthCiphertext_mlKem()
    {
        assumeMlKem();
        long ref = mlKemKey();
        try
        {
            SpecLimitTest.assertWrongLengthRefused(ni, ref, null, 768, 32, RND);
        }
        finally
        {
            ni.dispose(ref);
        }
    }

    @Test
    public void decap_wrongLengthCiphertext_rsasve()
    {
        long ref = rsaKey();
        try
        {
            SpecLimitTest.assertWrongLengthRefused(ni, ref, "RSASVE", 256, 256, RND);
        }
        finally
        {
            ni.dispose(ref);
        }
    }

    @Test
    public void encap_zeroLengthSecretWindow_tooSmall()
    {
        long ref = rsaKey();
        try
        {
            assertTyped(IllegalArgumentException.class, "output too small",
                    () -> ni.encap(ref, "RSASVE", new byte[0], 0, 0, new byte[256], 0, 256, RND));
        }
        finally
        {
            ni.dispose(ref);
        }
    }

    @Test
    public void decap_zeroLengthCiphertext_refusedByTheLibrary()
    {
        long ref = rsaKey();
        try
        {
            OpenSSLException e = Assertions.assertThrows(OpenSSLException.class,
                    () -> ni.decap(ref, "RSASVE", new byte[0], 0, 0, new byte[256], 0, 256, RND));
            Assertions.assertTrue(e.getMessage().startsWith("OpenSSL Error:"), e.getMessage());
        }
        finally
        {
            ni.dispose(ref);
        }
    }

    private static void assertTyped(Class<? extends RuntimeException> type, String message,
                                    Executable call)
    {
        Assertions.assertEquals(message, Assertions.assertThrows(type, call).getMessage());
    }
}
