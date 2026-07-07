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
import org.openssl.jostle.jcajce.provider.ErrorCode;
import org.openssl.jostle.jcajce.provider.fips.FIPSNISelector;
import org.openssl.jostle.jcajce.provider.rsa.RSAServiceNI;
import org.openssl.jostle.jcajce.spec.SpecNI;
import org.openssl.jostle.rand.RandSource;
import org.openssl.jostle.test.TestUtil;

import java.security.SecureRandom;

/**
 * Input-validation limit tests at the FIPS RSA signing NI surface
 * ({@link FIPSNISelector#RSAServiceNI}). The FIPS JNI glue is the base
 * rsa_ni_jni.c re-included under renamed symbols, so the bridge's
 * null/range/negative/state checks and typed-error mapping are identical by
 * construction — this pins that they survived into the FIPS interface library
 * with the same messages. Mirrors the base {@code RSALimitTest}.
 *
 * <p>FIPS notes: keygen uses 2048 (the FIPS module floor — 1024 fails inside
 * the module). The {@code RandSource} parameter is still null-checked by the
 * bridge (see the null-rand tests), but the FIPS entropy path never consults
 * it — {@link TestUtil#RNDSrc} is supplied only to satisfy that null-check.
 *
 * <p>Runs under the {@code integrationTest*} tasks; gated on
 * {@code TEST_FIPS_LIB} (whole class skips when unset). Discipline (testing.md):
 * exact-message assertions, {@code Integer.MIN_VALUE} alongside {@code -1} on
 * int offsets/lengths, range checks at {@code boundary + 1}, and functional
 * offset-write verification (prefix untouched, output verifies, shifted-window
 * does not).
 */
public class FIPSRSAServiceLimitTest
{
    private static final byte[] PUB_EXP_F4 = {0x01, 0x00, 0x01};
    private static final RandSource RND = TestUtil.RNDSrc;

    @BeforeAll
    public static void beforeAll()
    {
        Assumptions.assumeFalse(TestUtil.skipFipsTests(),
                "TEST_FIPS_LIB not set (full path to the FIPS module library)");
        TestUtil.addFipsProvider();
    }

    private final RSAServiceNI rsaServiceNI = FIPSNISelector.RSAServiceNI;
    private final SpecNI specNI = FIPSNISelector.SpecNI;

    // -----------------------------------------------------------------
    // generateKeyPair
    // -----------------------------------------------------------------

    @Test
    public void generateKeyPair_nullPubExp()
    {
        assertNPE("public exponent is null",
                () -> rsaServiceNI.generateKeyPair(2048, null, RND));
    }

    @Test
    public void generateKeyPair_emptyPubExp()
    {
        // A non-null but empty pubexp surfaces as the same null-pubexp code
        // (must never jo_assert on user input).
        assertNPE("public exponent is null",
                () -> rsaServiceNI.generateKeyPair(2048, new byte[0], RND));
    }

    @Test
    public void generateKeyPair_nullRand()
    {
        assertIAE("supplied random source was null",
                () -> rsaServiceNI.generateKeyPair(2048, PUB_EXP_F4, null));
    }

    // -----------------------------------------------------------------
    // decodePublicComponents
    // -----------------------------------------------------------------

    @Test
    public void decodePublicComponents_nullSpec()
    {
        assertIAE("key spec is null",
                () -> rsaServiceNI.decodePublicComponents(0, new byte[]{0x01}, PUB_EXP_F4));
    }

    @Test
    public void decodePublicComponents_nullN()
    {
        withSpec(keyRef -> assertNPE("modulus is null",
                () -> rsaServiceNI.decodePublicComponents(keyRef, null, PUB_EXP_F4)));
    }

    @Test
    public void decodePublicComponents_nullE()
    {
        withSpec(keyRef -> assertNPE("public exponent is null",
                () -> rsaServiceNI.decodePublicComponents(keyRef, new byte[]{0x01}, null)));
    }

    // -----------------------------------------------------------------
    // decodePrivateComponents
    // -----------------------------------------------------------------

    @Test
    public void decodePrivateComponents_nullSpec()
    {
        assertIAE("key spec is null",
                () -> rsaServiceNI.decodePrivateComponents(0, new byte[]{0x01}, PUB_EXP_F4, new byte[]{0x01}));
    }

    @Test
    public void decodePrivateComponents_nullN()
    {
        withSpec(keyRef -> assertNPE("modulus is null",
                () -> rsaServiceNI.decodePrivateComponents(keyRef, null, PUB_EXP_F4, new byte[]{0x01})));
    }

    @Test
    public void decodePrivateComponents_nullE()
    {
        withSpec(keyRef -> assertNPE("public exponent is null",
                () -> rsaServiceNI.decodePrivateComponents(keyRef, new byte[]{0x01}, null, new byte[]{0x01})));
    }

    @Test
    public void decodePrivateComponents_nullD()
    {
        withSpec(keyRef -> assertNPE("private exponent is null",
                () -> rsaServiceNI.decodePrivateComponents(keyRef, new byte[]{0x01}, PUB_EXP_F4, null)));
    }

    // -----------------------------------------------------------------
    // decodePrivateComponentsCrt
    // -----------------------------------------------------------------

    @Test
    public void decodePrivateComponentsCrt_nullSpec()
    {
        byte[] one = {0x01};
        assertIAE("key spec is null",
                () -> rsaServiceNI.decodePrivateComponentsCrt(0, one, PUB_EXP_F4, one, one, one, one, one, one));
    }

    @Test
    public void decodePrivateComponentsCrt_anyNull()
    {
        // Each component slot has its own dedicated error code.
        byte[] one = {0x01};
        String[] expectedMsg = {
                "modulus is null",            // 0: n
                "public exponent is null",    // 1: e
                "private exponent is null",   // 2: d
                "prime P is null",            // 3: p
                "prime Q is null",            // 4: q
                "prime exponent P is null",   // 5: dp
                "prime exponent Q is null",   // 6: dq
                "CRT coefficient is null"     // 7: qinv
        };
        for (int nullIdx = 0; nullIdx < 8; nullIdx++)
        {
            final int idx = nullIdx;
            withSpec(keyRef -> assertNPE(expectedMsg[idx],
                    () -> rsaServiceNI.decodePrivateComponentsCrt(keyRef,
                            idx == 0 ? null : one,
                            idx == 1 ? null : PUB_EXP_F4,
                            idx == 2 ? null : one,
                            idx == 3 ? null : one,
                            idx == 4 ? null : one,
                            idx == 5 ? null : one,
                            idx == 6 ? null : one,
                            idx == 7 ? null : one)));
        }
    }

    // -----------------------------------------------------------------
    // getComponent
    // -----------------------------------------------------------------

    @Test
    public void getComponent_nullSpec()
    {
        assertIAE("key spec is null",
                () -> rsaServiceNI.getComponent(0, RSAServiceNI.COMP_MODULUS, null));
    }

    @Test
    public void getComponent_specHasNullKey()
    {
        withSpec(keyRef -> assertIAE("key spec has null key",
                () -> rsaServiceNI.getComponent(keyRef, RSAServiceNI.COMP_MODULUS, null)));
    }

    @Test
    public void getComponent_outputTooSmall()
    {
        long keyRef = genKey();
        try
        {
            int needed = rsaServiceNI.getComponent(keyRef, RSAServiceNI.COMP_MODULUS, null);
            Assertions.assertTrue(needed > 0);
            assertIAE("output too small",
                    () -> rsaServiceNI.getComponent(keyRef, RSAServiceNI.COMP_MODULUS, new byte[needed - 1]));
        }
        finally
        {
            specNI.dispose(keyRef);
        }
    }

    // -----------------------------------------------------------------
    // initSign / initVerify
    // -----------------------------------------------------------------

    @Test
    public void initSign_nullKey()
    {
        long rsaRef = rsaServiceNI.allocateSigner();
        try
        {
            assertIAE("key spec is null", () -> rsaServiceNI.initSign(rsaRef, 0, "SHA-256",
                    RSAServiceNI.PADDING_PKCS1, null, 0, RND));
        }
        finally
        {
            rsaServiceNI.disposeSigner(rsaRef);
        }
    }

    @Test
    public void initSign_nullDigestName()
    {
        withSignerAndKey((rsaRef, keyRef) -> assertNPE("name is null",
                () -> rsaServiceNI.initSign(rsaRef, keyRef, null, RSAServiceNI.PADDING_PKCS1, null, 0, RND)));
    }

    @Test
    public void initSign_nullRand()
    {
        withSignerAndKey((rsaRef, keyRef) -> assertIAE("supplied random source was null",
                () -> rsaServiceNI.initSign(rsaRef, keyRef, "SHA-256", RSAServiceNI.PADDING_PKCS1, null, 0, null)));
    }

    @Test
    public void initVerify_nullKey()
    {
        long rsaRef = rsaServiceNI.allocateSigner();
        try
        {
            assertIAE("key spec is null", () -> rsaServiceNI.initVerify(rsaRef, 0, "SHA-256",
                    RSAServiceNI.PADDING_PKCS1, null, 0));
        }
        finally
        {
            rsaServiceNI.disposeSigner(rsaRef);
        }
    }

    @Test
    public void initVerify_nullDigestName()
    {
        withSignerAndKey((rsaRef, keyRef) -> assertNPE("name is null",
                () -> rsaServiceNI.initVerify(rsaRef, keyRef, null, RSAServiceNI.PADDING_PKCS1, null, 0)));
    }

    // -----------------------------------------------------------------
    // update (offset / length: -1, MIN_VALUE, combinations, boundary+1)
    // -----------------------------------------------------------------

    @Test
    public void update_nullInput()
    {
        withInitedSigner((rsaRef, keyRef) -> assertNPE("input is null",
                () -> rsaServiceNI.update(rsaRef, null, 0, 0)));
    }

    @Test
    public void update_offsetNegative()
    {
        withInitedSigner((rsaRef, keyRef) ->
        {
            for (int off : new int[]{-1, Integer.MIN_VALUE})
            {
                assertIAE("input offset is negative",
                        () -> rsaServiceNI.update(rsaRef, new byte[16], off, 0));
            }
        });
    }

    @Test
    public void update_lenNegative()
    {
        withInitedSigner((rsaRef, keyRef) ->
        {
            for (int len : new int[]{-1, Integer.MIN_VALUE})
            {
                assertIAE("input len is negative",
                        () -> rsaServiceNI.update(rsaRef, new byte[16], 0, len));
            }
        });
    }

    @Test
    public void update_negativeOffsetWithValidLen()
    {
        // Negative off + valid len: only an explicit off<0 guard catches this.
        withInitedSigner((rsaRef, keyRef) -> assertIAE("input offset is negative",
                () -> rsaServiceNI.update(rsaRef, new byte[16], -1, 8)));
    }

    @Test
    public void update_outOfRange_boundaryPlusOne()
    {
        withInitedSigner((rsaRef, keyRef) ->
        {
            // off + len = 1 + 10 > 10, and 0 + 11 > 10.
            assertIAE("input offset + length is out of range",
                    () -> rsaServiceNI.update(rsaRef, new byte[10], 1, 10));
            assertIAE("input offset + length is out of range",
                    () -> rsaServiceNI.update(rsaRef, new byte[10], 0, 11));
        });
    }

    // -----------------------------------------------------------------
    // sign
    // -----------------------------------------------------------------

    @Test
    public void sign_nullRand()
    {
        withInitedSigner((rsaRef, keyRef) -> assertIAE("supplied random source was null",
                () -> rsaServiceNI.sign(rsaRef, new byte[256], 0, null)));
    }

    @Test
    public void sign_offsetNegative()
    {
        withInitedSigner((rsaRef, keyRef) ->
        {
            for (int off : new int[]{-1, Integer.MIN_VALUE})
            {
                assertIAE("output offset is negative",
                        () -> rsaServiceNI.sign(rsaRef, new byte[256], off, RND));
            }
        });
    }

    @Test
    public void sign_offsetPastEnd()
    {
        // offset == size+1 → past end.
        withInitedSigner((rsaRef, keyRef) -> assertIAE("output offset + length is out of range",
                () -> rsaServiceNI.sign(rsaRef, new byte[10], 11, RND)));
    }

    @Test
    public void sign_outputTooSmall()
    {
        withInitedSigner((rsaRef, keyRef) ->
        {
            int needed = rsaServiceNI.sign(rsaRef, null, 0, RND);
            Assertions.assertTrue(needed > 0);
            assertIAE("output too small",
                    () -> rsaServiceNI.sign(rsaRef, new byte[needed - 1], 0, RND));
        });
    }

    @Test
    public void sign_notInitialized()
    {
        long rsaRef = rsaServiceNI.allocateSigner();
        try
        {
            assertISE("not initialized", () -> rsaServiceNI.sign(rsaRef, new byte[256], 0, RND));
        }
        finally
        {
            rsaServiceNI.disposeSigner(rsaRef);
        }
    }

    @Test
    public void sign_initForVerify()
    {
        withSignerAndKey((rsaRef, keyRef) ->
        {
            rsaServiceNI.initVerify(rsaRef, keyRef, "SHA-256", RSAServiceNI.PADDING_PKCS1, null, 0);
            assertISE("unexpected state", () -> rsaServiceNI.sign(rsaRef, new byte[256], 0, RND));
        });
    }

    // -----------------------------------------------------------------
    // verify
    // -----------------------------------------------------------------

    @Test
    public void verify_nullSig()
    {
        withInitedVerifier((rsaRef, keyRef) -> assertIAE("sig is null",
                () -> rsaServiceNI.verify(rsaRef, null, 0)));
    }

    @Test
    public void verify_sigLenNegative()
    {
        withInitedVerifier((rsaRef, keyRef) ->
        {
            for (int len : new int[]{-1, Integer.MIN_VALUE})
            {
                assertIAE("sig length is negative",
                        () -> rsaServiceNI.verify(rsaRef, new byte[1], len));
            }
        });
    }

    @Test
    public void verify_sigLenZero()
    {
        // sigLen=0 against a 1-byte buffer is a legitimate "doesn't verify".
        withInitedVerifier((rsaRef, keyRef) ->
                Assertions.assertEquals(ErrorCode.JO_FAIL.getCode(),
                        rsaServiceNI.verify(rsaRef, new byte[1], 0)));
    }

    @Test
    public void verify_sigOutOfRange_offsetEdge()
    {
        withInitedVerifier((rsaRef, keyRef) -> assertIAE("sig out of range",
                () -> rsaServiceNI.verify(rsaRef, new byte[10], 11)));
    }

    @Test
    public void verify_sigOutOfRange_emptyBuf()
    {
        withInitedVerifier((rsaRef, keyRef) -> assertIAE("sig out of range",
                () -> rsaServiceNI.verify(rsaRef, new byte[0], 1)));
    }

    @Test
    public void verify_notInitialized()
    {
        long rsaRef = rsaServiceNI.allocateSigner();
        try
        {
            assertISE("not initialized", () -> rsaServiceNI.verify(rsaRef, new byte[1], 1));
        }
        finally
        {
            rsaServiceNI.disposeSigner(rsaRef);
        }
    }

    @Test
    public void verify_initForSign()
    {
        withSignerAndKey((rsaRef, keyRef) ->
        {
            rsaServiceNI.initSign(rsaRef, keyRef, "SHA-256", RSAServiceNI.PADDING_PKCS1, null, 0, RND);
            assertISE("unexpected state", () -> rsaServiceNI.verify(rsaRef, new byte[1], 1));
        });
    }

    // -----------------------------------------------------------------
    // NI-direct happy-path coverage (non-JCE entry points)
    // -----------------------------------------------------------------

    @Test
    public void decodePrivateComponents_roundTrip()
    {
        // Round-trip the no-CRT private decode path (JCE rejects bare
        // RSAPrivateKeySpec; NI callers can supply n, e, d directly).
        long src = 0;
        long noCrt = 0;
        long signer = 0;
        try
        {
            src = genKey();
            byte[] n = fetchComponent(src, RSAServiceNI.COMP_MODULUS);
            byte[] e = fetchComponent(src, RSAServiceNI.COMP_PUBLIC_EXPONENT);
            byte[] d = fetchComponent(src, RSAServiceNI.COMP_PRIVATE_EXPONENT);

            noCrt = specNI.allocate();
            Assertions.assertTrue(noCrt > 0);
            Assertions.assertEquals(0, rsaServiceNI.decodePrivateComponents(noCrt, n, e, d),
                    "non-CRT decode should succeed");

            signer = rsaServiceNI.allocateSigner();
            rsaServiceNI.initSign(signer, noCrt, "SHA-256", RSAServiceNI.PADDING_PKCS1, null, 0, RND);
            rsaServiceNI.update(signer, new byte[]{1, 2, 3}, 0, 3);
            int needed = rsaServiceNI.sign(signer, null, 0, RND);
            byte[] sig = new byte[needed];
            Assertions.assertEquals(needed, rsaServiceNI.sign(signer, sig, 0, RND));
        }
        finally
        {
            rsaServiceNI.disposeSigner(signer);
            specNI.dispose(noCrt);
            specNI.dispose(src);
        }
    }

    @Test
    public void sign_writesAtOffsetWithoutClobberingPrefix()
    {
        long signRef = 0;
        long verifyRef = 0;
        long keyRef = 0;
        try
        {
            signRef = rsaServiceNI.allocateSigner();
            verifyRef = rsaServiceNI.allocateSigner();
            keyRef = genKey();
            byte[] msg = {1, 2, 3};

            rsaServiceNI.initSign(signRef, keyRef, "SHA-256", RSAServiceNI.PADDING_PKCS1, null, 0, RND);
            rsaServiceNI.update(signRef, msg, 0, msg.length);
            int needed = rsaServiceNI.sign(signRef, null, 0, RND);
            Assertions.assertEquals(256, needed);

            int prefix = 7;
            byte[] big = new byte[needed + prefix];
            new SecureRandom().nextBytes(big);
            byte[] expectedPrefix = new byte[prefix];
            System.arraycopy(big, 0, expectedPrefix, 0, prefix);

            Assertions.assertEquals(needed, rsaServiceNI.sign(signRef, big, prefix, RND));

            // (1) prefix untouched.
            byte[] actualPrefix = new byte[prefix];
            System.arraycopy(big, 0, actualPrefix, 0, prefix);
            Assertions.assertArrayEquals(expectedPrefix, actualPrefix, "prefix bytes were modified");

            // (2) signature at big[prefix..] verifies.
            byte[] sig = new byte[needed];
            System.arraycopy(big, prefix, sig, 0, needed);
            rsaServiceNI.initVerify(verifyRef, keyRef, "SHA-256", RSAServiceNI.PADDING_PKCS1, null, 0);
            rsaServiceNI.update(verifyRef, msg, 0, msg.length);
            Assertions.assertEquals(ErrorCode.JO_SUCCESS.getCode(),
                    rsaServiceNI.verify(verifyRef, sig, sig.length), "signature at offset did not verify");

            // (3) window one byte earlier must NOT verify.
            byte[] shiftedSig = new byte[needed];
            System.arraycopy(big, prefix - 1, shiftedSig, 0, needed);
            rsaServiceNI.initVerify(verifyRef, keyRef, "SHA-256", RSAServiceNI.PADDING_PKCS1, null, 0);
            rsaServiceNI.update(verifyRef, msg, 0, msg.length);
            Assertions.assertEquals(ErrorCode.JO_FAIL.getCode(), safeVerify(verifyRef, shiftedSig),
                    "shifted-by-one signature verified — wrote at outOff-1");
        }
        finally
        {
            rsaServiceNI.disposeSigner(signRef);
            rsaServiceNI.disposeSigner(verifyRef);
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void signRaw_writesAtOffsetWithoutClobberingPrefix()
    {
        // RAW PKCS#1 v1.5 path (NoneWithRSA, PADDING_PKCS1_NONE) — a distinct
        // C branch from the hashed path.
        long signRef = 0;
        long verifyRef = 0;
        long keyRef = 0;
        try
        {
            signRef = rsaServiceNI.allocateSigner();
            verifyRef = rsaServiceNI.allocateSigner();
            keyRef = genKey();
            byte[] tbs = new byte[32];
            new SecureRandom().nextBytes(tbs);

            rsaServiceNI.initSign(signRef, keyRef, "NONE", RSAServiceNI.PADDING_PKCS1_NONE, null, 0, RND);
            rsaServiceNI.update(signRef, tbs, 0, tbs.length);
            int needed = rsaServiceNI.sign(signRef, null, 0, RND);
            Assertions.assertEquals(256, needed);

            int prefix = 7;
            byte[] big = new byte[needed + prefix];
            new SecureRandom().nextBytes(big);
            byte[] expectedPrefix = new byte[prefix];
            System.arraycopy(big, 0, expectedPrefix, 0, prefix);

            Assertions.assertEquals(needed, rsaServiceNI.sign(signRef, big, prefix, RND));

            byte[] actualPrefix = new byte[prefix];
            System.arraycopy(big, 0, actualPrefix, 0, prefix);
            Assertions.assertArrayEquals(expectedPrefix, actualPrefix, "raw sign modified the prefix");

            byte[] sig = new byte[needed];
            System.arraycopy(big, prefix, sig, 0, needed);
            rsaServiceNI.initVerify(verifyRef, keyRef, "NONE", RSAServiceNI.PADDING_PKCS1_NONE, null, 0);
            rsaServiceNI.update(verifyRef, tbs, 0, tbs.length);
            Assertions.assertEquals(ErrorCode.JO_SUCCESS.getCode(),
                    rsaServiceNI.verify(verifyRef, sig, sig.length), "raw signature at offset did not verify");

            byte[] shiftedSig = new byte[needed];
            System.arraycopy(big, prefix - 1, shiftedSig, 0, needed);
            rsaServiceNI.initVerify(verifyRef, keyRef, "NONE", RSAServiceNI.PADDING_PKCS1_NONE, null, 0);
            rsaServiceNI.update(verifyRef, tbs, 0, tbs.length);
            Assertions.assertEquals(ErrorCode.JO_FAIL.getCode(), safeVerify(verifyRef, shiftedSig),
                    "raw shifted-by-one signature verified — wrote at outOff-1");
        }
        finally
        {
            rsaServiceNI.disposeSigner(signRef);
            rsaServiceNI.disposeSigner(verifyRef);
            specNI.dispose(keyRef);
        }
    }

    // -----------------------------------------------------------------
    // helpers
    // -----------------------------------------------------------------

    private int safeVerify(long verifyRef, byte[] sig)
    {
        // A malformed signature may return JO_FAIL or surface a structural
        // OpenSSL error; both are correct rejections.
        try
        {
            return rsaServiceNI.verify(verifyRef, sig, sig.length);
        }
        catch (Exception expected)
        {
            return ErrorCode.JO_FAIL.getCode();
        }
    }

    private long genKey()
    {
        long keyRef = rsaServiceNI.generateKeyPair(2048, PUB_EXP_F4, RND);
        Assertions.assertTrue(keyRef > 0);
        return keyRef;
    }

    private byte[] fetchComponent(long keyRef, int component)
    {
        int len = rsaServiceNI.getComponent(keyRef, component, null);
        byte[] out = new byte[len];
        Assertions.assertEquals(len, rsaServiceNI.getComponent(keyRef, component, out));
        return out;
    }

    private interface SpecBody
    {
        void run(long keyRef) throws Exception;
    }

    private interface PairBody
    {
        void run(long rsaRef, long keyRef) throws Exception;
    }

    private void withSpec(SpecBody body)
    {
        long keyRef = specNI.allocate();
        Assertions.assertTrue(keyRef > 0);
        try
        {
            body.run(keyRef);
        }
        catch (Exception e)
        {
            rethrow(e);
        }
        finally
        {
            specNI.dispose(keyRef);
        }
    }

    private void withSignerAndKey(PairBody body)
    {
        long rsaRef = rsaServiceNI.allocateSigner();
        long keyRef = genKey();
        try
        {
            body.run(rsaRef, keyRef);
        }
        catch (Exception e)
        {
            rethrow(e);
        }
        finally
        {
            rsaServiceNI.disposeSigner(rsaRef);
            specNI.dispose(keyRef);
        }
    }

    private void withInitedSigner(PairBody body)
    {
        withSignerAndKey((rsaRef, keyRef) ->
        {
            rsaServiceNI.initSign(rsaRef, keyRef, "SHA-256", RSAServiceNI.PADDING_PKCS1, null, 0, RND);
            body.run(rsaRef, keyRef);
        });
    }

    private void withInitedVerifier(PairBody body)
    {
        withSignerAndKey((rsaRef, keyRef) ->
        {
            rsaServiceNI.initVerify(rsaRef, keyRef, "SHA-256", RSAServiceNI.PADDING_PKCS1, null, 0);
            body.run(rsaRef, keyRef);
        });
    }

    private static void rethrow(Exception e)
    {
        if (e instanceof RuntimeException)
        {
            throw (RuntimeException) e;
        }
        throw new RuntimeException(e);
    }

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

    private static void assertISE(String message, Executable action)
    {
        IllegalStateException e = Assertions.assertThrows(IllegalStateException.class, action);
        Assertions.assertEquals(message, e.getMessage());
    }
}
