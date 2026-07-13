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
import org.openssl.jostle.jcajce.provider.InvalidCipherTextException;
import org.openssl.jostle.jcajce.provider.fips.FIPSNISelector;
import org.openssl.jostle.jcajce.provider.rsa.RSAOAEPCipherNI;
import org.openssl.jostle.jcajce.provider.rsa.RSAServiceNI;
import org.openssl.jostle.jcajce.spec.SpecNI;
import org.openssl.jostle.rand.RandSource;
import org.openssl.jostle.test.TestUtil;

import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Input-validation limit tests at the FIPS RSA-OAEP cipher NI surface
 * ({@link FIPSNISelector#RSAOAEPCipherNI}). The FIPS JNI glue is the base
 * rsa_oaep_ni_jni.c re-included under renamed symbols, so the bridge's
 * null/range/state checks and typed-error mapping are identical by
 * construction. Mirrors the base {@code RSAOAEPCipherLimitTest}.
 *
 * <p>OAEP is FIPS-approved in the 3.1.2 module. Keygen uses the 2048 module
 * floor; {@link TestUtil#RNDSrc} satisfies the bridge null-check (the FIPS
 * entropy path does not consult it).
 *
 * <p>Runs under the {@code integrationTest*} tasks; gated on
 * {@code TEST_FIPS_LIB}. Adds an in-place / aliased-buffer test over the
 * distinct-in/out doFinal (testing.md) plus the base's functional offset-write.
 */
public class FIPSRSAOAEPCipherLimitTest
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
    private final RSAOAEPCipherNI cipherNI = FIPSNISelector.RSAOAEPCipherNI;
    private final SpecNI specNI = FIPSNISelector.SpecNI;

    @Test
    public void init_nullKey()
    {
        long ref = cipherNI.allocateCipher();
        try
        {
            IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class,
                    () -> cipherNI.init(ref, 0, RSAOAEPCipherNI.OP_ENCRYPT, "SHA-256", null, null, RND));
            Assertions.assertEquals("key spec is null", e.getMessage());
        }
        finally
        {
            cipherNI.disposeCipher(ref);
        }
    }

    @Test
    public void nullCipherCtx_allEntryPointsRejectedTyped()
    {
        // A 0/null cipher ctx handle at any OAEP cipher entry point must
        // surface the typed JO_CIPHER_CTX_IS_NULL -> IllegalArgumentException
        // ("cipher context is null"), NOT abort the JVM via jo_assert — the
        // FIPS glue re-includes the base bridge, so this pins the same fix
        // through the FIPS library (rsa_oaep_ni_jni.c / rsa_oaep_ni_ffi.c
        // under interface/fips/). Passing 0 for the key spec as well pins the
        // validation ORDER (ctx before key).
        Assertions.assertEquals("cipher context is null", Assertions.assertThrows(IllegalArgumentException.class,
                () -> cipherNI.init(0, 0, RSAOAEPCipherNI.OP_ENCRYPT, "SHA-256", null, null, RND)).getMessage());
        Assertions.assertEquals("cipher context is null", Assertions.assertThrows(IllegalArgumentException.class,
                () -> cipherNI.doFinal(0, new byte[16], 0, 16, null, 0, RND)).getMessage());
    }

    @Test
    public void init_nullDigest()
    {
        withCipherAndKey((ref, keyRef) ->
        {
            NullPointerException e = Assertions.assertThrows(NullPointerException.class,
                    () -> cipherNI.init(ref, keyRef, RSAOAEPCipherNI.OP_ENCRYPT, null, null, null, RND));
            Assertions.assertEquals("name is null", e.getMessage());
        });
    }

    @Test
    public void init_invalidOpMode()
    {
        withCipherAndKey((ref, keyRef) ->
                // Op-mode rejection surfaces as ISE or IAE via the base handler.
                Assertions.assertThrows(RuntimeException.class,
                        () -> cipherNI.init(ref, keyRef, 99, "SHA-256", null, null, RND)));
    }

    @Test
    public void init_nullRand_encrypt()
    {
        withCipherAndKey((ref, keyRef) ->
        {
            IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class,
                    () -> cipherNI.init(ref, keyRef, RSAOAEPCipherNI.OP_ENCRYPT, "SHA-256", null, null, null));
            Assertions.assertEquals("supplied random source was null", e.getMessage());
        });
    }

    @Test
    public void init_nullRand_decrypt()
    {
        // Decrypt also requires a RandSource (RSA blinding consumes entropy).
        withCipherAndKey((ref, keyRef) ->
        {
            IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class,
                    () -> cipherNI.init(ref, keyRef, RSAOAEPCipherNI.OP_DECRYPT, "SHA-256", null, null, null));
            Assertions.assertEquals("supplied random source was null", e.getMessage());
        });
    }

    @Test
    public void doFinal_notInitialized()
    {
        long ref = cipherNI.allocateCipher();
        try
        {
            IllegalStateException e = Assertions.assertThrows(IllegalStateException.class,
                    () -> cipherNI.doFinal(ref, new byte[1], 0, 1, null, 0, RND));
            Assertions.assertEquals("not initialized", e.getMessage());
        }
        finally
        {
            cipherNI.disposeCipher(ref);
        }
    }

    @Test
    public void doFinal_nullInput()
    {
        withEncryptCipher((ref, keyRef) ->
        {
            NullPointerException e = Assertions.assertThrows(NullPointerException.class,
                    () -> cipherNI.doFinal(ref, null, 0, 0, null, 0, RND));
            Assertions.assertEquals("input is null", e.getMessage());
        });
    }

    @Test
    public void doFinal_offsetNegative()
    {
        withEncryptCipher((ref, keyRef) ->
        {
            for (int off : new int[]{-1, Integer.MIN_VALUE})
            {
                IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class,
                        () -> cipherNI.doFinal(ref, new byte[16], off, 16, null, 0, RND));
                Assertions.assertEquals("input offset is negative", e.getMessage());
            }
        });
    }

    @Test
    public void doFinal_outputTooSmall()
    {
        withEncryptCipher((ref, keyRef) ->
        {
            // Encrypt outputs 256 bytes for a 2048-bit modulus; supply 100.
            IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class,
                    () -> cipherNI.doFinal(ref, new byte[16], 0, 16, new byte[100], 0, RND));
            Assertions.assertEquals("output too small", e.getMessage());
        });
    }

    @Test
    public void doFinal_outOfRange()
    {
        withEncryptCipher((ref, keyRef) ->
        {
            IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class,
                    () -> cipherNI.doFinal(ref, new byte[10], 1, 10, null, 0, RND));
            Assertions.assertEquals("input offset + length is out of range", e.getMessage());
        });
    }

    @Test
    public void doFinal_writesAtOffsetWithoutClobberingPrefix()
    {
        long encRef = 0;
        long decRef = 0;
        long keyRef = 0;
        try
        {
            encRef = cipherNI.allocateCipher();
            decRef = cipherNI.allocateCipher();
            keyRef = genKey();
            cipherNI.init(encRef, keyRef, RSAOAEPCipherNI.OP_ENCRYPT, "SHA-256", null, null, RND);

            byte[] msg = {1, 2, 3, 4};
            int needed = cipherNI.doFinal(encRef, msg, 0, msg.length, null, 0, RND);
            Assertions.assertEquals(256, needed);

            int prefix = 5;
            byte[] big = new byte[needed + prefix];
            new SecureRandom().nextBytes(big);
            byte[] expectedPrefix = Arrays.copyOf(big, prefix);

            Assertions.assertEquals(needed, cipherNI.doFinal(encRef, msg, 0, msg.length, big, prefix, RND));

            // (1) prefix untouched.
            Assertions.assertArrayEquals(expectedPrefix, Arrays.copyOf(big, prefix),
                    "prefix bytes were modified");
            // (2) ciphertext at big[prefix..] decrypts to the plaintext.
            byte[] ct = Arrays.copyOfRange(big, prefix, prefix + needed);
            cipherNI.init(decRef, keyRef, RSAOAEPCipherNI.OP_DECRYPT, "SHA-256", null, null, RND);
            Assertions.assertArrayEquals(msg, decrypt(decRef, ct),
                    "ciphertext at offset did not decrypt to the plaintext");
            // (3) window one byte earlier must NOT decrypt (typed rejection).
            byte[] shifted = Arrays.copyOfRange(big, prefix - 1, prefix - 1 + needed);
            cipherNI.init(decRef, keyRef, RSAOAEPCipherNI.OP_DECRYPT, "SHA-256", null, null, RND);
            final long decRefFinal = decRef;
            byte[] shiftedOut = new byte[needed];
            InvalidCipherTextException thrown = Assertions.assertThrows(InvalidCipherTextException.class,
                    () -> cipherNI.doFinal(decRefFinal, shifted, 0, shifted.length, shiftedOut, 0, RND),
                    "shifted-by-one ciphertext did not trigger InvalidCipherTextException — wrote at outOff-1");
            Assertions.assertNotNull(thrown.getMessage());
            Assertions.assertTrue(thrown.getMessage().startsWith("invalid cipher text"), thrown.getMessage());
        }
        finally
        {
            cipherNI.disposeCipher(encRef);
            cipherNI.disposeCipher(decRef);
            specNI.dispose(keyRef);
        }
    }

    @Test
    public void doFinal_inPlace_sameOffset()
    {
        assertInPlaceRoundTrips(0);
    }

    @Test
    public void doFinal_inPlace_atOffset()
    {
        // Encrypt with a single buffer as both input and output at a non-zero
        // offset: plaintext planted at 0, ciphertext written at outOff.
        assertInPlaceRoundTrips(5);
    }

    /**
     * Encrypt with {@code in == out} (one array), then decrypt the written
     * region and assert it matches the plaintext, and every byte outside the
     * ciphertext region is byte-identical to a pre-call snapshot.
     */
    private void assertInPlaceRoundTrips(int outOff)
    {
        long encRef = 0;
        long decRef = 0;
        long keyRef = 0;
        try
        {
            encRef = cipherNI.allocateCipher();
            decRef = cipherNI.allocateCipher();
            keyRef = genKey();
            cipherNI.init(encRef, keyRef, RSAOAEPCipherNI.OP_ENCRYPT, "SHA-256", null, null, RND);

            byte[] msg = {10, 20, 30, 40, 50};
            int needed = 256;
            int cap = outOff + needed + 8;
            byte[] buf = new byte[cap];
            new SecureRandom().nextBytes(buf);
            System.arraycopy(msg, 0, buf, 0, msg.length);
            byte[] snapshot = buf.clone();

            int written = cipherNI.doFinal(encRef, buf, 0, msg.length, buf, outOff, RND);
            Assertions.assertEquals(needed, written);

            // ciphertext round-trips.
            byte[] ct = Arrays.copyOfRange(buf, outOff, outOff + written);
            cipherNI.init(decRef, keyRef, RSAOAEPCipherNI.OP_DECRYPT, "SHA-256", null, null, RND);
            Assertions.assertArrayEquals(msg, decrypt(decRef, ct),
                    "outOff=" + outOff + ": in-place ciphertext did not decrypt to the plaintext");
            // whole destination outside [outOff, outOff+written) untouched.
            Assertions.assertArrayEquals(Arrays.copyOf(snapshot, outOff), Arrays.copyOf(buf, outOff),
                    "outOff=" + outOff + ": bytes before the output offset were clobbered");
            Assertions.assertArrayEquals(
                    Arrays.copyOfRange(snapshot, outOff + written, cap),
                    Arrays.copyOfRange(buf, outOff + written, cap),
                    "outOff=" + outOff + ": bytes after the ciphertext were clobbered");
        }
        finally
        {
            cipherNI.disposeCipher(encRef);
            cipherNI.disposeCipher(decRef);
            specNI.dispose(keyRef);
        }
    }

    // -----------------------------------------------------------------
    // helpers
    // -----------------------------------------------------------------

    private byte[] decrypt(long decRef, byte[] ct)
    {
        int ptLen = cipherNI.doFinal(decRef, ct, 0, ct.length, null, 0, RND);
        byte[] pt = new byte[ptLen];
        int written = cipherNI.doFinal(decRef, ct, 0, ct.length, pt, 0, RND);
        return Arrays.copyOf(pt, written);
    }

    private long genKey()
    {
        long keyRef = rsaServiceNI.generateKeyPair(2048, PUB_EXP_F4, RND);
        Assertions.assertTrue(keyRef > 0);
        return keyRef;
    }

    private interface PairBody
    {
        void run(long ref, long keyRef) throws Exception;
    }

    private void withCipherAndKey(PairBody body)
    {
        long ref = cipherNI.allocateCipher();
        long keyRef = genKey();
        try
        {
            body.run(ref, keyRef);
        }
        catch (Exception e)
        {
            if (e instanceof RuntimeException)
            {
                throw (RuntimeException) e;
            }
            throw new RuntimeException(e);
        }
        finally
        {
            cipherNI.disposeCipher(ref);
            specNI.dispose(keyRef);
        }
    }

    private void withEncryptCipher(PairBody body)
    {
        withCipherAndKey((ref, keyRef) ->
        {
            cipherNI.init(ref, keyRef, RSAOAEPCipherNI.OP_ENCRYPT, "SHA-256", null, null, RND);
            body.run(ref, keyRef);
        });
    }
}
