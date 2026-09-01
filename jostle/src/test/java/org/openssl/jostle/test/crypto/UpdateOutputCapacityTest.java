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

package org.openssl.jostle.test.crypto;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;

import javax.crypto.Cipher;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;

/**
 * {@code engineUpdate}'s ShortBufferException threshold is UPDATE's output
 * bound, not update-plus-doFinal.
 *
 * <p>MT-33. The 5-arg overload guarded on {@code engineGetOutputSize}, which
 * reports what update AND a following doFinal produce together, so it refused
 * buffers a caller had sized correctly. Measured before the fix: AES/CTS
 * demanded 64 bytes of capacity for an update that writes 0.
 *
 * <p><b>The contract pinned here is agreement with OUR OWN emission bound, not
 * with BouncyCastle's numbers.</b> Our minimums legitimately differ from BC's -
 * BC holds back a block on padded encrypt where EVP does not - so a test
 * asserting BC's figures would be pinning the wrong thing.
 *
 * <p>Each case asserts BOTH halves: the exact minimum is accepted, and one byte
 * less throws. Only the pair locates the boundary; either alone passes against
 * a guard that is off in one direction.
 */
public class UpdateOutputCapacityTest
{
    private static final SecureRandom SR = new SecureRandom();

    /** Overridden by the JSLFIPS twin. */
    protected String providerName()
    {
        return JostleProvider.PROVIDER_NAME;
    }

    @BeforeAll
    public static void setUp()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    private Cipher enc(String xform, int keyBytes, AlgorithmParameterSpec ps) throws Exception
    {
        byte[] k = new byte[keyBytes];
        SR.nextBytes(k);
        Cipher c = Cipher.getInstance(xform, providerName());
        Key key = new SecretKeySpec(k, xform.substring(0, xform.indexOf('/')));
        if (ps == null)
        {
            c.init(Cipher.ENCRYPT_MODE, key);
        }
        else
        {
            c.init(Cipher.ENCRYPT_MODE, key, ps);
        }
        return c;
    }

    private static IvParameterSpec iv(int n)
    {
        byte[] b = new byte[n];
        SR.nextBytes(b);
        return new IvParameterSpec(b);
    }

    /**
     * The minimum output capacity {@code update} accepts must equal what it
     * writes, and one byte less must be refused.
     */
    private void assertBoundary(String label, Cipher c, byte[] in, int expectedMin) throws Exception
    {
        int written = c.update(in, 0, in.length, new byte[expectedMin], 0);
        Assertions.assertTrue(written <= expectedMin,
                label + ": wrote " + written + " into a buffer of " + expectedMin);

        if (expectedMin == 0)
        {
            // Nothing to under-size. The accepted-at-zero half above IS the
            // property: before MT-33 this demanded a full input-sized window.
            return;
        }
        Assertions.assertThrows(ShortBufferException.class,
                () -> c.update(in, 0, in.length, new byte[expectedMin - 1], 0),
                label + ": a buffer one byte under the emission bound must be refused");
    }

    @Test
    public void cbcPkcs5_updateDemandsOnlyWhatItWrites() throws Exception
    {
        byte[] in = new byte[64];
        SR.nextBytes(in);
        Cipher c = enc("AES/CBC/PKCS5Padding", 16, iv(16));
        // getOutputSize is 80 here (64 + a pad block). update writes 64, so 80
        // was the old, wrong threshold.
        Assertions.assertEquals(80, c.getOutputSize(64), "precondition: doFinal-sized bound");
        assertBoundary("AES/CBC/PKCS5Padding", c, in, 64);
    }

    @Test
    public void gcm_updateDoesNotDemandTagRoom() throws Exception
    {
        byte[] in = new byte[64];
        SR.nextBytes(in);
        Cipher c = enc("AES/GCM/NoPadding", 16, new GCMParameterSpec(128, new byte[12]));
        Assertions.assertEquals(80, c.getOutputSize(64), "precondition: includes the 16-byte tag");
        // The tag is emitted at doFinal, so update needs none of that room.
        assertBoundary("AES/GCM/NoPadding", c, in, 64);
    }

    /**
     * CTS is the sharp case: it accumulates, so update writes NOTHING, and the
     * old guard demanded a 64-byte window for it.
     */
    @Test
    public void cts_accumulatesSoUpdateNeedsNoCapacityAtAll() throws Exception
    {
        byte[] in = new byte[64];
        SR.nextBytes(in);
        Cipher c = enc("AES/CTS/NoPadding", 16, iv(16));
        assertBoundary("AES/CTS/NoPadding", c, in, 0);
    }

    /**
     * The guard must not UNDER-guard. A padded decrypt holds back a block, so
     * the bound for a later update carries an extra block on top of the input
     * length; a threshold "simplified" to inputLen would let a caller through
     * that the native guard then refuses.
     *
     * <p>Measured: after a 32-byte first update, a 16-byte second update
     * requires 32 bytes of capacity - DOUBLE its input - and writes 16.
     *
     * <p>The threshold therefore exceeds actual emission here, and that is
     * correct rather than a residue of the bug this class pins. It is the same
     * bound {@code block_cipher_ctx_update} enforces natively, so relaxing the
     * Java side to the emitted 16 would only move the refusal into C. An
     * earlier draft of this test asserted "emission exceeds input length" and
     * FAILED: emission is 16, the BOUND is 32. The distinction is the test.
     */
    @Test
    public void paddedDecrypt_thresholdCarriesTheHeldBackBlock() throws Exception
    {
        byte[] key = new byte[16];
        byte[] ivb = new byte[16];
        SR.nextBytes(key);
        SR.nextBytes(ivb);
        final Key k = new SecretKeySpec(key, "AES");
        byte[] pt = new byte[64];
        SR.nextBytes(pt);

        Cipher e = Cipher.getInstance("AES/CBC/PKCS5Padding", providerName());
        e.init(Cipher.ENCRYPT_MODE, k, new IvParameterSpec(ivb));
        final byte[] ct = e.doFinal(pt);

        Cipher d = primedDecryptor(k, ivb, ct);
        int written = d.update(ct, 32, 16, new byte[32], 0);
        Assertions.assertEquals(16, written, "emission for the second update");

        Assertions.assertThrows(ShortBufferException.class,
                () -> primedDecryptor(k, ivb, ct).update(ct, 32, 16, new byte[31], 0),
                "31 bytes is under the bound and must be refused");

        // The load-bearing half: the bound is strictly GREATER than inputLen,
        // so a threshold collapsed to inputLen would wrongly accept 16.
        Assertions.assertThrows(ShortBufferException.class,
                () -> primedDecryptor(k, ivb, ct).update(ct, 32, 16, new byte[16], 0),
                "a window sized at inputLen must be refused - that is the under-guard");
    }

    /** A padded decryptor that has already consumed 32 bytes, so a block is held back. */
    private Cipher primedDecryptor(Key k, byte[] ivb, byte[] ct) throws Exception
    {
        Cipher d = Cipher.getInstance("AES/CBC/PKCS5Padding", providerName());
        d.init(Cipher.DECRYPT_MODE, k, new IvParameterSpec(ivb));
        d.update(ct, 0, 32, new byte[d.getOutputSize(32)], 0);
        return d;
    }
}
