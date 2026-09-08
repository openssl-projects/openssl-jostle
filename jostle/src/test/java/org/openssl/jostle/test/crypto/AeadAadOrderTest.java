/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.test.crypto;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.OpenSSLException;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.security.Security;

/**
 * MT-70: AAD supplied AFTER plaintext has been consumed.
 *
 * <h2>The contract</h2>
 *
 * <p>{@code Cipher.updateAAD} is documented to throw {@link IllegalStateException}
 * "if operating in either GCM or CCM mode and one of the update methods has
 * already been called for the active encryption/decryption operation". The
 * refusal is therefore correct; only its TYPE was wrong. GCM surfaced
 * {@link OpenSSLException}, which is a {@code RuntimeException}, so a caller's
 * {@code catch (IllegalStateException)} did not fire.
 *
 * <h2>Where the references stand, measured</h2>
 *
 * <p>SunJCE throws {@code IllegalStateException}. <b>BouncyCastle ACCEPTS</b>
 * late AAD and produces output byte-identical to the legal order, because it
 * defers the work. This is the documented boundary of the match-BouncyCastle
 * rule: BC diverges from the JCE contract, so JCE-canonical wins and the
 * divergence is pinned in BOTH halves by
 * {@link #bouncyCastleAcceptsLateAadAndWeDoNot()}.
 */
public class AeadAadOrderTest
{
    private static final String JSL = JostleProvider.PROVIDER_NAME;
    private static final SecureRandom RANDOM = new SecureRandom();

    @BeforeAll
    public static void setUp()
    {
        if (Security.getProvider(JSL) == null)
        {
            Security.addProvider(new JostleProvider());
        }
        if (Security.getProvider("BC") == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /**
     * CONTROL, recorded before the fix: GCM refused late AAD with
     * {@link OpenSSLException}. Inverted to {@link IllegalStateException} by the
     * fix; kept here as the record of what moved.
     */
    @Test
    public void gcmRefusesAadAfterUpdate_encrypt() throws Exception
    {
        assertLateAadRefused(Cipher.ENCRYPT_MODE);
    }

    /** Decrypt is a different code path and gets its own cell. */
    @Test
    public void gcmRefusesAadAfterUpdate_decrypt() throws Exception
    {
        assertLateAadRefused(Cipher.DECRYPT_MODE);
    }

    /** CCM already refused correctly; this pins it so it cannot drift to GCM's shape. */
    @Test
    public void ccmRefusesAadAfterUpdate_bothDirections() throws Exception
    {
        for (int mode : new int[]{Cipher.ENCRYPT_MODE, Cipher.DECRYPT_MODE})
        {
            Cipher cipher = init("AES/CCM/NoPadding", mode);
            cipher.update(new byte[16]);
            IllegalStateException ex = Assertions.assertThrows(IllegalStateException.class,
                    () -> cipher.updateAAD(new byte[8]));
            Assertions.assertEquals("AAD must be supplied before any data", ex.getMessage(),
                    "the two AEAD SPIs must refuse in identical words");
        }
    }

    /**
     * An EMPTY update must NOT close the AAD window — SunJCE and BouncyCastle
     * both accept it, measured.
     *
     * <h3>Why this uses the ByteBuffer overload, and must</h3>
     *
     * <p>{@code Cipher.update(byte[]...)} short-circuits a zero-length input and
     * NEVER calls the SPI — measured: after an encrypt {@code doFinal},
     * {@code update(new byte[0])} does not trip the SPI's reuse guard while
     * {@code update(new byte[16])} does. So a {@code byte[]}-based version of
     * this test passes against ANY implementation, including one that closes the
     * window at method entry, and would be vacuous.
     *
     * <p>{@code Cipher.update(ByteBuffer, ByteBuffer)} does NOT short-circuit;
     * it reaches {@code BlockCipherSpi.engineUpdate(ByteBuffer, ByteBuffer)},
     * which returns early on {@code remaining() == 0}. That is the one public
     * path that can tell a correct implementation from one that sets the flag
     * too early, so it is the path this test uses. <b>Do not rewrite it with
     * byte arrays.</b>
     */
    @Test
    public void anEmptyUpdateDoesNotCloseTheAadWindow() throws Exception
    {
        for (int mode : new int[]{Cipher.ENCRYPT_MODE, Cipher.DECRYPT_MODE})
        {
            Cipher cipher = init("AES/GCM/NoPadding", mode);
            cipher.update(ByteBuffer.allocate(0), ByteBuffer.allocate(64));
            cipher.updateAAD(new byte[8]);   // must NOT throw
        }
    }

    /**
     * The divergence, pinned in both halves: BouncyCastle accepts late AAD and
     * we refuse it. Asserting BC's half means a bcprov bump that moves the
     * reference fails here loudly, rather than leaving our refusal looking
     * unexplained.
     */
    @Test
    public void bouncyCastleAcceptsLateAadAndWeDoNot() throws Exception
    {
        byte[] key = new byte[16];
        byte[] nonce = new byte[12];
        RANDOM.nextBytes(key);
        RANDOM.nextBytes(nonce);

        Cipher bc = Cipher.getInstance("AES/GCM/NoPadding", "BC");
        bc.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
        bc.update(new byte[16]);
        bc.updateAAD(new byte[8]);   // BC tolerates this; the JCE contract does not

        Cipher jsl = Cipher.getInstance("AES/GCM/NoPadding", JSL);
        jsl.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
        jsl.update(new byte[16]);
        Assertions.assertThrows(IllegalStateException.class, () -> jsl.updateAAD(new byte[8]),
                "JCE-canonical wins where BouncyCastle diverges from the contract");
    }

    private static void assertLateAadRefused(int mode) throws Exception
    {
        Cipher cipher = init("AES/GCM/NoPadding", mode);
        cipher.update(new byte[16]);
        IllegalStateException ex = Assertions.assertThrows(IllegalStateException.class,
                () -> cipher.updateAAD(new byte[8]));
        Assertions.assertEquals("AAD must be supplied before any data", ex.getMessage());
    }

    private static Cipher init(String transformation, int mode) throws Exception
    {
        byte[] key = new byte[16];
        byte[] nonce = new byte[12];
        RANDOM.nextBytes(key);
        RANDOM.nextBytes(nonce);
        Cipher cipher = Cipher.getInstance(transformation, JSL);
        cipher.init(mode, new SecretKeySpec(key, "AES"), new GCMParameterSpec(64, nonce));
        return cipher;
    }
}
