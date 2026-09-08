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

    /**
     * MT-70b: {@code doFinal} returns the Cipher to its post-init state, so the
     * AAD window must REOPEN. Otherwise the MT-70 guard turns a legal reuse into
     * a refusal.
     *
     * <p>The discriminating shape needs an {@code update()} before the first
     * {@code doFinal} — without one the flag is never set and the bug hides. A
     * probe using only {@code updateAAD} + {@code doFinal} reports every mode
     * healthy on the broken build.
     *
     * <p>Driven over every mode {@code BlockCipherSpi.isAeadMode()} covers — GCM,
     * OCB and ChaCha20-Poly1305 — not GCM alone, and asserts the second
     * message's PLAINTEXT rather than merely that updateAAD did not throw.
     * Decrypt, because an encrypt reuse is refused by the nonce-reuse guard
     * regardless. CCM is exempt: it resets its own flag in a {@code finally}
     * after final, which is the sibling this fix copies.
     */
    @Test
    public void aDecryptCipherReusedAfterDoFinalAcceptsAadAgain() throws Exception
    {
        for (String transformation : new String[]{"AES/GCM/NoPadding", "AES/OCB/NoPadding",
                "ChaCha20-Poly1305", "AES/CCM/NoPadding"})
        {
            // The two messages differ in PLAINTEXT (40 vs 24 bytes) and in AAD, so
            // the second assertion cannot pass against a stale output buffer.
            //
            // The NONCE is deliberately the same, and it has to be: a reused
            // decrypt instance still holds the nonce it was initialised with, so
            // a second message made with a different one is simply undecryptable
            // without re-init. Measured — BouncyCastle and SunJCE both raise
            // AEADBadTagException for that shape, so requiring a distinct nonce
            // here would replace the property under test with a tag failure.
            // The two ciphertexts sharing a nonce is a fixture artefact of
            // testing decrypt reuse, not a pattern to copy.
            byte[] key = new byte[32];
            byte[] nonce = new byte[12];
            byte[] aadA = new byte[]{1, 2, 3};
            byte[] aadB = new byte[]{4, 5, 6, 7};
            byte[] plainA = new byte[40];
            byte[] plainB = new byte[24];
            RANDOM.nextBytes(key);
            RANDOM.nextBytes(nonce);
            RANDOM.nextBytes(plainA);
            RANDOM.nextBytes(plainB);

            byte[] first = aeadEncrypt(transformation, key, nonce, aadA, plainA);
            byte[] second = aeadEncrypt(transformation, key, nonce, aadB, plainB);

            Cipher dec = Cipher.getInstance(transformation, JSL);
            dec.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, keyAlgorithmFor(transformation)),
                    specFor(transformation, nonce));
            dec.updateAAD(aadA);

            // The update() is what sets the flag; without it this test passes
            // against the broken build.
            java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
            byte[] partial = dec.update(first, 0, first.length - 4);
            if (partial != null)
            {
                out.write(partial);
            }
            out.write(dec.doFinal(first, first.length - 4, 4));
            Assertions.assertArrayEquals(plainA, out.toByteArray(), transformation + " first message");

            // No re-init: that is the whole point.
            dec.updateAAD(aadB);
            Assertions.assertArrayEquals(plainB, dec.doFinal(second),
                    transformation + " second message on the same instance");
        }
    }

    /**
     * MT-70b, failure path: a FAILED doFinal must also reopen the AAD window.
     *
     * <p>A bad tag on decrypt is the ordinary case, not an exotic one — it is
     * what an attacker-supplied or corrupted message produces — and the JCE
     * contract keeps the Cipher usable afterwards. If the reset sits only on the
     * success path, the next operation on that instance gets a stale
     * {@code IllegalStateException} about AAD that has nothing to do with what
     * went wrong.
     *
     * <p>CCM resets in a {@code finally} for this reason; this is the cell that
     * holds the other AEAD modes to the same behaviour.
     */
    @Test
    public void aFailedDoFinalAlsoReopensTheAadWindow() throws Exception
    {
        for (String transformation : new String[]{"AES/GCM/NoPadding", "AES/OCB/NoPadding",
                "ChaCha20-Poly1305", "AES/CCM/NoPadding"})
        {
            byte[] key = new byte[32];
            byte[] nonce = new byte[12];
            byte[] aad = new byte[]{1, 2, 3};
            byte[] plaintext = new byte[40];
            RANDOM.nextBytes(key);
            RANDOM.nextBytes(nonce);
            RANDOM.nextBytes(plaintext);

            byte[] good = aeadEncrypt(transformation, key, nonce, aad, plaintext);
            byte[] tampered = good.clone();
            tampered[tampered.length - 1] ^= (byte) 0x01;   // flip a tag byte

            Cipher dec = Cipher.getInstance(transformation, JSL);
            dec.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, keyAlgorithmFor(transformation)),
                    specFor(transformation, nonce));
            dec.updateAAD(aad);
            dec.update(tampered, 0, tampered.length - 4);   // sets the flag
            Assertions.assertThrows(javax.crypto.AEADBadTagException.class,
                    () -> dec.doFinal(tampered, tampered.length - 4, 4),
                    transformation + ": a flipped tag byte must fail authentication");

            // The instance stays usable, and the AAD window must have reopened.
            dec.updateAAD(aad);
            Assertions.assertArrayEquals(plaintext, dec.doFinal(good),
                    transformation + ": a good message after a failed one");
        }
    }

    private static byte[] aeadEncrypt(String transformation, byte[] key, byte[] nonce,
                                      byte[] aad, byte[] plaintext) throws Exception
    {
        Cipher enc = Cipher.getInstance(transformation, JSL);
        enc.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, keyAlgorithmFor(transformation)),
                specFor(transformation, nonce));
        enc.updateAAD(aad);
        return enc.doFinal(plaintext);
    }

    private static String keyAlgorithmFor(String transformation)
    {
        return transformation.startsWith("ChaCha") ? "ChaCha20" : "AES";
    }

    private static java.security.spec.AlgorithmParameterSpec specFor(String transformation, byte[] nonce)
    {
        if (transformation.startsWith("ChaCha"))
        {
            return new javax.crypto.spec.IvParameterSpec(nonce);
        }
        return new GCMParameterSpec(transformation.contains("CCM") ? 64 : 128, nonce);
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
