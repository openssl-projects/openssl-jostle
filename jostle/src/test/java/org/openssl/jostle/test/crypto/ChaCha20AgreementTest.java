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

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.SecureRandom;
import java.security.Security;

import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Agreement between BouncyCastle (CHACHA7539, the RFC 7539 / 8439 12-byte-nonce
 * engine) and Jostle for raw ChaCha20, plus chunking, negative-path, reset and
 * boundary coverage. Raw ChaCha20 has no authentication; its cross-validation
 * anchor is BouncyCastle (there is no counter-0 published keystream vector in
 * RFC 8439, which fixes its examples at counter 1).
 */
public class ChaCha20AgreementTest
{
    private static final String JSL = JostleProvider.PROVIDER_NAME;
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;
    // Jostle exposes "ChaCha20"; BouncyCastle's matching engine is "CHACHA7539".
    private static final String JSL_NAME = "ChaCha20";
    private static final String BC_NAME = "CHACHA7539";

    private static final SecureRandom RANDOM = new SecureRandom();

    private static SecureRandom seededRandom(String testName) throws Exception
    {
        long seed = RANDOM.nextLong();
        System.out.println(testName + " seed=" + seed);
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        sr.setSeed(seed);
        return sr;
    }

    @BeforeAll
    static void before()
    {
        if (Security.getProvider(BC) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
        if (Security.getProvider(JSL) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    private static SecretKey randomKey(SecureRandom sr)
    {
        byte[] key = new byte[32];
        sr.nextBytes(key);
        return new SecretKeySpec(key, "ChaCha20");
    }

    /** BC and Jostle produce byte-identical keystream output, both directions. */
    @Test
    public void agreesWithBC_bothDirections() throws Exception
    {
        SecureRandom sr = seededRandom("agreesWithBC_bothDirections");

        for (int trial = 0; trial < 25; trial++)
        {
            SecretKey key = randomKey(sr);
            byte[] nonce = new byte[12];
            sr.nextBytes(nonce);
            byte[] msg = new byte[sr.nextInt(400)];
            sr.nextBytes(msg);
            IvParameterSpec iv = new IvParameterSpec(nonce);

            Cipher jslEnc = Cipher.getInstance(JSL_NAME, JSL);
            jslEnc.init(Cipher.ENCRYPT_MODE, key, iv);
            byte[] jslCt = jslEnc.doFinal(msg);

            Cipher bcEnc = Cipher.getInstance(BC_NAME, BC);
            bcEnc.init(Cipher.ENCRYPT_MODE, key, iv);
            byte[] bcCt = bcEnc.doFinal(msg);
            Assertions.assertArrayEquals(bcCt, jslCt, "ciphertext (trial " + trial + ")");

            // BC-encrypt -> JSL-decrypt and JSL-encrypt -> BC-decrypt.
            Cipher jslDec = Cipher.getInstance(JSL_NAME, JSL);
            jslDec.init(Cipher.DECRYPT_MODE, key, iv);
            Assertions.assertArrayEquals(msg, jslDec.doFinal(bcCt), "BC-enc/JSL-dec");

            Cipher bcDec = Cipher.getInstance(BC_NAME, BC);
            bcDec.init(Cipher.DECRYPT_MODE, key, iv);
            Assertions.assertArrayEquals(msg, bcDec.doFinal(jslCt), "JSL-enc/BC-dec");
        }
    }

    /**
     * The same logical input produces byte-identical output whether processed
     * one-shot, byte-by-byte, or in chunks straddling the 64-byte ChaCha block.
     */
    @Test
    public void chunkingMatrix_byteIdentical() throws Exception
    {
        SecureRandom sr = seededRandom("chunkingMatrix_byteIdentical");
        SecretKey key = randomKey(sr);
        byte[] nonce = new byte[12];
        sr.nextBytes(nonce);
        byte[] msg = new byte[64 * 3 + 5];
        sr.nextBytes(msg);
        IvParameterSpec iv = new IvParameterSpec(nonce);

        byte[] oneShot = oneShot(key, iv, msg);

        // byte-by-byte
        Assertions.assertArrayEquals(oneShot, chunked(key, iv, msg, 1), "byte-by-byte");
        // chunk sizes straddling the 64-byte block boundary
        for (int chunk : new int[]{63, 64, 65, 127, 128, 129})
        {
            Assertions.assertArrayEquals(oneShot, chunked(key, iv, msg, chunk), "chunk=" + chunk);
        }
        // random splits
        Assertions.assertArrayEquals(oneShot, randomSplit(key, iv, msg, sr), "random split");
    }

    private static byte[] oneShot(SecretKey key, IvParameterSpec iv, byte[] msg) throws Exception
    {
        Cipher c = Cipher.getInstance(JSL_NAME, JSL);
        c.init(Cipher.ENCRYPT_MODE, key, iv);
        return c.doFinal(msg);
    }

    private static byte[] chunked(SecretKey key, IvParameterSpec iv, byte[] msg, int chunk) throws Exception
    {
        Cipher c = Cipher.getInstance(JSL_NAME, JSL);
        c.init(Cipher.ENCRYPT_MODE, key, iv);
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        for (int off = 0; off < msg.length; off += chunk)
        {
            int len = Math.min(chunk, msg.length - off);
            byte[] piece = c.update(msg, off, len);
            if (piece != null)
            {
                out.write(piece);
            }
        }
        out.write(c.doFinal());
        return out.toByteArray();
    }

    private static byte[] randomSplit(SecretKey key, IvParameterSpec iv, byte[] msg, SecureRandom sr) throws Exception
    {
        Cipher c = Cipher.getInstance(JSL_NAME, JSL);
        c.init(Cipher.ENCRYPT_MODE, key, iv);
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        int off = 0;
        while (off < msg.length)
        {
            int len = Math.min(1 + sr.nextInt(40), msg.length - off);
            byte[] piece = c.update(msg, off, len);
            if (piece != null)
            {
                out.write(piece);
            }
            off += len;
        }
        out.write(c.doFinal());
        return out.toByteArray();
    }

    /** The transform actually transforms, round-trips, and a wrong key diverges. */
    @Test
    public void negativePath() throws Exception
    {
        SecureRandom sr = seededRandom("negativePath");
        SecretKey key = randomKey(sr);
        SecretKey wrong = randomKey(sr);
        byte[] nonce = new byte[12];
        sr.nextBytes(nonce);
        byte[] msg = new byte[80];
        sr.nextBytes(msg);
        IvParameterSpec iv = new IvParameterSpec(nonce);

        Cipher enc = Cipher.getInstance(JSL_NAME, JSL);
        enc.init(Cipher.ENCRYPT_MODE, key, iv);
        byte[] ct = enc.doFinal(msg);
        Assertions.assertFalse(Arrays.areEqual(msg, ct), "ciphertext == plaintext");

        Cipher dec = Cipher.getInstance(JSL_NAME, JSL);
        dec.init(Cipher.DECRYPT_MODE, key, iv);
        Assertions.assertArrayEquals(msg, dec.doFinal(ct), "round-trip");

        Cipher decWrong = Cipher.getInstance(JSL_NAME, JSL);
        decWrong.init(Cipher.DECRYPT_MODE, wrong, iv);
        Assertions.assertFalse(Arrays.areEqual(msg, decWrong.doFinal(ct)), "wrong key recovered plaintext");
    }

    /** Deterministic given (key, nonce, counter): reuse yields identical output. */
    @Test
    public void resetReuse_deterministic() throws Exception
    {
        SecureRandom sr = seededRandom("resetReuse_deterministic");
        SecretKey key = randomKey(sr);
        byte[] nonce = new byte[12];
        sr.nextBytes(nonce);
        byte[] msg = new byte[55];
        sr.nextBytes(msg);
        IvParameterSpec iv = new IvParameterSpec(nonce);

        Cipher c = Cipher.getInstance(JSL_NAME, JSL);
        c.init(Cipher.ENCRYPT_MODE, key, iv);
        byte[] first = c.doFinal(msg);
        c.init(Cipher.ENCRYPT_MODE, key, iv);
        byte[] second = c.doFinal(msg);
        Assertions.assertArrayEquals(first, second, "deterministic reuse");

        byte[] other = new byte[55];
        sr.nextBytes(other);
        c.init(Cipher.ENCRYPT_MODE, key, iv);
        Assertions.assertFalse(Arrays.areEqual(first, c.doFinal(other)), "distinct input -> distinct output");
    }

    /** Key must be 32 bytes; nonce must be 12 bytes. */
    @Test
    public void boundaryLengths_rejected() throws Exception
    {
        SecureRandom sr = seededRandom("boundaryLengths_rejected");
        byte[] nonce = new byte[12];
        sr.nextBytes(nonce);

        for (int kl : new int[]{31, 33})
        {
            byte[] kb = new byte[kl];
            sr.nextBytes(kb);
            SecretKey badKey = new SecretKeySpec(kb, "ChaCha20");
            Cipher c = Cipher.getInstance(JSL_NAME, JSL);
            assertThrows(InvalidKeyException.class,
                    () -> c.init(Cipher.ENCRYPT_MODE, badKey, new IvParameterSpec(nonce)), "key len " + kl);
        }

        SecretKey key = randomKey(sr);
        for (int nl : new int[]{11, 13})
        {
            byte[] nb = new byte[nl];
            sr.nextBytes(nb);
            Cipher c = Cipher.getInstance(JSL_NAME, JSL);
            assertThrows(InvalidAlgorithmParameterException.class,
                    () -> c.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(nb)), "nonce len " + nl);
        }
    }
}
