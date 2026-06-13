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
import org.openssl.jostle.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.security.SecureRandom;
import java.security.Security;

/**
 * Regression guard for the CBC decrypt update/doFinal buffering gap
 * (CBC_DECRYPT_UPDATE_BUFFERING_GAP.md): JSL's padded-decrypt sizing didn't
 * model OpenSSL's held-back final block, so {@code update(...)} + {@code
 * doFinal()} corrupted any non-block-aligned plaintext, and sub-block chunked
 * decrypt corrupted everything — EVP wrote past the staged output buffer.
 *
 * <p>Drives decrypt (and encrypt, whose direct-buffer guard had the same
 * under-check) through every chunking the JCE surface offers, for plaintext
 * lengths spanning the doc's matrix, against SunJCE-produced reference
 * ciphertext. The chunk sizes deliberately include sub-block (1, 7, 8),
 * exactly-block (16), and block-spanning (24) splits — block-aligned chunked
 * decrypt previously corrupted the JVM heap silently while returning correct
 * bytes, so "passes" at one chunk size proves little about the others.
 */
public class CBCUpdateBufferingTest
{
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final int[] PLAINTEXT_LENGTHS = {15, 16, 17, 30, 31, 32, 100};
    private static final int[] CHUNK_SIZES = {1, 7, 8, 16, 24};

    @BeforeAll
    static void before()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    private static SecureRandom seededRandom(String testName) throws Exception
    {
        long seed = RANDOM.nextLong();
        System.out.println(testName + " seed=" + seed);
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        sr.setSeed(seed);
        return sr;
    }

    private static byte[] chunkedUpdateDoFinal(Cipher c, byte[] in, int chunk) throws Exception
    {
        ByteArrayOutputStream acc = new ByteArrayOutputStream();
        for (int off = 0; off < in.length; off += chunk)
        {
            int len = Math.min(chunk, in.length - off);
            byte[] o = c.update(in, off, len);
            if (o != null)
            {
                acc.write(o, 0, o.length);
            }
        }
        byte[] f = c.doFinal();
        acc.write(f, 0, f.length);
        return acc.toByteArray();
    }

    @Test
    public void decryptUpdateThenDoFinal_allLengths_matchesSunJce() throws Exception
    {
        SecureRandom random = seededRandom("decryptUpdateThenDoFinal_allLengths_matchesSunJce");
        byte[] key = new byte[16];
        byte[] iv = new byte[16];
        random.nextBytes(key);
        random.nextBytes(iv);
        SecretKeySpec k = new SecretKeySpec(key, "AES");

        for (int n : PLAINTEXT_LENGTHS)
        {
            byte[] pt = new byte[n];
            random.nextBytes(pt);

            // Reference ciphertext from SunJCE — known-good producer.
            Cipher enc = Cipher.getInstance("AES/CBC/PKCS5Padding", "SunJCE");
            enc.init(Cipher.ENCRYPT_MODE, k, new IvParameterSpec(iv));
            byte[] ct = enc.doFinal(pt);

            // update(all) + doFinal() — the CMS content-decryption shape.
            Cipher d = Cipher.getInstance("AES/CBC/PKCS5Padding", JostleProvider.PROVIDER_NAME);
            d.init(Cipher.DECRYPT_MODE, k, new IvParameterSpec(iv));
            ByteArrayOutputStream acc = new ByteArrayOutputStream();
            byte[] u = d.update(ct);
            if (u != null)
            {
                acc.write(u, 0, u.length);
            }
            byte[] f = d.doFinal();
            acc.write(f, 0, f.length);
            Assertions.assertArrayEquals(pt, acc.toByteArray(),
                    "n=" + n + ": update(all)+doFinal() diverged");

            // Chunked updates at every split in the matrix.
            for (int chunk : CHUNK_SIZES)
            {
                Cipher dc = Cipher.getInstance("AES/CBC/PKCS5Padding", JostleProvider.PROVIDER_NAME);
                dc.init(Cipher.DECRYPT_MODE, k, new IvParameterSpec(iv));
                Assertions.assertArrayEquals(pt, chunkedUpdateDoFinal(dc, ct, chunk),
                        "n=" + n + " chunk=" + chunk + ": chunked decrypt diverged");
            }
        }
    }

    @Test
    public void encryptChunked_allLengths_sunJceDecrypts() throws Exception
    {
        // The encrypt-side direct-buffer guard shared the under-check; prove
        // chunked encrypt emits ciphertext SunJCE accepts at every split.
        SecureRandom random = seededRandom("encryptChunked_allLengths_sunJceDecrypts");
        byte[] key = new byte[16];
        byte[] iv = new byte[16];
        random.nextBytes(key);
        random.nextBytes(iv);
        SecretKeySpec k = new SecretKeySpec(key, "AES");

        for (int n : PLAINTEXT_LENGTHS)
        {
            byte[] pt = new byte[n];
            random.nextBytes(pt);

            for (int chunk : CHUNK_SIZES)
            {
                Cipher enc = Cipher.getInstance("AES/CBC/PKCS5Padding", JostleProvider.PROVIDER_NAME);
                enc.init(Cipher.ENCRYPT_MODE, k, new IvParameterSpec(iv));
                byte[] ct = chunkedUpdateDoFinal(enc, pt, chunk);

                Cipher dec = Cipher.getInstance("AES/CBC/PKCS5Padding", "SunJCE");
                dec.init(Cipher.DECRYPT_MODE, k, new IvParameterSpec(iv));
                Assertions.assertArrayEquals(pt, dec.doFinal(ct),
                        "n=" + n + " chunk=" + chunk + ": SunJCE rejected chunked-encrypt output");
            }
        }
    }

    @Test
    public void decryptChunked_tamperedCiphertext_doesNotRoundTrip() throws Exception
    {
        // Negative path: damage the ciphertext body and assert the chunked
        // decrypt either throws BadPaddingException or yields different
        // plaintext — proves the chunked path actually decrypts its input.
        SecureRandom random = seededRandom("decryptChunked_tamperedCiphertext_doesNotRoundTrip");
        byte[] key = new byte[16];
        byte[] iv = new byte[16];
        random.nextBytes(key);
        random.nextBytes(iv);
        SecretKeySpec k = new SecretKeySpec(key, "AES");

        byte[] pt = new byte[30];
        random.nextBytes(pt);
        Cipher enc = Cipher.getInstance("AES/CBC/PKCS5Padding", "SunJCE");
        enc.init(Cipher.ENCRYPT_MODE, k, new IvParameterSpec(iv));
        byte[] ct = enc.doFinal(pt);

        byte[] tampered = Arrays.clone(ct);
        tampered[3] ^= (byte) 0x01;

        Cipher d = Cipher.getInstance("AES/CBC/PKCS5Padding", JostleProvider.PROVIDER_NAME);
        d.init(Cipher.DECRYPT_MODE, k, new IvParameterSpec(iv));
        try
        {
            byte[] decoded = chunkedUpdateDoFinal(d, tampered, 8);
            Assertions.assertFalse(Arrays.areEqual(pt, decoded),
                    "tampered ciphertext must not round-trip");
        }
        catch (BadPaddingException e)
        {
            // also acceptable — corrupting block 0 cascades into the padding
        }
    }
}
