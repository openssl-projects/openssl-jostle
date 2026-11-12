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

import org.bouncycastle.crypto.engines.ChaCha7539Engine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.util.Arrays;
import org.openssl.jostle.util.encoders.Hex;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.ChaCha20ParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.security.SecureRandom;
import java.security.Security;

/**
 * Agreement for the ChaCha20 initial block counter path: JSL under ChaCha20ParameterSpec against SunJCE and against
 * BouncyCastle's ChaCha7539Engine positioned with seekTo, plus counter 0 against BouncyCastle's CHACHA7539.
 * ChaCha20AgreementTest covers counter 0 through IvParameterSpec on every leg; ChaCha20ParameterSpecTest holds the
 * spec contract, the RFC 8439 vectors and the per-nonce limit.
 *
 * <p>Lives in {@code src/test/java11} so it runs on unitTest11; the {@code src/test/java25} copy runs the same cells on
 * unitTest25JNI and unitTest25FFM.
 */
public class ChaCha20CounterAgreementTest
{
    private static final String JSL = JostleProvider.PROVIDER_NAME;
    private static final String SUN = "SunJCE";
    private static final SecureRandom R = new SecureRandom();

    @BeforeAll
    static void before()
    {
        if (Security.getProvider("BC") == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
        if (Security.getProvider(JSL) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    private static SecureRandom seededRandom(String testName) throws Exception
    {
        long seed = R.nextLong();
        System.out.println(testName + " seed=" + seed);
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        sr.setSeed(seed);
        return sr;
    }

    private static SecretKey randomKey()
    {
        return randomKey(R);
    }

    private static SecretKey randomKey(SecureRandom sr)
    {
        byte[] key = new byte[32];
        sr.nextBytes(key);
        return new SecretKeySpec(key, "ChaCha20");
    }

    private static byte[] randomNonce(SecureRandom sr)
    {
        byte[] nonce = new byte[12];
        sr.nextBytes(nonce);
        return nonce;
    }

    private static Cipher cipher(String provider, int mode, SecretKey key, byte[] nonce, int counter)
        throws Exception
    {
        Cipher c = Cipher.getInstance("ChaCha20", provider);
        c.init(mode, key, new ChaCha20ParameterSpec(nonce, counter));
        return c;
    }

    /** Bytes the counter leaves for one nonce: 64 per block up to and including block 2^32 - 1. */
    private static long bytesLeft(int counter)
    {
        return ((1L << 32) - Integer.toUnsignedLong(counter)) * 64;
    }

    /** Feeds msg through update in the given chunk sizes, then doFinal; null chunks means one doFinal. */
    private static byte[] process(Cipher c, byte[] msg, int[] chunks) throws Exception
    {
        if (chunks == null)
        {
            return c.doFinal(msg);
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int off = 0;
        for (int i = 0; off < msg.length; i++)
        {
            int n = Math.min(chunks[i % chunks.length], msg.length - off);
            byte[] o = c.update(msg, off, n);
            if (o != null)
            {
                out.write(o);
            }
            off += n;
        }
        out.write(c.doFinal());
        return out.toByteArray();
    }

    /** ChaCha20ParameterSpec(counter 0) agrees byte-for-byte with BC CHACHA7539. */
    @Test
    public void chaChaParameterSpec_agreesWithBC() throws Exception
    {
        SecretKey key = randomKey();
        byte[] nonce = new byte[12];
        R.nextBytes(nonce);
        byte[] msg = new byte[150];
        R.nextBytes(msg);

        Cipher jsl = Cipher.getInstance("ChaCha20", JSL);
        jsl.init(Cipher.ENCRYPT_MODE, key, new ChaCha20ParameterSpec(nonce, 0));
        byte[] jslCt = jsl.doFinal(msg);

        Cipher bc = Cipher.getInstance("CHACHA7539", "BC");
        bc.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(nonce));
        Assertions.assertArrayEquals(bc.doFinal(msg), jslCt);
    }

    /**
     * Random key, nonce and message at counters across the whole unsigned range, including the int sign boundary,
     * one-shot and chunked, both directions against SunJCE. Messages stop at the per-nonce limit.
     */
    @Test
    public void agreesWithSunJce_acrossTheCounterRange() throws Exception
    {
        SecureRandom sr = seededRandom("agreesWithSunJce_acrossTheCounterRange");
        int[] fixed = {1, 42, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFE, 0xFFFFFFFF};
        int[][] chunkings = {null, {1}, {63}, {64}, {65}, {7, 64, 13}};
        for (int trial = 0; trial < 30; trial++)
        {
            int counter = trial < fixed.length ? fixed[trial] : sr.nextInt();
            SecretKey key = randomKey(sr);
            byte[] nonce = randomNonce(sr);
            byte[] msg = new byte[(int) Math.min(1 + sr.nextInt(300), bytesLeft(counter))];
            sr.nextBytes(msg);
            int[] chunks = chunkings[trial % chunkings.length];
            String label = String.format("counter 0x%08x length %d trial %d", counter, msg.length, trial);

            byte[] sunCt = cipher(SUN, Cipher.ENCRYPT_MODE, key, nonce, counter).doFinal(msg);
            byte[] jslCt = process(cipher(JSL, Cipher.ENCRYPT_MODE, key, nonce, counter), msg, chunks);
            Assertions.assertArrayEquals(sunCt, jslCt, label + " encrypt");
            Assertions.assertArrayEquals(msg,
                process(cipher(JSL, Cipher.DECRYPT_MODE, key, nonce, counter), sunCt, chunks), label + " decrypt");
        }
    }

    /**
     * The BouncyCastle reference for the counter path, beside the SunJCE one: ChaCha7539Engine positioned with
     * seekTo at block counter c over a random message equals JSL under ChaCha20ParameterSpec(nonce, c), one-shot
     * and chunked, both directions. The engine stops one block before the RFC 8439 limit, so each message ends
     * short of it and counter 2^32 - 1 is not drawn.
     */
    @Test
    public void agreesWithBouncyCastleEngine_acrossTheCounterRange() throws Exception
    {
        SecureRandom sr = seededRandom("agreesWithBouncyCastleEngine_acrossTheCounterRange");
        int[] fixed = {1, 42, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFE};
        int[][] chunkings = {null, {1}, {63}, {64}, {65}, {7, 64, 13}};
        for (int trial = 0; trial < 30; trial++)
        {
            int counter = trial < fixed.length ? fixed[trial] : sr.nextInt();
            if (counter == 0xFFFFFFFF)
            {
                counter = 0xFFFFFFFE;
            }
            byte[] keyBytes = new byte[32];
            sr.nextBytes(keyBytes);
            SecretKey key = new SecretKeySpec(keyBytes, "ChaCha20");
            byte[] nonce = randomNonce(sr);
            byte[] msg = new byte[(int) Math.min(1 + sr.nextInt(300), bytesLeft(counter) - 1)];
            sr.nextBytes(msg);
            int[] chunks = chunkings[trial % chunkings.length];
            String label = String.format("counter 0x%08x length %d trial %d", counter, msg.length, trial);

            ChaCha7539Engine engine = new ChaCha7539Engine();
            engine.init(true, new ParametersWithIV(new KeyParameter(keyBytes), nonce));
            engine.seekTo(Integer.toUnsignedLong(counter) * 64);
            byte[] bcCt = new byte[msg.length];
            engine.processBytes(msg, 0, msg.length, bcCt, 0);

            byte[] jslCt = process(cipher(JSL, Cipher.ENCRYPT_MODE, key, nonce, counter), msg, chunks);
            Assertions.assertArrayEquals(bcCt, jslCt, label + " JSL encrypt");
            Assertions.assertArrayEquals(msg,
                process(cipher(JSL, Cipher.DECRYPT_MODE, key, nonce, counter), bcCt, chunks), label + " JSL decrypt");
        }
    }

    /**
     * A 16-byte keystream at an arbitrary counter, the DTLS 1.3 record-number mask shape (RFC 9147 4.2.3), equals
     * the JDK's, and the keystream at counter c + 1 is bytes 64 to 79 of the keystream at counter c.
     */
    @Test
    public void sixteenByteMaskAtAnArbitraryCounter_equalsTheJdk() throws Exception
    {
        SecureRandom sr = seededRandom("sixteenByteMaskAtAnArbitraryCounter_equalsTheJdk");
        for (int trial = 0; trial < 25; trial++)
        {
            int counter = sr.nextInt();
            if (counter == 0xFFFFFFFF)
            {
                counter = 0;
            }
            SecretKey key = randomKey(sr);
            byte[] nonce = randomNonce(sr);
            String label = String.format("counter 0x%08x", counter);

            byte[] mask = cipher(JSL, Cipher.ENCRYPT_MODE, key, nonce, counter).doFinal(new byte[16]);
            Assertions.assertArrayEquals(cipher(SUN, Cipher.ENCRYPT_MODE, key, nonce, counter)
                .doFinal(new byte[16]), mask, label);

            byte[] twoBlocks = cipher(JSL, Cipher.ENCRYPT_MODE, key, nonce, counter).doFinal(new byte[128]);
            byte[] next = cipher(JSL, Cipher.ENCRYPT_MODE, key, nonce, counter + 1).doFinal(new byte[16]);
            Assertions.assertArrayEquals(Arrays.copyOfRange(twoBlocks, 64, 80), next, label + " next block");
            Assertions.assertFalse(Arrays.areEqual(mask, next), label + " distinct counters");
        }
    }

    private static final int MONTE_CARLO_SAMPLES = 300000;

    /**
     * Monte Carlo over the nonce and the counter: each sample draws a fresh key, nonce, counter and 1 to 64 byte
     * message ending short of BouncyCastle's limit, and JSL must equal ChaCha7539Engine positioned with seekTo and
     * round-trip through its own decrypt on every sample.
     */
    @Test
    public void monteCarloOverTheNonceAndCounter_agreesWithBouncyCastleEngine() throws Exception
    {
        SecureRandom sr = seededRandom("monteCarloOverTheNonceAndCounter_agreesWithBouncyCastleEngine");
        Cipher jsl = Cipher.getInstance("ChaCha20", JSL);
        ChaCha7539Engine engine = new ChaCha7539Engine();
        for (int i = 0; i < MONTE_CARLO_SAMPLES; i++)
        {
            int counter = sr.nextInt();
            if (counter == 0xFFFFFFFF)
            {
                counter = 0xFFFFFFFE;
            }
            byte[] keyBytes = new byte[32];
            byte[] nonce = new byte[12];
            byte[] msg = new byte[(int) Math.min(1 + sr.nextInt(64), bytesLeft(counter) - 1)];
            sr.nextBytes(keyBytes);
            sr.nextBytes(nonce);
            sr.nextBytes(msg);
            SecretKey key = new SecretKeySpec(keyBytes, "ChaCha20");
            ChaCha20ParameterSpec spec = new ChaCha20ParameterSpec(nonce, counter);
            String sample = String.format("sample %d nonce %s counter 0x%08x length %d", i, Hex.toHexString(nonce),
                counter, msg.length);

            engine.init(true, new ParametersWithIV(new KeyParameter(keyBytes), nonce));
            engine.seekTo(Integer.toUnsignedLong(counter) * 64);
            byte[] bcCt = new byte[msg.length];
            engine.processBytes(msg, 0, msg.length, bcCt, 0);

            jsl.init(Cipher.ENCRYPT_MODE, key, spec);
            byte[] jslCt = jsl.doFinal(msg);
            if (!Arrays.areEqual(bcCt, jslCt))
            {
                Assertions.fail(sample + ": ciphertext differs from BouncyCastle");
            }

            jsl.init(Cipher.DECRYPT_MODE, key, spec);
            if (!Arrays.areEqual(msg, jsl.doFinal(jslCt)))
            {
                Assertions.fail(sample + ": decrypt does not round-trip");
            }
        }
    }
}
