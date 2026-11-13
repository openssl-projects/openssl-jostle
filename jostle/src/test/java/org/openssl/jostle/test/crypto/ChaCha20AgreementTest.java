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
import org.openssl.jostle.jcajce.spec.ChaCha20CounterParameterSpec;
import org.openssl.jostle.test.util.CipherFamilies;
import org.openssl.jostle.test.util.CipherSurfaceDriver;
import org.openssl.jostle.test.util.KeyGeneratorSurfaceDriver;
import org.openssl.jostle.test.util.ProviderSurfaceGuard;
import org.openssl.jostle.util.Arrays;
import org.openssl.jostle.util.encoders.Hex;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.SecureRandom;
import java.security.Security;
import java.io.ByteArrayOutputStream;

import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Agreement between BouncyCastle (CHACHA7539, the RFC 7539 / 8439 12-byte-nonce
 * engine) and Jostle for raw ChaCha20, plus chunking, negative-path, reset and
 * boundary coverage. Raw ChaCha20 has no authentication; its cross-validation
 * anchor is BouncyCastle on every leg. RFC 8439 A.2 Test Vector 1 is at counter 0
 * and ChaCha20ParameterSpecTest runs it.
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
        ByteArrayOutputStream out = new ByteArrayOutputStream();
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
        ByteArrayOutputStream out = new ByteArrayOutputStream();
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

    /**
     * A key tagged "ChaCha7539" — BouncyCastle's name for this same RFC 7539 /
     * 8439 engine, and what bc-java's {@code JceChaCha20Poly1305} builds its
     * record-key {@code SecretKeySpec} with — must be accepted by the ChaCha20
     * cipher under either cipher-name spelling. Each accepted alias must not
     * only init without throwing but key the cipher identically to a plain
     * "ChaCha20"-tagged key, proving the match selects the same key material
     * rather than merely that init was permissive.
     */
    @Test
    public void acceptsChaCha7539KeyAlgorithmSpelling() throws Exception
    {
        SecureRandom sr = seededRandom("acceptsChaCha7539KeyAlgorithmSpelling");
        byte[] keyBytes = new byte[32];
        sr.nextBytes(keyBytes);
        byte[] nonce = new byte[12];
        sr.nextBytes(nonce);
        byte[] pt = new byte[1 + sr.nextInt(200)];
        sr.nextBytes(pt);

        Cipher ref = Cipher.getInstance(JSL_NAME, JSL);
        ref.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(keyBytes, "ChaCha20"), new IvParameterSpec(nonce));
        byte[] refCt = ref.doFinal(pt);

        String[] cipherNames = {JSL_NAME, BC_NAME};
        String[] keyAliases = {"ChaCha7539", "CHACHA7539", "chacha7539"};
        for (String cipherName : cipherNames)
        {
            for (String keyAlias : keyAliases)
            {
                String where = cipherName + "/" + keyAlias;

                Cipher enc = Cipher.getInstance(cipherName, JSL);
                enc.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(keyBytes, keyAlias), new IvParameterSpec(nonce));
                byte[] ct = enc.doFinal(pt);
                Assertions.assertTrue(Arrays.areEqual(refCt, ct),
                        where + ": did not encrypt identically to a ChaCha20-tagged key");

                Cipher dec = Cipher.getInstance(cipherName, JSL);
                dec.init(Cipher.DECRYPT_MODE, new SecretKeySpec(keyBytes, keyAlias), new IvParameterSpec(nonce));
                Assertions.assertTrue(Arrays.areEqual(pt, dec.doFinal(ct)),
                        where + ": round-trip failed for accepted key algorithm");
            }
        }

        // The same spelling is accepted by the AEAD SPI, which shares the
        // "ChaCha20" key algorithm.
        Cipher aeadRef = Cipher.getInstance("ChaCha20-Poly1305", JSL);
        aeadRef.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(keyBytes, "ChaCha20"), new IvParameterSpec(nonce));
        byte[] aeadCt = aeadRef.doFinal(pt);

        Cipher aead = Cipher.getInstance("ChaCha20-Poly1305", JSL);
        aead.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(keyBytes, "ChaCha7539"), new IvParameterSpec(nonce));
        Assertions.assertTrue(Arrays.areEqual(aeadCt, aead.doFinal(pt)),
                "ChaCha20-Poly1305: ChaCha7539-tagged key did not encrypt identically");

        // Not a blanket accept: BouncyCastle's original 8-byte-nonce "ChaCha" is
        // a different algorithm and stays rejected, as does an unrelated family.
        for (String rejected : new String[]{"ChaCha", "Salsa20", "AES"})
        {
            Cipher c = Cipher.getInstance(JSL_NAME, JSL);
            InvalidKeyException ex = assertThrows(InvalidKeyException.class,
                    () -> c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(keyBytes, rejected),
                            new IvParameterSpec(nonce)), rejected);
            Assertions.assertEquals("unsupported key algorithm " + rejected, ex.getMessage());
        }
    }

    /**
     * The BouncyCastle-spelled key algorithm agrees with BouncyCastle, both
     * directions — the exact configuration bc-java's TLS layer uses, where
     * {@code JceChaCha20Poly1305} fetches a "ChaCha7539" cipher and keys it with
     * a {@code SecretKeySpec(..., "ChaCha7539")}.
     *
     * <p>Distinct from {@link #acceptsChaCha7539KeyAlgorithmSpelling()}, which
     * proves the alias selects the same key material but never leaves Jostle,
     * and from {@link #agreesWithBC_bothDirections()}, which crosses to BC but
     * with a "ChaCha20"-tagged key. Only this test does both at once.
     */
    @Test
    public void chaCha7539KeyAlgorithm_agreesWithBC_bothDirections() throws Exception
    {
        SecureRandom sr = seededRandom("chaCha7539KeyAlgorithm_agreesWithBC_bothDirections");

        for (int trial = 0; trial < 25; trial++)
        {
            byte[] keyBytes = new byte[32];
            sr.nextBytes(keyBytes);
            SecretKey key = new SecretKeySpec(keyBytes, "ChaCha7539");
            byte[] nonce = new byte[12];
            sr.nextBytes(nonce);
            byte[] msg = new byte[sr.nextInt(400)];
            sr.nextBytes(msg);
            IvParameterSpec iv = new IvParameterSpec(nonce);

            Cipher jslEnc = Cipher.getInstance(BC_NAME, JSL);
            jslEnc.init(Cipher.ENCRYPT_MODE, key, iv);
            byte[] jslCt = jslEnc.doFinal(msg);

            Cipher bcEnc = Cipher.getInstance(BC_NAME, BC);
            bcEnc.init(Cipher.ENCRYPT_MODE, key, iv);
            byte[] bcCt = bcEnc.doFinal(msg);
            Assertions.assertArrayEquals(bcCt, jslCt, "ciphertext (trial " + trial + ")");

            // BC-encrypt -> JSL-decrypt and JSL-encrypt -> BC-decrypt.
            Cipher jslDec = Cipher.getInstance(BC_NAME, JSL);
            jslDec.init(Cipher.DECRYPT_MODE, key, iv);
            Assertions.assertArrayEquals(msg, jslDec.doFinal(bcCt), "BC-enc/JSL-dec");

            Cipher bcDec = Cipher.getInstance(BC_NAME, BC);
            bcDec.init(Cipher.DECRYPT_MODE, key, iv);
            Assertions.assertArrayEquals(msg, bcDec.doFinal(jslCt), "JSL-enc/BC-dec");
        }
    }

    // ---------------------------------------------------------------
    // Cipher completeness guard (MT-4)
    // ---------------------------------------------------------------



    /**
     * Every {@code Cipher} name ProvChaCha20 registers is DRIVEN — a real
     * encrypt/decrypt round trip on the name as registered, not a
     * {@code getInstance} that asserts non-null. See
     * {@link CipherSurfaceDriver}.
     */
    @Test
    public void everyRegisteredChaCha20CipherIsDriven() throws Exception
    {
        CipherSurfaceDriver.driveWholeSurface(
                Security.getProvider(JostleProvider.PROVIDER_NAME),
                CipherFamilies.CHACHA20_PREFIX, "ChaCha20", CipherFamilies.CHACHA20,
                seededRandom("everyRegisteredChaCha20CipherIsDriven"));
    }

    /**
     * Every {@code KeyGenerator} name ProvChaCha20 registers is DRIVEN,
     * discovered rather than listed, aliases included — the bare name plus
     * {@code ChaCha20-Poly1305} and the two OID spellings, four in all where
     * {@code getServices()} shows one.
     */
    @Test
    public void everyRegisteredChaCha20KeyGeneratorIsDriven()
    {
        ProviderSurfaceGuard.assertEveryServiceDriven(
                Security.getProvider(JostleProvider.PROVIDER_NAME),
                CipherFamilies.CHACHA20_PREFIX, "ChaCha20 KeyGenerator (JSL)",
                new String[]{"KeyGenerator"},
                KeyGeneratorSurfaceDriver.forProvider(
                        JostleProvider.PROVIDER_NAME, CipherFamilies.CHACHA20_KEYGEN, "ChaCha20", 64));
    }

    private static final int MONTE_CARLO_SAMPLES = 300000;

    /**
     * Monte Carlo over the nonce at counter 0: each sample draws a fresh key, nonce and 1 to 64 byte message, and
     * JSL must equal BouncyCastle and round-trip through its own decrypt on every sample.
     */
    @Test
    public void monteCarloOverTheNonce_agreesWithBC() throws Exception
    {
        SecureRandom sr = seededRandom("monteCarloOverTheNonce_agreesWithBC");
        Cipher jsl = Cipher.getInstance(JSL_NAME, JSL);
        Cipher bc = Cipher.getInstance(BC_NAME, BC);
        for (int i = 0; i < MONTE_CARLO_SAMPLES; i++)
        {
            byte[] keyBytes = new byte[32];
            byte[] nonce = new byte[12];
            byte[] msg = new byte[1 + sr.nextInt(64)];
            sr.nextBytes(keyBytes);
            sr.nextBytes(nonce);
            sr.nextBytes(msg);
            SecretKeySpec key = new SecretKeySpec(keyBytes, "ChaCha20");
            IvParameterSpec iv = new IvParameterSpec(nonce);

            jsl.init(Cipher.ENCRYPT_MODE, key, iv);
            byte[] jslCt = jsl.doFinal(msg);
            bc.init(Cipher.ENCRYPT_MODE, key, iv);
            byte[] bcCt = bc.doFinal(msg);
            if (!Arrays.areEqual(bcCt, jslCt))
            {
                Assertions.fail("sample " + i + " nonce " + Hex.toHexString(nonce) + " length " + msg.length
                    + ": ciphertext differs from BouncyCastle");
            }

            jsl.init(Cipher.DECRYPT_MODE, key, iv);
            if (!Arrays.areEqual(msg, jsl.doFinal(jslCt)))
            {
                Assertions.fail("sample " + i + " nonce " + Hex.toHexString(nonce) + " length " + msg.length
                    + ": decrypt does not round-trip");
            }
        }
    }

    private static Cipher counterCipher(int mode, SecretKey key, byte[] nonce, int counter) throws Exception
    {
        Cipher c = Cipher.getInstance(JSL_NAME, JSL);
        c.init(mode, key, new ChaCha20CounterParameterSpec(nonce, counter));
        return c;
    }

    /** Bytes the counter leaves for one nonce: 64 per block up to and including block 2^32 - 1. */
    private static long bytesLeft(int counter)
    {
        return ((1L << 32) - (counter & 0xFFFFFFFFL)) * 64;
    }

    /** BouncyCastle's ChaCha7539Engine positioned at block counter c, applied to msg. */
    private static byte[] engineAt(byte[] keyBytes, byte[] nonce, int counter, byte[] msg)
    {
        ChaCha7539Engine engine = new ChaCha7539Engine();
        engine.init(true, new ParametersWithIV(new KeyParameter(keyBytes), nonce));
        engine.seekTo((counter & 0xFFFFFFFFL) * 64);
        byte[] out = new byte[msg.length];
        engine.processBytes(msg, 0, msg.length, out, 0);
        return out;
    }

    /** Feeds msg through update in the given chunk sizes, then doFinal; null chunks means one doFinal. */
    private static byte[] processChunked(Cipher c, byte[] msg, int[] chunks) throws Exception
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

    /** ChaCha20CounterParameterSpec at counter 0 agrees byte for byte with BouncyCastle's CHACHA7539. */
    @Test
    public void counterSpecAtCounterZero_agreesWithBC() throws Exception
    {
        SecureRandom sr = seededRandom("counterSpecAtCounterZero_agreesWithBC");
        byte[] keyBytes = new byte[32];
        byte[] nonce = new byte[12];
        byte[] msg = new byte[150];
        sr.nextBytes(keyBytes);
        sr.nextBytes(nonce);
        sr.nextBytes(msg);
        SecretKey key = new SecretKeySpec(keyBytes, "ChaCha20");

        byte[] jslCt = counterCipher(Cipher.ENCRYPT_MODE, key, nonce, 0).doFinal(msg);
        Cipher bc = Cipher.getInstance(BC_NAME, BC);
        bc.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(nonce));
        Assertions.assertArrayEquals(bc.doFinal(msg), jslCt);
    }

    /**
     * The BouncyCastle reference for the counter path: ChaCha7539Engine positioned with seekTo at block counter c
     * equals JSL under ChaCha20CounterParameterSpec(nonce, c), one-shot and chunked, both directions. The engine
     * stops one block before the RFC 8439 limit, so each message ends short of it and 2^32 - 1 is not drawn.
     */
    @Test
    public void counterSpec_agreesWithBouncyCastleEngine_acrossTheCounterRange() throws Exception
    {
        SecureRandom sr = seededRandom("counterSpec_agreesWithBouncyCastleEngine_acrossTheCounterRange");
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
            byte[] nonce = new byte[12];
            sr.nextBytes(nonce);
            byte[] msg = new byte[(int) Math.min(1 + sr.nextInt(300), bytesLeft(counter) - 1)];
            sr.nextBytes(msg);
            int[] chunks = chunkings[trial % chunkings.length];
            String label = String.format("counter 0x%08x length %d trial %d", counter, msg.length, trial);

            byte[] bcCt = engineAt(keyBytes, nonce, counter, msg);
            Cipher enc = counterCipher(Cipher.ENCRYPT_MODE, key, nonce, counter);
            Assertions.assertArrayEquals(bcCt, processChunked(enc, msg, chunks), label + " encrypt");
            Cipher dec = counterCipher(Cipher.DECRYPT_MODE, key, nonce, counter);
            Assertions.assertArrayEquals(msg, processChunked(dec, bcCt, chunks), label + " decrypt");
        }
    }

    /**
     * A 16-byte keystream at an arbitrary counter, the DTLS 1.3 record-number mask shape (RFC 9147 4.2.3), equals
     * BouncyCastle's engine, and the keystream at counter c + 1 is bytes 64 to 79 of the keystream at counter c.
     */
    @Test
    public void counterSpec_sixteenByteMaskAtAnArbitraryCounter_agreesWithBouncyCastleEngine() throws Exception
    {
        SecureRandom sr = seededRandom("counterSpec_sixteenByteMaskAtAnArbitraryCounter_agreesWithBouncyCastleEngine");
        for (int trial = 0; trial < 25; trial++)
        {
            int counter = sr.nextInt();
            if (counter == 0xFFFFFFFF || counter == 0xFFFFFFFE)
            {
                counter = 0;
            }
            byte[] keyBytes = new byte[32];
            sr.nextBytes(keyBytes);
            SecretKey key = new SecretKeySpec(keyBytes, "ChaCha20");
            byte[] nonce = new byte[12];
            sr.nextBytes(nonce);
            String label = String.format("counter 0x%08x", counter);

            byte[] mask = counterCipher(Cipher.ENCRYPT_MODE, key, nonce, counter).doFinal(new byte[16]);
            Assertions.assertArrayEquals(engineAt(keyBytes, nonce, counter, new byte[16]), mask, label);

            byte[] twoBlocks = counterCipher(Cipher.ENCRYPT_MODE, key, nonce, counter).doFinal(new byte[128]);
            byte[] next = counterCipher(Cipher.ENCRYPT_MODE, key, nonce, counter + 1).doFinal(new byte[16]);
            Assertions.assertArrayEquals(Arrays.copyOfRange(twoBlocks, 64, 80), next, label + " next block");
            Assertions.assertFalse(Arrays.areEqual(mask, next), label + " distinct counters");
        }
    }

    /**
     * Monte Carlo over the nonce and the counter through ChaCha20CounterParameterSpec: each sample draws a fresh
     * key, nonce, counter and 1 to 64 byte message ending short of BouncyCastle's limit, and JSL must equal
     * ChaCha7539Engine positioned with seekTo and round-trip through its own decrypt on every sample.
     */
    @Test
    public void monteCarloOverTheNonceAndCounter_agreesWithBouncyCastleEngine() throws Exception
    {
        SecureRandom sr = seededRandom("monteCarloOverTheNonceAndCounter_agreesWithBouncyCastleEngine");
        Cipher jsl = Cipher.getInstance(JSL_NAME, JSL);
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
            ChaCha20CounterParameterSpec spec = new ChaCha20CounterParameterSpec(nonce, counter);
            String sample = String.format("sample %d nonce %s counter 0x%08x length %d", i, Hex.toHexString(nonce),
                counter, msg.length);

            engine.init(true, new ParametersWithIV(new KeyParameter(keyBytes), nonce));
            engine.seekTo((counter & 0xFFFFFFFFL) * 64);
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
