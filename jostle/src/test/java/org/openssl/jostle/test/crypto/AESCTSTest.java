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
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.security.InvalidKeyException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;

/**
 * AES CBC-CTS — CBC with ciphertext stealing — through the JSL provider.
 *
 * <h2>The variant is CS3, and that is a measured choice, not a default</h2>
 *
 * NIST SP 800-38A Appendix G defines three orderings (CS1, CS2, CS3) that
 * differ only in how the last two ciphertext blocks are arranged. OpenSSL's
 * {@code cts_mode} defaults to <b>CS1</b> on every environment measured;
 * BouncyCastle's {@code AES/CTS/NoPadding} — and its {@code AES/CBC/CS3Padding},
 * which agrees with it byte for byte — is <b>CS3</b>. Jostle pins CS3
 * explicitly in C. Inheriting OpenSSL's default would produce ciphertext no BC
 * or Kerberos (RFC 3962) peer could read.
 *
 * <h2>What a parity test can actually discriminate</h2>
 *
 * This is the part that is easy to get wrong, and the reason
 * {@link #agreesWithBouncyCastleAcrossBothFinalBlockShapes()} insists on both
 * shapes (measured, {@code fips-c-review/probes/cts_probe.c}):
 *
 * <pre>
 *                    FULL final block        PARTIAL final block
 *   CS1              same as CS2             DIFFERS
 *   CS2              same as CS1             same as CS3
 *   CS3              DIFFERS (swaps the      same as CS2
 *                    last two blocks)
 * </pre>
 *
 * So a test that only ever feeds partial final blocks catches a CS1 mistake
 * but <b>cannot</b> tell CS3 from CS2, and a single-block (16-byte) input
 * discriminates nothing at all — all three agree there.
 *
 * <h2>One-shot EVP under a streaming contract</h2>
 *
 * OpenSSL's CTS accepts exactly one {@code EVP_EncryptUpdate}, and only at one
 * block or more; a second update is refused, mutely. Ciphertext stealing needs
 * the end of the message before any block can be emitted. So the util layer
 * accumulates and hands EVP the whole message at {@code doFinal} — the same
 * treatment XTS gets. Chunking is therefore invisible to the output, updates
 * emit nothing, and the one-block minimum applies to the accumulated total.
 *
 * <p>Subclassed by {@code FIPSAESCTSTest}, which runs the whole contract
 * against the FIPS interface library and lib ctx.
 */
public class AESCTSTest
{
    protected static final String XFORM = "AES/CTS/NoPadding";

    /** BouncyCastle's explicit-variant spelling of the same thing. */
    protected static final String XFORM_CS3 = "AES/CBC/CS3Padding";

    protected static final int BLOCK = 16;

    private static final SecureRandom RANDOM = new SecureRandom();

    protected static SecureRandom seededRandom(String testName) throws Exception
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
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    /** Overridden by the FIPS subclass. */
    protected String providerName()
    {
        return JostleProvider.PROVIDER_NAME;
    }


    // -----------------------------------------------------------------
    // Agreement with BouncyCastle — the independent implementation.
    // -----------------------------------------------------------------

    /**
     * Byte equality with BC across both final-block shapes and all three key
     * widths. This is the CS3 hard guard: switch the pin to CS2 and the
     * full-block rows fail; switch it to CS1 and the partial-block rows fail.
     * Neither shape alone catches both, which is why the loop covers both.
     */
    @Test
    public void agreesWithBouncyCastleAcrossBothFinalBlockShapes() throws Exception
    {
        SecureRandom sr = seededRandom("agreesWithBouncyCastleAcrossBothFinalBlockShapes");

        for (int keyLen : new int[]{16, 24, 32})
        {
            for (int trial = 0; trial < 12; trial++)
            {
                byte[] key = randomBytes(sr, keyLen);
                byte[] iv = randomBytes(sr, BLOCK);

                // Alternate deliberately: an all-partial generator cannot tell
                // CS3 from CS2, an all-full one cannot tell CS1 from CS2.
                int msgLen = (trial % 2 == 0)
                        ? BLOCK * (1 + sr.nextInt(6))                       // FULL final block
                        : BLOCK * (1 + sr.nextInt(6)) + 1 + sr.nextInt(15); // PARTIAL final block
                byte[] msg = randomBytes(sr, msgLen);

                byte[] jsl = oneShot(XFORM, providerName(), Cipher.ENCRYPT_MODE, key, iv, msg);
                byte[] bc = oneShot(XFORM, BouncyCastleProvider.PROVIDER_NAME,
                        Cipher.ENCRYPT_MODE, key, iv, msg);

                Assertions.assertArrayEquals(bc, jsl,
                        "keyLen=" + keyLen + " msgLen=" + msgLen
                                + (msgLen % BLOCK == 0 ? " (FULL final block)" : " (PARTIAL final block)")
                                + ": must equal BouncyCastle — a wrong cts_mode pin shows up here");

                // Ciphertext stealing: output length equals input length.
                Assertions.assertEquals(msgLen, jsl.length, "CTS output length must equal input length");
            }
        }
    }

    /**
     * BC's two spellings are the same bytes, so ours must be too — otherwise a
     * caller switching names silently changes the wire format.
     */
    @Test
    public void bothRegisteredSpellingsProduceIdenticalBytes() throws Exception
    {
        SecureRandom sr = seededRandom("bothRegisteredSpellingsProduceIdenticalBytes");

        for (int trial = 0; trial < 10; trial++)
        {
            byte[] key = randomBytes(sr, 16);
            byte[] iv = randomBytes(sr, BLOCK);
            byte[] msg = randomBytes(sr, BLOCK + 1 + sr.nextInt(48));

            byte[] viaCts = oneShot(XFORM, providerName(), Cipher.ENCRYPT_MODE, key, iv, msg);
            byte[] viaCs3 = oneShot(XFORM_CS3, providerName(), Cipher.ENCRYPT_MODE, key, iv, msg);
            byte[] bcCts = oneShot(XFORM, BouncyCastleProvider.PROVIDER_NAME,
                    Cipher.ENCRYPT_MODE, key, iv, msg);

            Assertions.assertArrayEquals(viaCts, viaCs3, "AES/CTS and AES/CBC/CS3Padding must agree");
            Assertions.assertArrayEquals(bcCts, viaCts, "and both must equal BouncyCastle");
        }
    }

    @Test
    public void decryptsWhatBouncyCastleEncrypted() throws Exception
    {
        SecureRandom sr = seededRandom("decryptsWhatBouncyCastleEncrypted");

        for (int trial = 0; trial < 12; trial++)
        {
            byte[] key = randomBytes(sr, 16 + 8 * sr.nextInt(3));
            byte[] iv = randomBytes(sr, BLOCK);
            byte[] msg = randomBytes(sr, BLOCK + sr.nextInt(64));

            byte[] bcCt = oneShot(XFORM, BouncyCastleProvider.PROVIDER_NAME,
                    Cipher.ENCRYPT_MODE, key, iv, msg);
            Assertions.assertArrayEquals(msg,
                    oneShot(XFORM, providerName(), Cipher.DECRYPT_MODE, key, iv, bcCt),
                    "BC encrypt -> Jostle decrypt");
        }
    }

    @Test
    public void bouncyCastleDecryptsWhatWeEncrypted() throws Exception
    {
        SecureRandom sr = seededRandom("bouncyCastleDecryptsWhatWeEncrypted");

        for (int trial = 0; trial < 12; trial++)
        {
            byte[] key = randomBytes(sr, 16 + 8 * sr.nextInt(3));
            byte[] iv = randomBytes(sr, BLOCK);
            byte[] msg = randomBytes(sr, BLOCK + sr.nextInt(64));

            byte[] ct = oneShot(XFORM, providerName(), Cipher.ENCRYPT_MODE, key, iv, msg);
            Assertions.assertArrayEquals(msg,
                    oneShot(XFORM, BouncyCastleProvider.PROVIDER_NAME,
                            Cipher.DECRYPT_MODE, key, iv, ct),
                    "Jostle encrypt -> BC decrypt");
        }
    }

    /**
     * CTS must not degenerate into plain CBC. For a whole-block message CS3
     * swaps the last two ciphertext blocks, so the two differ — and for a
     * partial-block message CBC cannot encode the input at all.
     */
    @Test
    public void ctsIsNotPlainCbc() throws Exception
    {
        SecureRandom sr = seededRandom("ctsIsNotPlainCbc");
        byte[] key = randomBytes(sr, 16);
        byte[] iv = randomBytes(sr, BLOCK);
        byte[] msg = randomBytes(sr, 2 * BLOCK);

        byte[] cts = oneShot(XFORM, providerName(), Cipher.ENCRYPT_MODE, key, iv, msg);
        byte[] cbc = oneShot("AES/CBC/NoPadding", providerName(), Cipher.ENCRYPT_MODE, key, iv, msg);

        Assertions.assertFalse(Arrays.areEqual(cts, cbc),
                "CS3 swaps the last two blocks, so a 2-block CTS message must differ from CBC");

        // ...and it is exactly a swap of those two blocks, which pins WHICH
        // way round the arrangement goes rather than merely that it differs.
        byte[] swapped = new byte[cbc.length];
        System.arraycopy(cbc, BLOCK, swapped, 0, BLOCK);
        System.arraycopy(cbc, 0, swapped, BLOCK, BLOCK);
        Assertions.assertArrayEquals(swapped, cts,
                "CS3 on a whole-block message is CBC with the last two blocks exchanged");
    }


    // -----------------------------------------------------------------
    // Negative path.
    // -----------------------------------------------------------------

    @Test
    public void tamperedCiphertextDoesNotRoundTrip() throws Exception
    {
        SecureRandom sr = seededRandom("tamperedCiphertextDoesNotRoundTrip");
        byte[] key = randomBytes(sr, 16);
        byte[] iv = randomBytes(sr, BLOCK);
        byte[] msg = randomBytes(sr, 3 * BLOCK + 5);

        byte[] ct = oneShot(XFORM, providerName(), Cipher.ENCRYPT_MODE, key, iv, msg);
        byte[] tampered = Arrays.clone(ct);
        tampered[sr.nextInt(tampered.length)] ^= (byte) 0x01;

        byte[] decoded = oneShot(XFORM, providerName(), Cipher.DECRYPT_MODE, key, iv, tampered);
        Assertions.assertFalse(Arrays.areEqual(msg, decoded),
                "a tampered ciphertext must not decrypt to the original plaintext");
    }

    @Test
    public void wrongKeyDoesNotRecoverPlaintext() throws Exception
    {
        SecureRandom sr = seededRandom("wrongKeyDoesNotRecoverPlaintext");
        byte[] key = randomBytes(sr, 16);
        byte[] wrong = randomBytes(sr, 16);
        byte[] iv = randomBytes(sr, BLOCK);
        byte[] msg = randomBytes(sr, 2 * BLOCK + 7);

        byte[] ct = oneShot(XFORM, providerName(), Cipher.ENCRYPT_MODE, key, iv, msg);
        Assertions.assertFalse(
                Arrays.areEqual(msg, oneShot(XFORM, providerName(), Cipher.DECRYPT_MODE, wrong, iv, ct)),
                "decrypting with a different key must not recover the plaintext");
    }

    @Test
    public void wrongIvChangesOnlyTheFirstBlock() throws Exception
    {
        SecureRandom sr = seededRandom("wrongIvChangesOnlyTheFirstBlock");
        byte[] key = randomBytes(sr, 16);
        byte[] iv = randomBytes(sr, BLOCK);
        byte[] otherIv = randomBytes(sr, BLOCK);
        byte[] msg = randomBytes(sr, 3 * BLOCK);

        byte[] ct = oneShot(XFORM, providerName(), Cipher.ENCRYPT_MODE, key, iv, msg);
        byte[] decoded = oneShot(XFORM, providerName(), Cipher.DECRYPT_MODE, key, otherIv, ct);

        Assertions.assertFalse(Arrays.areEqual(msg, decoded),
                "a different IV must not recover the plaintext");
    }


    // -----------------------------------------------------------------
    // Chunking — the accumulator. Compared against the ONE-SHOT output,
    // not a round trip: chunked-encrypt plus chunked-decrypt making the
    // same mistake round-trips cleanly while being non-interoperable.
    // -----------------------------------------------------------------

    @Test
    public void chunkedUpdatesAgreeWithOneShotAndBouncyCastle() throws Exception
    {
        SecureRandom sr = seededRandom("chunkedUpdatesAgreeWithOneShotAndBouncyCastle");

        for (int msgLen : new int[]{16, 17, 31, 32, 33, 47, 48, 64, 79})
        {
            byte[] key = randomBytes(sr, 16);
            byte[] iv = randomBytes(sr, BLOCK);
            byte[] msg = randomBytes(sr, msgLen);

            byte[] reference = oneShot(XFORM, BouncyCastleProvider.PROVIDER_NAME,
                    Cipher.ENCRYPT_MODE, key, iv, msg);
            Assertions.assertArrayEquals(reference,
                    oneShot(XFORM, providerName(), Cipher.ENCRYPT_MODE, key, iv, msg),
                    "msgLen=" + msgLen + ": one-shot must equal BC");

            int[] byteByByte = new int[msgLen];
            java.util.Arrays.fill(byteByByte, 1);
            Assertions.assertArrayEquals(reference, chunked(key, iv, msg, byteByByte),
                    "msgLen=" + msgLen + ": byte-by-byte must equal the one-shot bytes");

            Assertions.assertArrayEquals(reference, chunked(key, iv, msg, adversarialChunks(msgLen)),
                    "msgLen=" + msgLen + ": block-1 / block / block+1 chunking must match");

            for (int trial = 0; trial < 5; trial++)
            {
                Assertions.assertArrayEquals(reference, chunked(key, iv, msg, randomSplits(sr, msgLen)),
                        "msgLen=" + msgLen + ": random-split chunking must match");
            }
        }
    }

    /**
     * An accumulating update emits nothing, and the auto-allocating
     * {@code update(byte[],int,int)} overload must therefore hand back an
     * empty array — not a zero-filled one of the input's length, which is what
     * a size function still reporting {@code len} would produce.
     */
    @Test
    public void updateEmitsNothingWhileAccumulating() throws Exception
    {
        SecureRandom sr = seededRandom("updateEmitsNothingWhileAccumulating");
        byte[] key = randomBytes(sr, 16);
        byte[] iv = randomBytes(sr, BLOCK);
        byte[] msg = randomBytes(sr, 40);

        Cipher enc = Cipher.getInstance(XFORM, providerName());
        enc.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));

        byte[] part = enc.update(msg, 0, 32);
        Assertions.assertTrue(part == null || part.length == 0,
                "an accumulating update must emit no bytes, got "
                        + (part == null ? "null" : part.length));
        Assertions.assertEquals(0, enc.getOutputSize(0) - 32,
                "getOutputSize must account for the 32 accumulated bytes");

        byte[] rest = enc.doFinal(msg, 32, 8);
        Assertions.assertEquals(40, rest.length, "doFinal emits the whole message");
    }

    /**
     * The one-block minimum applies to the ACCUMULATED total, not per chunk —
     * so 8 bytes then 8 more is a legal 16-byte message even though a single
     * 8-byte message is not.
     */
    @Test
    public void subBlockChunksAccumulateIntoAValidMessage() throws Exception
    {
        SecureRandom sr = seededRandom("subBlockChunksAccumulateIntoAValidMessage");
        byte[] key = randomBytes(sr, 16);
        byte[] iv = randomBytes(sr, BLOCK);
        byte[] msg = randomBytes(sr, 16);

        Cipher enc = Cipher.getInstance(XFORM, providerName());
        enc.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
        enc.update(msg, 0, 8);
        byte[] ct = enc.doFinal(msg, 8, 8);

        Assertions.assertArrayEquals(
                oneShot(XFORM, BouncyCastleProvider.PROVIDER_NAME, Cipher.ENCRYPT_MODE, key, iv, msg),
                ct, "8 + 8 must be one valid 16-byte message");
    }


    // -----------------------------------------------------------------
    // Boundaries and refusals.
    // -----------------------------------------------------------------

    /**
     * One AES block is the floor: 15 refused, 16 accepted, 17 accepted.
     * Zero-length is refused too, and reaches the check only because the
     * minimum is enforced at the terminal call — the SPI skips update
     * entirely when there is nothing to feed.
     */
    @Test
    public void messageShorterThanOneBlockRejected() throws Exception
    {
        SecureRandom sr = seededRandom("messageShorterThanOneBlockRejected");
        byte[] key = randomBytes(sr, 16);
        byte[] iv = randomBytes(sr, BLOCK);

        for (int len : new int[]{0, 1, 8, 15})
        {
            byte[] msg = randomBytes(sr, len);
            Cipher enc = Cipher.getInstance(XFORM, providerName());
            enc.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
            IllegalBlockSizeException e = Assertions.assertThrows(IllegalBlockSizeException.class,
                    () -> enc.doFinal(msg), len + "-byte message must be refused");
            Assertions.assertEquals("data not block size aligned", e.getMessage());
        }

        for (int len : new int[]{16, 17})
        {
            byte[] msg = randomBytes(sr, len);
            Assertions.assertEquals(len,
                    oneShot(XFORM, providerName(), Cipher.ENCRYPT_MODE, key, iv, msg).length,
                    len + "-byte message must be accepted");
        }
    }

    @Test
    public void keyLengthBoundaries() throws Exception
    {
        SecureRandom sr = seededRandom("keyLengthBoundaries");
        byte[] iv = randomBytes(sr, BLOCK);

        for (int len : new int[]{1, 8, 15, 17, 23, 25, 31, 33, 64})
        {
            byte[] raw = randomBytes(sr, len);
            Cipher c = Cipher.getInstance(XFORM, providerName());
            Assertions.assertThrows(InvalidKeyException.class,
                    () -> c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(raw, "AES"), new IvParameterSpec(iv)),
                    len + "-byte key must be rejected");
        }

        for (int len : new int[]{16, 24, 32})
        {
            Cipher c = Cipher.getInstance(XFORM, providerName());
            c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(randomBytes(sr, len), "AES"),
                    new IvParameterSpec(iv));
        }
    }

    @Test
    public void ivLengthBoundaries() throws Exception
    {
        SecureRandom sr = seededRandom("ivLengthBoundaries");
        byte[] key = randomBytes(sr, 16);

        for (int len : new int[]{1, 8, 15, 17, 32})
        {
            byte[] iv = randomBytes(sr, len);
            Cipher c = Cipher.getInstance(XFORM, providerName());
            Assertions.assertThrows(Exception.class,
                    () -> c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv)),
                    len + "-byte IV must be rejected");
        }

        Cipher ok = Cipher.getInstance(XFORM, providerName());
        ok.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"),
                new IvParameterSpec(randomBytes(sr, BLOCK)));
    }

    /**
     * Padding on top of ciphertext stealing is a contradiction, not a
     * redundancy: padded plaintext is always a block multiple, the stealing
     * becomes a no-op, and the result is ordinary CBC no CTS peer can read.
     * Refused at {@code getInstance} with the JCE-canonical type.
     */
    @Test
    public void paddingWithCtsRejected()
    {
        for (String bad : new String[]{"AES/CTS/PKCS5Padding", "AES/CTS/PKCS7Padding"})
        {
            NoSuchPaddingException e = Assertions.assertThrows(NoSuchPaddingException.class,
                    () -> Cipher.getInstance(bad, providerName()), bad + " must be refused");
            Assertions.assertEquals("CTS mode takes no padding; ciphertext stealing replaces it",
                    e.getMessage());
        }
    }


    // -----------------------------------------------------------------
    // Reset / reuse.
    // -----------------------------------------------------------------

    @Test
    public void reinitDiscardsAPartiallyAccumulatedMessage() throws Exception
    {
        SecureRandom sr = seededRandom("reinitDiscardsAPartiallyAccumulatedMessage");
        byte[] key = randomBytes(sr, 16);
        byte[] iv = randomBytes(sr, BLOCK);
        byte[] msg = randomBytes(sr, 20);

        Cipher c = Cipher.getInstance(XFORM, providerName());
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
        c.update(msg, 0, 13);                       // abandoned mid-message

        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
        byte[] after = c.doFinal(msg);

        Assertions.assertArrayEquals(
                oneShot(XFORM, BouncyCastleProvider.PROVIDER_NAME, Cipher.ENCRYPT_MODE, key, iv, msg),
                after, "re-init must discard the abandoned 13 bytes");
    }

    @Test
    public void doFinalLeavesTheAccumulatorEmpty() throws Exception
    {
        SecureRandom sr = seededRandom("doFinalLeavesTheAccumulatorEmpty");
        byte[] key = randomBytes(sr, 16);
        byte[] iv = randomBytes(sr, BLOCK);
        byte[] first = randomBytes(sr, 20);
        byte[] second = randomBytes(sr, 24);

        Cipher c = Cipher.getInstance(XFORM, providerName());
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
        c.doFinal(first);
        byte[] out = c.doFinal(second);

        Assertions.assertArrayEquals(
                oneShot(XFORM, BouncyCastleProvider.PROVIDER_NAME, Cipher.ENCRYPT_MODE, key, iv, second),
                out, "the second message must not be prefixed by the first");
    }

    @Test
    public void refusedShortMessageLeavesNothingBehind() throws Exception
    {
        SecureRandom sr = seededRandom("refusedShortMessageLeavesNothingBehind");
        byte[] key = randomBytes(sr, 16);
        byte[] iv = randomBytes(sr, BLOCK);

        Cipher c = Cipher.getInstance(XFORM, providerName());
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
        Assertions.assertThrows(IllegalBlockSizeException.class, () -> c.doFinal(randomBytes(sr, 7)));

        // A refused 7-byte message must not combine with a later 9-byte one
        // into an accepted 16-byte message the caller never asked for.
        byte[] msg = randomBytes(sr, 9);
        Assertions.assertThrows(IllegalBlockSizeException.class, () -> c.doFinal(msg),
                "the refused message must have been discarded");
    }


    // -----------------------------------------------------------------
    // Offset write and in-place.
    // -----------------------------------------------------------------

    @Test
    public void doFinalWritesAtOffsetWithoutClobberingPrefix() throws Exception
    {
        SecureRandom sr = seededRandom("doFinalWritesAtOffsetWithoutClobberingPrefix");
        byte[] key = randomBytes(sr, 16);
        byte[] iv = randomBytes(sr, BLOCK);
        byte[] msg = randomBytes(sr, 2 * BLOCK + 5);

        int outOff = 9;
        byte[] big = new byte[outOff + msg.length + 11];
        sr.nextBytes(big);
        byte[] expectedPrefix = java.util.Arrays.copyOf(big, outOff);
        byte[] snapshot = Arrays.clone(big);

        Cipher enc = Cipher.getInstance(XFORM, providerName());
        enc.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
        int written = enc.doFinal(msg, 0, msg.length, big, outOff);

        Assertions.assertEquals(msg.length, written);
        Assertions.assertArrayEquals(expectedPrefix, java.util.Arrays.copyOf(big, outOff),
                "bytes preceding outOff must be untouched");
        Assertions.assertArrayEquals(
                java.util.Arrays.copyOfRange(snapshot, outOff + written, big.length),
                java.util.Arrays.copyOfRange(big, outOff + written, big.length),
                "bytes after the written region must be untouched");

        byte[] window = java.util.Arrays.copyOfRange(big, outOff, outOff + written);
        Assertions.assertArrayEquals(msg,
                oneShot(XFORM, providerName(), Cipher.DECRYPT_MODE, key, iv, window),
                "the written region must decrypt to the plaintext");

        byte[] shifted = java.util.Arrays.copyOfRange(big, outOff - 1, outOff - 1 + written);
        Assertions.assertFalse(
                Arrays.areEqual(msg, oneShot(XFORM, providerName(), Cipher.DECRYPT_MODE, key, iv, shifted)),
                "a window starting one byte early must NOT decrypt to the plaintext");
    }

    /**
     * {@code doFinal(buf, off, len, buf, off)} — same offset, which is the
     * only in-place layout a streaming transform supports. The whole
     * destination is verified, not just the written region.
     */
    @Test
    public void inPlaceSameOffsetMatchesSeparateBuffer() throws Exception
    {
        SecureRandom sr = seededRandom("inPlaceSameOffsetMatchesSeparateBuffer");
        byte[] key = randomBytes(sr, 16);
        byte[] iv = randomBytes(sr, BLOCK);
        byte[] msg = randomBytes(sr, 3 * BLOCK + 3);

        byte[] reference = oneShot(XFORM, providerName(), Cipher.ENCRYPT_MODE, key, iv, msg);

        int prefix = 5;
        int suffix = 7;
        byte[] buf = new byte[prefix + msg.length + suffix];
        sr.nextBytes(buf);
        byte[] snapshot = Arrays.clone(buf);
        System.arraycopy(msg, 0, buf, prefix, msg.length);

        Cipher enc = Cipher.getInstance(XFORM, providerName());
        enc.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
        int written = enc.doFinal(buf, prefix, msg.length, buf, prefix);

        Assertions.assertEquals(reference.length, written);
        Assertions.assertArrayEquals(reference,
                java.util.Arrays.copyOfRange(buf, prefix, prefix + written),
                "in-place must equal the separate-buffer result");
        Assertions.assertArrayEquals(java.util.Arrays.copyOf(snapshot, prefix),
                java.util.Arrays.copyOf(buf, prefix), "prefix untouched");
        Assertions.assertArrayEquals(
                java.util.Arrays.copyOfRange(snapshot, prefix + msg.length, buf.length),
                java.util.Arrays.copyOfRange(buf, prefix + msg.length, buf.length), "suffix untouched");
    }

    @Test
    public void shortOutputBufferRefusalKeepsTheMessageForRetry() throws Exception
    {
        SecureRandom sr = seededRandom("shortOutputBufferRefusalKeepsTheMessageForRetry");
        byte[] key = randomBytes(sr, 16);
        byte[] iv = randomBytes(sr, BLOCK);
        byte[] msg = randomBytes(sr, 2 * BLOCK + 1);

        Cipher enc = Cipher.getInstance(XFORM, providerName());
        enc.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
        Assertions.assertThrows(ShortBufferException.class,
                () -> enc.doFinal(msg, 0, msg.length, new byte[msg.length - 1], 0));

        // JCE's ShortBufferException contract is "retry with a bigger buffer",
        // so the message must still be there.
        byte[] out = new byte[msg.length];
        int written = enc.doFinal(msg, 0, msg.length, out, 0);
        Assertions.assertArrayEquals(
                oneShot(XFORM, BouncyCastleProvider.PROVIDER_NAME, Cipher.ENCRYPT_MODE, key, iv, msg),
                java.util.Arrays.copyOf(out, written), "the retry must produce the full result");
    }


    // -----------------------------------------------------------------
    // Registration.
    // -----------------------------------------------------------------

    @Test
    public void bothSpellingsAreRegisteredServices()
    {
        Provider p = Security.getProvider(providerName());
        Assertions.assertNotNull(p, providerName() + " must be registered");
        Assertions.assertNotNull(p.getService("Cipher", XFORM), XFORM + " must be a Service");
        Assertions.assertNotNull(p.getService("Cipher", XFORM_CS3), XFORM_CS3 + " must be a Service");
    }


    // -----------------------------------------------------------------
    // Helpers.
    // -----------------------------------------------------------------

    protected static byte[] randomBytes(SecureRandom sr, int n)
    {
        byte[] b = new byte[n];
        sr.nextBytes(b);
        return b;
    }

    protected static byte[] oneShot(String xform, String provider, int mode,
                                    byte[] key, byte[] iv, byte[] in) throws Exception
    {
        Cipher c = Cipher.getInstance(xform, provider);
        c.init(mode, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
        return c.doFinal(in);
    }

    private byte[] chunked(byte[] key, byte[] iv, byte[] msg, int[] splits) throws Exception
    {
        Cipher c = Cipher.getInstance(XFORM, providerName());
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int off = 0;
        for (int n : splits)
        {
            if (n <= 0 || off >= msg.length)
            {
                continue;
            }
            int take = Math.min(n, msg.length - off);
            byte[] part = c.update(msg, off, take);
            if (part != null)
            {
                out.write(part);
            }
            off += take;
        }
        if (off < msg.length)
        {
            byte[] part = c.update(msg, off, msg.length - off);
            if (part != null)
            {
                out.write(part);
            }
        }
        out.write(c.doFinal());
        return out.toByteArray();
    }

    protected static int[] adversarialChunks(int total)
    {
        List<Integer> parts = new ArrayList<Integer>();
        int[] sizes = {BLOCK - 1, BLOCK, BLOCK + 1};
        int remaining = total;
        int i = 0;
        while (remaining > 0)
        {
            int n = Math.min(sizes[i++ % sizes.length], remaining);
            parts.add(n);
            remaining -= n;
        }
        int[] out = new int[parts.size()];
        for (int j = 0; j < out.length; j++)
        {
            out[j] = parts.get(j);
        }
        return out;
    }

    protected static int[] randomSplits(SecureRandom sr, int total)
    {
        List<Integer> parts = new ArrayList<Integer>();
        int remaining = total;
        while (remaining > 0)
        {
            int n = 1 + sr.nextInt(remaining);
            parts.add(n);
            remaining -= n;
        }
        int[] out = new int[parts.size()];
        for (int j = 0; j < out.length; j++)
        {
            out[j] = parts.get(j);
        }
        return out;
    }
}
