package org.openssl.jostle.test.crypto;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.util.Arrays;
import org.openssl.jostle.util.encoders.Hex;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.security.SecureRandom;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;

/**
 * AES-CFB1, the one-bit-segment CFB mode of NIST SP 800-38A.
 *
 * <p><b>Why this class exists.</b> {@code AES/CFB1/NoPadding} is reachable
 * through {@code engineSetMode}'s form-4 fallback and works, and until this
 * class it had NO test of any kind — not a vector, not a roundtrip, not a
 * chunking check. It was found while auditing the chunking dimension (MT-3) and
 * the audit understated it: the mode was not merely uncovered on that
 * dimension, it was uncovered entirely.
 *
 * <p><b>Why a from-spec reference.</b> The interop-reference order in
 * testing.md is BouncyCastle, then the JDK, then from-spec. Both were checked
 * rather than assumed, and both refuse: no installed JCE provider except JSL
 * serves {@code AES/CFB1} (measured across all fourteen), and BouncyCastle's
 * LIGHTWEIGHT API refuses it too — {@code CFBBlockCipher(AESEngine, 1)} throws
 * {@code IllegalArgumentException: CFB1 not supported}. So the order genuinely
 * exhausts and {@link #cfb1Reference} is the independent implementation.
 *
 * <p><b>Why the reference can be trusted.</b> A from-spec reference is an
 * implementation somebody wrote, so "it agrees with JSL" proves nothing — a
 * reference wrong in the same way as the code under test agrees perfectly.
 * {@link #fromSpecReferenceMatchesNistVectors()} anchors it to NIST instead,
 * and off-line the four plausible-and-wrong readings of the spec were each
 * confirmed to BREAK those vectors (bits LSB-first; register shifted right;
 * plaintext fed back instead of ciphertext; LSB rather than MSB of the output
 * block), with the untouched reference passing as control. The vectors
 * themselves were parsed programmatically from SP 800-38A and validated five
 * ways before use, including recomputing every Output Block with the JDK's AES.
 */
public class AESCFB1Test
{
    private static final String XFORM = "AES/CFB1/NoPadding";

    /**
     * SP 800-38A Appendix F.3. Each row is one key size; NIST publishes the
     * Encrypt and Decrypt tables separately but their data is identical with
     * the bit labels swapped, so one row drives both directions.
     *
     * <p>All six tables (F.3.1 to F.3.6) were parsed and validated; the pairing
     * above is because a CFB1 Decrypt table carries the same Input and Output
     * blocks as its Encrypt twin, which check 3 confirms rather than assumes.
     *
     * <p>{@code {sections, key, iv, plaintextBits, ciphertextBits}}; the bit
     * strings are the 16 published segment bits assembled MSB-first, which is
     * why the plaintext is always 6bc1, the first two bytes of NIST's standard
     * test plaintext.
     */
    private static final String[][] NIST_F3 = {
            {"F.3.1/F.3.2", "2b7e151628aed2a6abf7158809cf4f3c",
                            "000102030405060708090a0b0c0d0e0f", "6bc1", "68b3"},
            {"F.3.3/F.3.4", "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
                            "000102030405060708090a0b0c0d0e0f", "6bc1", "9359"},
            {"F.3.5/F.3.6", "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
                            "000102030405060708090a0b0c0d0e0f", "6bc1", "9029"},
    };

    @BeforeAll
    public static void setup()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    // ------------------------------------------------------------------
    // The from-spec reference: SP 800-38A, CFB with s = 1 bit.
    //
    //   I_1     = IV
    //   O_j     = CIPH_K(I_j)
    //   C_j     = P_j XOR MSB_1(O_j)
    //   I_{j+1} = LSB_127(I_j) | C_j
    //
    // Bits are MSB-first within each byte, matching OpenSSL's byte-length CFB1
    // path (len bytes -> len*8 bits). Built on the JDK's AES/ECB so the only
    // thing this code contributes is the mode, not the block cipher.
    // ------------------------------------------------------------------

    private static byte[] aesEcbBlock(byte[] key, byte[] block) throws Exception
    {
        Cipher c = Cipher.getInstance("AES/ECB/NoPadding", "SunJCE");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"));
        return c.doFinal(block);
    }

    private static boolean bitAt(byte[] data, int i)
    {
        return ((data[i >>> 3] >>> (7 - (i & 7))) & 1) != 0;
    }

    private static void setBitAt(byte[] data, int i, boolean v)
    {
        if (v)
        {
            data[i >>> 3] |= (byte) (1 << (7 - (i & 7)));
        }
        else
        {
            data[i >>> 3] &= (byte) ~(1 << (7 - (i & 7)));
        }
    }

    /** LSB_127(reg) | bit — shift the 128-bit register left one, append bit. */
    private static void shiftInBit(byte[] reg, boolean bit)
    {
        for (int i = 0; i < reg.length; i++)
        {
            int carry = (i + 1 < reg.length) ? ((reg[i + 1] >>> 7) & 1) : (bit ? 1 : 0);
            reg[i] = (byte) (((reg[i] << 1) & 0xFF) | carry);
        }
    }

    /** @param encrypt true when {@code in} is plaintext, false when it is ciphertext. */
    static byte[] cfb1Reference(byte[] key, byte[] iv, byte[] in, boolean encrypt) throws Exception
    {
        byte[] reg = Arrays.clone(iv);
        byte[] out = new byte[in.length];
        for (int i = 0; i < in.length * 8; i++)
        {
            byte[] o = aesEcbBlock(key, reg);
            boolean keyStreamBit = ((o[0] >>> 7) & 1) != 0;
            boolean inBit = bitAt(in, i);
            boolean outBit = inBit ^ keyStreamBit;
            setBitAt(out, i, outBit);
            // The CIPHERTEXT bit is fed back, whichever direction we are going.
            shiftInBit(reg, encrypt ? outBit : inBit);
        }
        return out;
    }

    private static Cipher jsl(int mode, byte[] key, byte[] iv) throws Exception
    {
        Cipher c = Cipher.getInstance(XFORM, JostleProvider.PROVIDER_NAME);
        c.init(mode, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
        return c;
    }

    // ------------------------------------------------------------------

    /**
     * The reference reproduces NIST's published vectors. This is what earns the
     * reference the right to anchor everything below it; without it the
     * reference is just a second opinion of unknown quality.
     */
    @Test
    public void fromSpecReferenceMatchesNistVectors() throws Exception
    {
        for (String[] v : NIST_F3)
        {
            byte[] key = Hex.decode(v[1]);
            byte[] iv = Hex.decode(v[2]);
            byte[] pt = Hex.decode(v[3]);
            byte[] ct = Hex.decode(v[4]);

            Assertions.assertArrayEquals(ct, cfb1Reference(key, iv, pt, true),
                    v[0] + ": reference encrypt does not match the NIST vector");
            Assertions.assertArrayEquals(pt, cfb1Reference(key, iv, ct, false),
                    v[0] + ": reference decrypt does not match the NIST vector");
        }
    }

    /** JSL reproduces NIST's published vectors, both directions. */
    @Test
    public void jslMatchesNistVectors() throws Exception
    {
        for (String[] v : NIST_F3)
        {
            byte[] key = Hex.decode(v[1]);
            byte[] iv = Hex.decode(v[2]);
            byte[] pt = Hex.decode(v[3]);
            byte[] ct = Hex.decode(v[4]);

            Assertions.assertArrayEquals(ct, jsl(Cipher.ENCRYPT_MODE, key, iv).doFinal(pt),
                    v[0] + ": JSL encrypt does not match the NIST vector");
            Assertions.assertArrayEquals(pt, jsl(Cipher.DECRYPT_MODE, key, iv).doFinal(ct),
                    v[0] + ": JSL decrypt does not match the NIST vector");
        }
    }

    /**
     * Agreement over random inputs, all three key sizes, both directions.
     *
     * <p>The vectors above pin two bytes at one fixed key and IV; this is what
     * covers the input space. Random key, random IV, random length and random
     * content per trial, per the random-input rule.
     */
    @Test
    public void agreesWithFromSpecReferenceOverRandomInputs() throws Exception
    {
        SecureRandom outer = new SecureRandom();
        long seed = outer.nextLong();
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        sr.setSeed(seed);

        List<String> failures = new ArrayList<String>();
        for (int keyLen : new int[]{16, 24, 32})
        {
            for (int trial = 0; trial < 8; trial++)
            {
                byte[] key = new byte[keyLen];
                byte[] iv = new byte[16];
                byte[] msg = new byte[1 + sr.nextInt(24)];
                sr.nextBytes(key);
                sr.nextBytes(iv);
                sr.nextBytes(msg);

                byte[] refCt = cfb1Reference(key, iv, msg, true);
                byte[] jslCt = jsl(Cipher.ENCRYPT_MODE, key, iv).doFinal(msg);
                if (!Arrays.areEqual(refCt, jslCt))
                {
                    failures.add("encrypt keyLen=" + keyLen + " len=" + msg.length + " diverged");
                }

                byte[] jslPt = jsl(Cipher.DECRYPT_MODE, key, iv).doFinal(refCt);
                if (!Arrays.areEqual(msg, jslPt))
                {
                    failures.add("decrypt keyLen=" + keyLen + " len=" + msg.length
                            + " did not recover the plaintext");
                }
            }
        }
        if (!failures.isEmpty())
        {
            Assertions.fail("seed=" + seed + "\n  " + String.join("\n  ", failures));
        }
    }

    /**
     * The chunking dimension, anchored by the reference rather than by our own
     * one-shot — chunked-equals-our-one-shot is satisfied by an implementation
     * that is uniformly wrong.
     *
     * <p>Split shapes are fixed here rather than derived from anything
     * mode-specific, so a future helper that narrows its own granularity cannot
     * narrow this coverage. Encrypt and decrypt separately: they are different
     * code paths.
     */
    @Test
    public void chunkingAgreesWithFromSpecReference() throws Exception
    {
        SecureRandom outer = new SecureRandom();
        long seed = outer.nextLong();
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        sr.setSeed(seed);

        List<String> failures = new ArrayList<String>();
        for (int keyLen : new int[]{16, 24, 32})
        {
            byte[] key = new byte[keyLen];
            byte[] iv = new byte[16];
            byte[] msg = new byte[19];
            sr.nextBytes(key);
            sr.nextBytes(iv);
            sr.nextBytes(msg);

            byte[] refCt = cfb1Reference(key, iv, msg, true);

            for (int chunk : new int[]{1, 2, 3, 7, 15, 16, 17, 0})
            {
                byte[] gotCt = drive(Cipher.ENCRYPT_MODE, key, iv, msg, chunk);
                if (!Arrays.areEqual(refCt, gotCt))
                {
                    failures.add("encrypt keyLen=" + keyLen + " chunk=" + describe(chunk)
                            + " differs from the from-spec reference");
                }
                byte[] gotPt = drive(Cipher.DECRYPT_MODE, key, iv, refCt, chunk);
                if (!Arrays.areEqual(msg, gotPt))
                {
                    failures.add("decrypt keyLen=" + keyLen + " chunk=" + describe(chunk)
                            + " did not recover the plaintext");
                }
            }

            // Random splits, so boundaries do not always fall where we chose.
            for (int trial = 0; trial < 6; trial++)
            {
                Cipher c = jsl(Cipher.ENCRYPT_MODE, key, iv);
                ByteArrayOutputStream out = new ByteArrayOutputStream();
                int off = 0;
                while (off < msg.length)
                {
                    int n = 1 + sr.nextInt(msg.length - off);
                    byte[] part = c.update(msg, off, n);
                    if (part != null)
                    {
                        out.write(part);
                    }
                    off += n;
                }
                out.write(c.doFinal());
                if (!Arrays.areEqual(refCt, out.toByteArray()))
                {
                    failures.add("encrypt keyLen=" + keyLen + " random split trial=" + trial + " diverged");
                }
            }
        }
        if (!failures.isEmpty())
        {
            Assertions.fail("seed=" + seed + "\n  " + String.join("\n  ", failures));
        }
    }

    /**
     * The negative path: CFB1 must actually transform its input, and a tampered
     * ciphertext must not decrypt back to the plaintext. A positive-only suite
     * accepts an implementation that copies its input.
     */
    @Test
    public void transformsInputAndRejectsTampering() throws Exception
    {
        SecureRandom sr = new SecureRandom();
        byte[] key = new byte[16];
        byte[] iv = new byte[16];
        byte[] msg = new byte[16];
        sr.nextBytes(key);
        sr.nextBytes(iv);
        sr.nextBytes(msg);

        byte[] ct = jsl(Cipher.ENCRYPT_MODE, key, iv).doFinal(msg);
        Assertions.assertFalse(Arrays.areEqual(msg, ct), "CFB1 did not transform its input");

        byte[] tampered = Arrays.clone(ct);
        tampered[0] ^= (byte) 0x01;
        Assertions.assertFalse(
                Arrays.areEqual(msg, jsl(Cipher.DECRYPT_MODE, key, iv).doFinal(tampered)),
                "a tampered ciphertext decrypted back to the plaintext");

        // A one-bit IV change must change the output; CFB1 feeds the IV in
        // immediately, so nothing may ignore it.
        byte[] iv2 = Arrays.clone(iv);
        iv2[15] ^= (byte) 0x01;
        Assertions.assertFalse(
                Arrays.areEqual(ct, jsl(Cipher.ENCRYPT_MODE, key, iv2).doFinal(msg)),
                "changing the IV did not change the ciphertext");
    }

    private static byte[] drive(int mode, byte[] key, byte[] iv, byte[] in, int chunk) throws Exception
    {
        Cipher c = jsl(mode, key, iv);
        if (chunk <= 0)
        {
            return c.doFinal(in);
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (int off = 0; off < in.length; off += chunk)
        {
            byte[] part = c.update(in, off, Math.min(chunk, in.length - off));
            if (part != null)
            {
                out.write(part);
            }
        }
        out.write(c.doFinal());
        return out.toByteArray();
    }

    private static String describe(int chunk)
    {
        return chunk <= 0 ? "one-shot" : Integer.toString(chunk);
    }
}
