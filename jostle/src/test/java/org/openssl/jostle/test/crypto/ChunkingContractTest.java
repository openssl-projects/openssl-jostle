package org.openssl.jostle.test.crypto;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.util.ArrayList;
import java.util.List;

/**
 * Chunking as a contract DIMENSION, swept across every transformation where
 * how the input is split can change the output.
 *
 * <p>Two defects motivated this class, both invisible to the per-name
 * completeness guards and to every roundtrip test in the suite:
 *
 * <ol>
 *   <li>The AES key-wrap modes emitted the whole result from a single EVP
 *       update, so a chunked caller got one independent wrap per
 *       {@code update()}, concatenated - byte-perfect one-shot against
 *       BouncyCastle, garbage chunked, and it round-tripped through our own
 *       unwrap. Nothing in the suite called {@code update()} on a wrap at all.</li>
 *   <li>ECB and CBC with {@code NoPadding} REFUSED a sub-block
 *       {@code update()}, where BouncyCastle and SunJCE buffer and emit at
 *       block completion. The split points in the existing agreement helpers
 *       were pinned to block boundaries by a parameter that legitimately
 *       constrained message LENGTHS, so the partial-block path was never
 *       reached.</li>
 * </ol>
 *
 * <p>The matrix therefore fixes the split shapes here rather than deriving
 * them from anything mode-specific: a future helper that restricts its own
 * split granularity cannot narrow this coverage. Every comparison is against
 * BouncyCastle, never against our own one-shot - a uniformly wrong
 * implementation agrees with itself, which is precisely how defect (1)
 * survived.
 *
 * <p>AES-XTS is deliberately absent and is the only absence: BouncyCastle
 * serves no {@code AES/XTS/NoPadding}, and its chunking contract is pinned in
 * {@link AESXTSTest} against a from-spec IEEE 1619 reference instead. Named
 * here in {@link #NO_BC_JCE_NAME} so the gap is explicit rather than assumed.
 *
 * <p><b>The AEAD modes are mostly pinned elsewhere, deliberately rather than by
 * accident</b>, which is why only one of them appears in this matrix:
 * <ul>
 *   <li>GCM - {@code AESAgreementTest.aesGCMSpreadSplitUpdateDoFinal}, explicit
 *       split points {0, 1, 15, 16, 17, random} across ~270 message lengths and
 *       three key sizes, against BouncyCastle.</li>
 *   <li>CCM - {@code AESAgreementTest.aesCCM_chunkingMatrix_byteIdentical}.</li>
 *   <li>OCB - {@code AESAgreementTest}'s OCB streaming test, which anchors its
 *       own one-shot to BouncyCastle in the same method and then compares every
 *       chunking to it; the chain reaches BC, which is what matters.</li>
 *   <li>ChaCha20-Poly1305 - was NOT pinned. Its agreement test splits the AAD
 *       but never the plaintext, so the dimension was uncovered. It is in this
 *       matrix now.</li>
 * </ul>
 */
public class ChunkingContractTest
{
    /**
     * Reachable transformations this matrix cannot cover, each with the reason
     * and where the contract is pinned instead. Measured, not assumed: a probe
     * over every {@code OSSLMode} spelling established which resolve, which
     * initialise, and which BouncyCastle also serves.
     *
     * <p>Listed rather than silently absent, so a gap reads as a gap. The
     * remaining genuine weakness is CFB1: it is reachable and usable through
     * JSL but BouncyCastle serves no {@code AES/CFB1}, so its chunking has no
     * independent reference yet.
     */
    static final String[] NO_BC_JCE_NAME = {
            "AES/XTS/NoPadding - BouncyCastle serves no XTS Cipher; AESXTSTest "
                    + "pins the same contract against a from-spec IEEE 1619 reference",
            "AES/CFB1/NoPadding - BouncyCastle serves no AES/CFB1 Cipher, in EITHER "
                    + "API (its lightweight CFBBlockCipher refuses a 1-bit width outright), "
                    + "and neither does any other installed provider. AESCFB1Test pins it "
                    + "against NIST SP 800-38A F.3 and a from-spec reference instead",
            "AESWrapInv - no BouncyCastle JCE transformation exists; AESKeyWrapInvTest "
                    + "anchors it on BC's lightweight AESWrapEngine(true) instead",
            "AES/CFB64, AES/STREAM, AES/POLY1305 - resolve through engineSetMode but "
                    + "fail init for AES, so no caller can drive them",
    };

    @BeforeAll
    public static void setup()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private static final class Mode
    {
        final String transformation;
        final String keyAlgorithm;
        final int keyLen;
        final int ivLen;        // -1 when the mode takes none
        final int unit;         // the size whose boundaries the splits straddle
        final int msgLen;       // a length this mode accepts
        final boolean accumulates;

        Mode(String transformation, String keyAlgorithm, int keyLen, int ivLen,
             int unit, int msgLen, boolean accumulates)
        {
            this.transformation = transformation;
            this.keyAlgorithm = keyAlgorithm;
            this.keyLen = keyLen;
            this.ivLen = ivLen;
            this.unit = unit;
            this.msgLen = msgLen;
            this.accumulates = accumulates;
        }
    }

    private static List<Mode> modes()
    {
        List<Mode> m = new ArrayList<Mode>();
        // Unpadded block modes: EVP buffers partial blocks, total must align.
        m.add(new Mode("AES/ECB/NoPadding", "AES", 16, -1, 16, 4 * 16, false));
        m.add(new Mode("AES/CBC/NoPadding", "AES", 16, 16, 16, 4 * 16, false));
        m.add(new Mode("AES/CBC/NoPadding", "AES", 32, 16, 16, 4 * 16, false));
        m.add(new Mode("DESede/CBC/NoPadding", "DESede", 24, 8, 8, 4 * 8, false));
        // Padded, where a partial final block is the normal case.
        m.add(new Mode("AES/CBC/PKCS5Padding", "AES", 16, 16, 16, 37, false));
        // Accumulating: one-shot EVP primitives under a streaming contract.
        m.add(new Mode("AES/CTS/NoPadding", "AES", 16, 16, 16, 37, true));
        m.add(new Mode("AESWRAP", "AES", 32, -1, 8, 32, true));
        m.add(new Mode("AESWRAPPAD", "AES", 32, -1, 8, 37, true));
        // ChaCha20-Poly1305. The other three AEADs are pinned on this dimension
        // by named tests of their own (see the class javadoc); this one was NOT
        // - every call in ChaCha20Poly1305AgreementTest is a one-shot doFinal,
        // with only the AAD split - so it is covered here. Measured correct
        // before being added, so this is coverage rather than a fix.
        m.add(new Mode("ChaCha20-Poly1305", "ChaCha20", 32, 12, 16, 37, false));
        // Streaming controls: these must NOT start accumulating.
        m.add(new Mode("AES/CTR/NoPadding", "AES", 16, 16, 16, 37, false));
        m.add(new Mode("AES/CFB/NoPadding", "AES", 16, 16, 16, 37, false));
        m.add(new Mode("AES/CFB8/NoPadding", "AES", 16, 16, 16, 37, false));
        m.add(new Mode("AES/OFB/NoPadding", "AES", 16, 16, 16, 37, false));
        return m;
    }

    /**
     * The split shapes, fixed here on purpose. Byte-wise and the two shapes
     * either side of the unit boundary are the ones a mode-derived granularity
     * silently drops.
     */
    private static int[] splitSizes(int unit)
    {
        return new int[]{1, unit - 1, unit, unit + 1, 0 /* one-shot */};
    }

    private static byte[] runChunked(Cipher c, byte[] in, int chunk) throws Exception
    {
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

    private static Cipher cipher(String provider, Mode m, int opMode, SecretKey key, byte[] iv)
            throws Exception
    {
        Cipher c = Cipher.getInstance(m.transformation, provider);
        AlgorithmParameterSpec ps = m.ivLen < 0 ? null : new IvParameterSpec(iv);
        if (ps == null)
        {
            c.init(opMode, key);
        }
        else
        {
            c.init(opMode, key, ps);
        }
        return c;
    }

    /**
     * Every split shape must produce exactly what BouncyCastle produces in one
     * shot, in BOTH directions. Encrypt and decrypt are separate code paths and
     * a discard or reset mistake can land on one only.
     */
    @Test
    public void everySplitShapeAgreesWithBouncyCastle() throws Exception
    {
        SecureRandom sr = new SecureRandom();
        long seed = sr.nextLong();
        sr = SecureRandom.getInstance("SHA1PRNG");
        sr.setSeed(seed);

        List<String> failures = new ArrayList<String>();

        for (Mode m : modes())
        {
            byte[] keyBytes = new byte[m.keyLen];
            byte[] iv = new byte[m.ivLen < 0 ? 0 : m.ivLen];
            byte[] msg = new byte[m.msgLen];
            sr.nextBytes(keyBytes);
            sr.nextBytes(iv);
            sr.nextBytes(msg);
            SecretKey key = new SecretKeySpec(keyBytes, m.keyAlgorithm);

            byte[] reference = cipher(BouncyCastleProvider.PROVIDER_NAME, m,
                    Cipher.ENCRYPT_MODE, key, iv).doFinal(msg);

            for (int chunk : splitSizes(m.unit))
            {
                try
                {
                    byte[] got = runChunked(
                            cipher(JostleProvider.PROVIDER_NAME, m, Cipher.ENCRYPT_MODE, key, iv),
                            msg, chunk);
                    if (!org.openssl.jostle.util.Arrays.areEqual(reference, got))
                    {
                        failures.add(m.transformation + " key=" + m.keyLen
                                + " encrypt chunk=" + describe(chunk)
                                + ": differs from BouncyCastle");
                    }
                }
                catch (Exception e)
                {
                    failures.add(m.transformation + " key=" + m.keyLen
                            + " encrypt chunk=" + describe(chunk)
                            + ": threw " + e.getClass().getSimpleName() + " " + e.getMessage());
                }

                try
                {
                    byte[] back = runChunked(
                            cipher(JostleProvider.PROVIDER_NAME, m, Cipher.DECRYPT_MODE, key, iv),
                            reference, chunk);
                    if (!org.openssl.jostle.util.Arrays.areEqual(msg, back))
                    {
                        failures.add(m.transformation + " key=" + m.keyLen
                                + " decrypt chunk=" + describe(chunk)
                                + ": did not recover the plaintext");
                    }
                }
                catch (Exception e)
                {
                    failures.add(m.transformation + " key=" + m.keyLen
                            + " decrypt chunk=" + describe(chunk)
                            + ": threw " + e.getClass().getSimpleName() + " " + e.getMessage());
                }
            }
        }

        if (!failures.isEmpty())
        {
            Assertions.fail("seed=" + seed + "\n  " + String.join("\n  ", failures));
        }
    }

    /** Random split points, so boundaries do not always fall where we chose. */
    @Test
    public void randomSplitsAgreeWithBouncyCastle() throws Exception
    {
        SecureRandom outer = new SecureRandom();
        long seed = outer.nextLong();
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        sr.setSeed(seed);

        List<String> failures = new ArrayList<String>();

        for (Mode m : modes())
        {
            for (int trial = 0; trial < 8; trial++)
            {
                byte[] keyBytes = new byte[m.keyLen];
                byte[] iv = new byte[m.ivLen < 0 ? 0 : m.ivLen];
                byte[] msg = new byte[m.msgLen];
                sr.nextBytes(keyBytes);
                sr.nextBytes(iv);
                sr.nextBytes(msg);
                SecretKey key = new SecretKeySpec(keyBytes, m.keyAlgorithm);

                byte[] reference = cipher(BouncyCastleProvider.PROVIDER_NAME, m,
                        Cipher.ENCRYPT_MODE, key, iv).doFinal(msg);

                Cipher c = cipher(JostleProvider.PROVIDER_NAME, m, Cipher.ENCRYPT_MODE, key, iv);
                ByteArrayOutputStream out = new ByteArrayOutputStream();
                int off = 0;
                while (off < msg.length)
                {
                    int n = 1 + sr.nextInt(Math.max(1, msg.length - off));
                    byte[] part = c.update(msg, off, n);
                    if (part != null)
                    {
                        out.write(part);
                    }
                    off += n;
                }
                out.write(c.doFinal());

                if (!org.openssl.jostle.util.Arrays.areEqual(reference, out.toByteArray()))
                {
                    failures.add(m.transformation + " trial=" + trial + ": random split differs from BouncyCastle");
                }
            }
        }

        if (!failures.isEmpty())
        {
            Assertions.fail("seed=" + seed + "\n  " + String.join("\n  ", failures));
        }
    }

    /**
     * Streaming modes must STAY streaming. Accumulation is correct only where
     * the EVP primitive is one-shot; applying it to a stream would be a silent
     * latency and memory regression that every output-comparison test above
     * would still pass, because the bytes would merely arrive later.
     */
    @Test
    public void streamingModesEmitFromUpdateRatherThanAccumulating() throws Exception
    {
        SecureRandom sr = new SecureRandom();
        List<String> failures = new ArrayList<String>();

        for (Mode m : modes())
        {
            if (m.accumulates)
            {
                continue;
            }
            byte[] keyBytes = new byte[m.keyLen];
            byte[] iv = new byte[m.ivLen < 0 ? 0 : m.ivLen];
            byte[] msg = new byte[m.msgLen];
            sr.nextBytes(keyBytes);
            sr.nextBytes(iv);
            sr.nextBytes(msg);
            SecretKey key = new SecretKeySpec(keyBytes, m.keyAlgorithm);

            Cipher c = cipher(JostleProvider.PROVIDER_NAME, m, Cipher.ENCRYPT_MODE, key, iv);
            // A whole number of units in: a non-accumulating mode must have
            // emitted something by now.
            byte[] part = c.update(msg, 0, m.unit * 2);
            int produced = part == null ? 0 : part.length;
            if (produced == 0)
            {
                failures.add(m.transformation + " emitted nothing from an update of "
                        + (m.unit * 2) + " bytes - has it started accumulating?");
            }
        }

        if (!failures.isEmpty())
        {
            Assertions.fail(String.join("\n  ", failures));
        }
    }

    /**
     * The three modes MT-3 marked CLOSE must stay unreachable in practice, and
     * must say so in a JCE-contracted way.
     *
     * <p>CFB64, STREAM and POLY1305 resolve through {@code engineSetMode} —
     * they are {@code OSSLMode} constants — but AES implements none of them, so
     * no caller can drive them and no chunking bug can hide behind them. MT-3's
     * CLOSE verdict for these three is therefore "recorded and pinned", NOT
     * "rejected at setMode": no behaviour was changed. The distinction matters
     * because the plan's other sense of CLOSE is an implemented refusal
     * following the CCM precedent, and that would be three behaviour changes.
     *
     * <p>What makes recording sufficient is that the refusal is already typed,
     * already consistent across all three, and already a provider-fallback
     * trigger: {@code InvalidKeyException} without parameters and
     * {@code InvalidAlgorithmParameterException} with them, both carrying
     * "mode not supported for cipher". Pinned here so "no caller can reach it"
     * is a tested fact rather than an observation — if any of these ever starts
     * initialising, it becomes reachable and needs a chunking row.
     */
    @Test
    public void closedModesRemainUnreachableAndRefuseTyped() throws Exception
    {
        SecretKeySpec key = new SecretKeySpec(new byte[16], "AES");
        List<String> failures = new ArrayList<String>();

        for (String mode : new String[]{"CFB64", "STREAM", "POLY1305"})
        {
            String tf = "AES/" + mode + "/NoPadding";

            // Without parameters: InvalidKeyException.
            try
            {
                Cipher.getInstance(tf, JostleProvider.PROVIDER_NAME).init(Cipher.ENCRYPT_MODE, key);
                failures.add(tf + " initialised without parameters - it is now reachable "
                        + "and needs a chunking row in this matrix");
            }
            catch (java.security.InvalidKeyException e)
            {
                if (!"mode not supported for cipher".equals(e.getMessage()))
                {
                    failures.add(tf + " no-params message: " + e.getMessage());
                }
            }
            catch (Exception e)
            {
                failures.add(tf + " no-params expected InvalidKeyException, got "
                        + e.getClass().getName() + ": " + e.getMessage());
            }

            // With parameters: InvalidAlgorithmParameterException.
            try
            {
                Cipher.getInstance(tf, JostleProvider.PROVIDER_NAME)
                        .init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(new byte[16]));
                failures.add(tf + " initialised with parameters - it is now reachable "
                        + "and needs a chunking row in this matrix");
            }
            catch (java.security.InvalidAlgorithmParameterException e)
            {
                if (!"mode not supported for cipher".equals(e.getMessage()))
                {
                    failures.add(tf + " with-params message: " + e.getMessage());
                }
            }
            catch (Exception e)
            {
                failures.add(tf + " with-params expected InvalidAlgorithmParameterException, got "
                        + e.getClass().getName() + ": " + e.getMessage());
            }
        }

        if (!failures.isEmpty())
        {
            Assertions.fail(String.join("\n  ", failures));
        }
    }


    private static String describe(int chunk)
    {
        return chunk <= 0 ? "one-shot" : Integer.toString(chunk);
    }
}
