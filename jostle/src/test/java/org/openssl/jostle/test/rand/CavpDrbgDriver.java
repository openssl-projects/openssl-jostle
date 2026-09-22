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

package org.openssl.jostle.test.rand;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.prng.EntropySource;
import org.bouncycastle.crypto.prng.EntropySourceProvider;
import org.bouncycastle.crypto.prng.SP800SecureRandom;
import org.bouncycastle.crypto.prng.SP800SecureRandomBuilder;
import org.bouncycastle.crypto.prng.drbg.CTRSP800DRBG;
import org.bouncycastle.crypto.prng.drbg.HMacSP800DRBG;
import org.bouncycastle.crypto.prng.drbg.HashSP800DRBG;
import org.bouncycastle.crypto.prng.drbg.SP80090DRBG;
import org.openssl.jostle.jcajce.provider.rand.RandServiceNI;
import org.openssl.jostle.util.ops.OperationsTestNI;

import java.util.ArrayDeque;
import java.util.Deque;

/**
 * Drives one CAVP block through Jostle and through BouncyCastle, so the two can
 * be compared on the same row.
 *
 * <p>Both sides consume ONE ordered entropy queue: {@code EntropyInput}, then
 * {@code EntropyInputReseed} for a reseed row, or {@code EntropyInputPR} #1 and
 * #2 for a prediction-resistance row.
 *
 * <p><b>Absent inputs differ by side: JOSTLE GETS AN EMPTY ARRAY, BOUNCYCASTLE
 * GETS {@code null}.</b> OpenSSL derives different bytes from NULL and treats
 * empty as absent; BouncyCastle includes the field only when the reference is
 * non-null, so an empty array there produces wrong bytes with no error.
 */
public final class CavpDrbgDriver
{
    private CavpDrbgDriver()
    {
    }

    /**
     * Instantiates through the operations-test hook and generates twice through
     * the shipped {@code RandServiceNI} path, per the CAVP sequence.
     *
     * @return the two generate outputs; CAVP's ReturnedBits is the second
     */
    public static byte[][] driveJostle(OperationsTestNI ops, RandServiceNI rand,
                                       CavpDrbgVectors.Vector v)
    {
        int[] err = new int[1];
        long ref = ops.op_createTestDrbg(v.openSslMechanism(), v.openSslVariant(),
                v.usesDerivationFunction(), v.strength(), v.predictionResistant(),
                v.personalizationString, v.entropyInput, v.nonce, err);
        if (ref == 0)
        {
            throw new IllegalStateException("op_createTestDrbg failed for " + v.key()
                    + ": err=" + err[0]);
        }
        try
        {
            byte[] out = new byte[v.returnedBitsLen / 8];

            if (v.hasReseed())
            {
                // The reseed draws fresh entropy, so it is re-set through the
                // handle first; a create-time hook alone cannot drive this row.
                check(ops.op_setTestEntropy(ref, v.entropyInputReseed), "setTestEntropy(reseed)", v);
                check(rand.ni_contextReseed(ref, v.strength(), false, v.additionalInputReseed),
                        "ni_contextReseed", v);
            }
            if (v.predictionResistant())
            {
                check(ops.op_setTestEntropy(ref, v.entropyInputPR1), "setTestEntropy(PR1)", v);
            }
            check(rand.ni_contextRandomBytes(ref, out, out.length, v.strength(),
                    v.predictionResistant(), v.additionalInput1), "generate 1", v);
            byte[] first = new byte[out.length];
            System.arraycopy(out, 0, first, 0, out.length);

            if (v.predictionResistant())
            {
                check(ops.op_setTestEntropy(ref, v.entropyInputPR2), "setTestEntropy(PR2)", v);
            }
            check(rand.ni_contextRandomBytes(ref, out, out.length, v.strength(),
                    v.predictionResistant(), v.additionalInput2), "generate 2", v);

            return new byte[][]{first, out};
        }
        finally
        {
            rand.ni_disposeContext(ref);
        }
    }

    private static void check(int code, String what, CavpDrbgVectors.Vector v)
    {
        if (code < 0)
        {
            throw new IllegalStateException(what + " returned " + code + " for " + v.key());
        }
    }

    /**
     * The same row through BouncyCastle's lightweight SP 800-90A DRBGs, which
     * take additional input on generate. The JCE-level
     * {@link SP800SecureRandomBuilder} cannot express those rows; see
     * {@link #driveBouncyCastleBuilder}.
     */
    public static byte[][] driveBouncyCastle(CavpDrbgVectors.Vector v)
    {
        EntropySource source = new QueueSource(v.entropyInputLen, queue(v));
        SP80090DRBG drbg = newDrbg(v, source);

        byte[] out = new byte[v.returnedBitsLen / 8];
        if (v.hasReseed())
        {
            drbg.reseed(orNull(v.additionalInputReseed));
        }
        drbg.generate(out, orNull(v.additionalInput1), v.predictionResistant());
        byte[] first = new byte[out.length];
        System.arraycopy(out, 0, first, 0, out.length);
        drbg.generate(out, orNull(v.additionalInput2), v.predictionResistant());
        return new byte[][]{first, out};
    }

    /**
     * The same row through the JCE-level builder, which is the API a caller
     * reaches for. It exposes only {@code nextBytes(byte[])}, so it can drive a
     * row with no additional input and no other.
     *
     * <p>Instantiation through the builder is LAZY: the first entropy draw
     * happens on the first operation, not at build, so a reseed row's two draws
     * both land inside {@code reseed}.
     */
    public static byte[][] driveBouncyCastleBuilder(CavpDrbgVectors.Vector v)
    {
        if (v.additionalInput1.length != 0 || v.additionalInput2.length != 0)
        {
            throw new IllegalArgumentException(
                    "the builder exposes no additional input: " + v.key());
        }

        final Deque<byte[]> queue = queue(v);
        SP800SecureRandomBuilder builder = new SP800SecureRandomBuilder(new EntropySourceProvider()
        {
            @Override
            public EntropySource get(int bitsRequired)
            {
                return new QueueSource(bitsRequired, queue);
            }
        });
        builder.setEntropyBitsRequired(v.entropyInputLen);
        builder.setSecurityStrength(v.strength());
        if (v.personalizationString.length != 0)
        {
            builder.setPersonalizationString(v.personalizationString);
        }

        SP800SecureRandom random;
        if (v.file.equals("Hash_DRBG"))
        {
            random = builder.buildHash(digest(v), v.nonce, v.predictionResistant());
        }
        else if (v.file.equals("HMAC_DRBG"))
        {
            random = builder.buildHMAC(new HMac(digest(v)), v.nonce, v.predictionResistant());
        }
        else
        {
            random = builder.buildCTR(AESEngine.newInstance(), keySizeBits(v), v.nonce,
                    v.predictionResistant());
        }

        byte[] out = new byte[v.returnedBitsLen / 8];
        if (v.hasReseed())
        {
            random.reseed(orNull(v.additionalInputReseed));
        }
        random.nextBytes(out);
        byte[] first = new byte[out.length];
        System.arraycopy(out, 0, first, 0, out.length);
        random.nextBytes(out);
        return new byte[][]{first, out};
    }

    private static SP80090DRBG newDrbg(CavpDrbgVectors.Vector v, EntropySource source)
    {
        byte[] ps = orNull(v.personalizationString);
        if (v.file.equals("Hash_DRBG"))
        {
            return new HashSP800DRBG(digest(v), v.strength(), source, ps, v.nonce);
        }
        if (v.file.equals("HMAC_DRBG"))
        {
            return new HMacSP800DRBG(new HMac(digest(v)), v.strength(), source, ps, v.nonce);
        }
        BlockCipher aes = AESEngine.newInstance();
        return new CTRSP800DRBG(aes, keySizeBits(v), v.strength(), source, ps, v.nonce);
    }

    private static int keySizeBits(CavpDrbgVectors.Vector v)
    {
        return Integer.parseInt(v.mechanism.substring(4, v.mechanism.indexOf(' ')));
    }

    private static Digest digest(CavpDrbgVectors.Vector v)
    {
        String name = v.mechanism;
        if (name.equals("SHA-1"))
        {
            return new SHA1Digest();
        }
        if (name.equals("SHA-224"))
        {
            return new SHA224Digest();
        }
        if (name.equals("SHA-256"))
        {
            return new SHA256Digest();
        }
        if (name.equals("SHA-384"))
        {
            return new SHA384Digest();
        }
        if (name.equals("SHA-512"))
        {
            return new SHA512Digest();
        }
        throw new IllegalArgumentException("no BC digest for " + name);
    }

    private static byte[] orNull(byte[] value)
    {
        return value.length == 0 ? null : value;
    }

    private static Deque<byte[]> queue(CavpDrbgVectors.Vector v)
    {
        Deque<byte[]> queue = new ArrayDeque<byte[]>();
        queue.add(v.entropyInput);
        if (v.hasReseed())
        {
            queue.add(v.entropyInputReseed);
        }
        if (v.predictionResistant())
        {
            queue.add(v.entropyInputPR1);
            queue.add(v.entropyInputPR2);
        }
        return queue;
    }

    /** Hands out the vector's entropy in order, and refuses to invent any. */
    private static final class QueueSource implements EntropySource
    {
        private final int bits;
        private final Deque<byte[]> queue;

        private QueueSource(int bits, Deque<byte[]> queue)
        {
            this.bits = bits;
            this.queue = queue;
        }

        @Override
        public boolean isPredictionResistant()
        {
            return false;
        }

        @Override
        public int entropySize()
        {
            return bits;
        }

        @Override
        public byte[] getEntropy()
        {
            byte[] value = queue.poll();
            if (value == null)
            {
                // Silence here would make BC seed itself and diverge for a reason
                // no assertion could name.
                throw new IllegalStateException("BouncyCastle drew more entropy than the row supplies");
            }
            return value;
        }
    }
}
