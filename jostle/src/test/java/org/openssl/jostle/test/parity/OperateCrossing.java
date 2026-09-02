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

package org.openssl.jostle.test.parity;

import org.openssl.jostle.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * The bidirectional operate-crossing for the two generator surfaces.
 *
 * <h2>Why a shape descriptor is not enough on its own</h2>
 *
 * <p>{@link Observation#produced} compares generated keys by their
 * caller-visible SHAPE, because a fresh key has no comparable bytes. A shape is
 * strictly weaker evidence: <b>it would accept a generator returning a
 * correctly-labelled, correctly-sized key full of zeros.</b> Nothing about
 * algorithm, format and length distinguishes a real key from a plausible one.
 *
 * <p>So a surface using descriptors owes a second check that only a working key
 * can pass. That is this class, and it was a condition of adopting the
 * descriptor rather than an optional extra.
 *
 * <h2>The two checks, and why they differ by key kind</h2>
 *
 * <ol>
 *   <li><b>Asymmetric</b> - we generate, encode, and the OTHER provider decodes
 *       and operates: it verifies a signature we made, or derives a shared
 *       secret equal to ours. A zero-filled or mismatched pair fails, and so
 *       does a mis-encoded AlgorithmIdentifier, which is the encoding-crossing
 *       check coming along for free.</li>
 *   <li><b>Symmetric</b> - a round-trip alone would NOT catch zeros, because a
 *       zero key encrypts and decrypts perfectly well. So the symmetric
 *       crossing additionally requires two generations to produce DIFFERENT
 *       bytes. That is the check that actually excludes a constant generator,
 *       and it is why this is not simply "encrypt with one, decrypt with the
 *       other".</li>
 * </ol>
 *
 * <h2>Families with no operation surface get a NAMED exception</h2>
 *
 * <p>The TLS hybrid KEMs have no encoding at all, so nothing can cross; the
 * ML-KEM key generator encapsulates to a recipient rather than producing a
 * standalone key. Those are named in the caller's table with the reason, never
 * silently skipped - an unexplained absence is indistinguishable from an
 * untested one.
 */
public final class OperateCrossing
{
    private OperateCrossing()
    {
    }

    /** What operation a family's keys can be crossed through. */
    public enum Op
    {
        SIGNATURE,
        KEY_AGREEMENT,
        /** No operation surface - the reason is carried alongside. */
        NONE
    }

    /** The outcome, as a short string for the survey row. */
    public static final class Result
    {
        public final boolean crossed;
        public final String detail;

        Result(boolean crossed, String detail)
        {
            this.crossed = crossed;
            this.detail = detail;
        }

        @Override
        public String toString()
        {
            return (crossed ? "CROSSED: " : "NOT CROSSED: ") + detail;
        }
    }

    /**
     * Generate on {@code producer}, cross the ENCODINGS to {@code consumer},
     * and have the consumer operate.
     *
     * @param kpgAlgorithm generator name on the producer
     * @param kfAlgorithm  KeyFactory name on the consumer
     * @param opAlgorithm  Signature or KeyAgreement name on the consumer
     */
    public static Result asymmetric(Provider producer, Provider consumer, Op op,
                                    String kpgAlgorithm, String kfAlgorithm, String opAlgorithm,
                                    int keySize)
    {
        try
        {
            KeyPairGenerator g = KeyPairGenerator.getInstance(kpgAlgorithm, producer);
            if (keySize > 0)
            {
                g.initialize(keySize);
            }
            KeyPair a = g.generateKeyPair();
            byte[] pub = a.getPublic().getEncoded();
            if (pub == null)
            {
                return new Result(false, "no encoding - nothing can cross");
            }
            KeyFactory kf = KeyFactory.getInstance(kfAlgorithm, consumer);
            PublicKey theirPub = kf.generatePublic(new X509EncodedKeySpec(pub));

            if (op == Op.SIGNATURE)
            {
                byte[] msg = new byte[64];
                new SecureRandom().nextBytes(msg);
                Signature s = Signature.getInstance(opAlgorithm, producer);
                s.initSign(a.getPrivate());
                s.update(msg);
                byte[] sig = s.sign();
                Signature v = Signature.getInstance(opAlgorithm, consumer);
                v.initVerify(theirPub);
                v.update(msg);
                if (!v.verify(sig))
                {
                    return new Result(false, "the other provider REFUSED a signature made with this key");
                }
                // And the negative half: a tampered message must NOT verify, or
                // "verified" proves nothing about the key.
                msg[0] ^= (byte) 0x01;
                Signature v2 = Signature.getInstance(opAlgorithm, consumer);
                v2.initVerify(theirPub);
                v2.update(msg);
                if (v2.verify(sig))
                {
                    return new Result(false, "a TAMPERED message verified - the check is vacuous");
                }
                return new Result(true, "signed here, verified there; tampered message rejected");
            }

            // Key agreement: both sides must derive the SAME secret from the
            // same pair of keys, which a zero-filled key cannot fake.
            KeyPair b = g.generateKeyPair();
            PrivateKey theirPriv = kf.generatePrivate(new PKCS8EncodedKeySpec(b.getPrivate().getEncoded()));
            KeyAgreement ours = KeyAgreement.getInstance(opAlgorithm, producer);
            ours.init(a.getPrivate());
            ours.doPhase(b.getPublic(), true);
            byte[] mine = ours.generateSecret();
            KeyAgreement theirs = KeyAgreement.getInstance(opAlgorithm, consumer);
            theirs.init(theirPriv);
            theirs.doPhase(theirPub, true);
            byte[] other = theirs.generateSecret();
            if (!Arrays.areEqual(mine, other))
            {
                return new Result(false, "derived secrets differ across providers");
            }
            if (allZero(mine))
            {
                return new Result(false, "derived secret is all zeros");
            }
            return new Result(true, "agreed to an identical " + mine.length + "-byte secret");
        }
        catch (Throwable t)
        {
            return new Result(false, t.getClass().getSimpleName()
                    + (t.getMessage() == null ? "" : ": " + brief(t.getMessage())));
        }
    }

    /**
     * Symmetric crossing: round-trip through the other provider AND require two
     * generations to differ.
     *
     * <p>The distinctness half is the one that matters. A round-trip is passed
     * by a generator returning a constant, because a constant key encrypts and
     * decrypts perfectly - which is precisely the failure the descriptor cannot
     * see.
     */
    public static Result symmetric(Provider producer, Provider consumer,
                                   String kgAlgorithm, int keySize, String transformation)
    {
        try
        {
            javax.crypto.KeyGenerator g = javax.crypto.KeyGenerator.getInstance(kgAlgorithm, producer);
            if (keySize > 0)
            {
                g.init(keySize);
            }
            SecretKey k1 = g.generateKey();
            SecretKey k2 = g.generateKey();
            byte[] b1 = k1.getEncoded();
            byte[] b2 = k2.getEncoded();
            if (b1 == null)
            {
                return new Result(false, "no encoding - nothing can cross");
            }
            if (allZero(b1))
            {
                return new Result(false, "generated key is all zeros");
            }
            if (Arrays.areEqual(b1, b2))
            {
                return new Result(false, "two generations produced IDENTICAL key bytes");
            }

            byte[] pt = new byte[32];
            new SecureRandom().nextBytes(pt);
            Cipher enc = Cipher.getInstance(transformation, producer);
            // Let the cipher CHOOSE its own IV and then read it back, rather
            // than the harness deciding a length. Two earlier versions got this
            // wrong in different ways: a hardcoded 16 failed DESede, whose
            // block is 8; and getBlockSize() before init raises
            // IllegalStateException on this provider. Both read exactly like a
            // provider rejecting a valid key, which is why neither is
            // acceptable in a crossing whose job is to prove keys work.
            enc.init(Cipher.ENCRYPT_MODE, k1);
            byte[] iv = enc.getIV();
            byte[] ct = enc.doFinal(pt);

            // The other provider gets the raw bytes, which is the only crossing
            // a secret key has - there is no encoded form to decode.
            Cipher dec = Cipher.getInstance(transformation, consumer);
            dec.init(Cipher.DECRYPT_MODE, new SecretKeySpec(b1, k1.getAlgorithm()),
                    new IvParameterSpec(iv));
            if (!Arrays.areEqual(pt, dec.doFinal(ct)))
            {
                return new Result(false, "round-trip through the other provider did not recover the plaintext");
            }
            return new Result(true, "distinct across generations, and round-tripped through the other provider");
        }
        catch (Throwable t)
        {
            return new Result(false, t.getClass().getSimpleName()
                    + (t.getMessage() == null ? "" : ": " + brief(t.getMessage())));
        }
    }

    /**
     * Distinctness alone, for a family with no shared transformation to cross
     * through.
     *
     * <p>Strictly weaker than {@link #symmetric} - it says nothing about the
     * other provider - but it is the half that actually excludes a constant or
     * zero-filled generator, so it is worth having on its own where the
     * round-trip cannot be arranged.
     */
    public static Result distinctness(Provider producer, String kgAlgorithm, int keySize)
    {
        try
        {
            javax.crypto.KeyGenerator g = javax.crypto.KeyGenerator.getInstance(kgAlgorithm, producer);
            if (keySize > 0)
            {
                g.init(keySize);
            }
            byte[] b1 = g.generateKey().getEncoded();
            byte[] b2 = g.generateKey().getEncoded();
            if (b1 == null)
            {
                return new Result(false, "no encoding");
            }
            if (allZero(b1))
            {
                return new Result(false, "generated key is all zeros");
            }
            if (Arrays.areEqual(b1, b2))
            {
                return new Result(false, "two generations produced IDENTICAL key bytes");
            }
            return new Result(true, "distinct across generations, " + b1.length + " bytes");
        }
        catch (Throwable t)
        {
            return new Result(false, t.getClass().getSimpleName()
                    + (t.getMessage() == null ? "" : ": " + brief(t.getMessage())));
        }
    }

    private static boolean allZero(byte[] b)
    {
        for (byte x : b)
        {
            if (x != 0)
            {
                return false;
            }
        }
        return true;
    }

    private static String brief(String m)
    {
        String s = m.replace('\n', ' ');
        return s.length() > 60 ? s.substring(0, 60) + "..." : s;
    }
}
