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

import java.security.Key;
import java.security.KeyPair;
import java.security.interfaces.DSAKey;
import java.security.interfaces.ECKey;
import java.security.interfaces.RSAKey;

/**
 * Shape descriptors for randomly-valued results, and the self-witness that
 * makes them safe to compare across providers.
 *
 * <h2>Why a descriptor must be GENERATION-STABLE first</h2>
 *
 * <p>A descriptor is only evidence about a provider if it is the SAME for two
 * keys that provider generates. Exact encoded length is not: DER INTEGER
 * leading-zero stripping makes one key type's encoding vary by a byte between
 * generations - classically a DSA or DH {@code Y} value, whose top byte is zero
 * roughly one time in 256. A descriptor carrying raw encoded length would
 * therefore flicker {@code SILENT_DIVERGENCE} rows at random, and the flicker
 * would look exactly like a real finding.
 *
 * <p>So {@link #generationStable} is called per family BEFORE any cross-provider
 * comparison: it generates twice on the same provider and requires the two
 * descriptors to agree. A family that fails is reported, never silently
 * compared.
 *
 * <h2>Bucketing was the first answer and it was NOT ENOUGH</h2>
 *
 * <p>The first version bucketed the encoded length to 16 bytes, on the theory
 * that a wide-enough bucket absorbs the wobble. Measured, it does not - it makes
 * the flicker RARER, which is worse, because a rare flicker looks like a real
 * finding and a common one looks like a bug in the harness. Twelve RSA-2048
 * generations produced PKCS#8 encodings of 1215, 1216, 1217 and 1218 bytes, and
 * the 16-byte boundary sits at 1216: the bucket took two values. DSA and DH
 * wobble by a byte too and happened not to straddle a boundary, so they passed
 * by luck.
 *
 * <p>So the length is no longer measured from the encoding where the key can be
 * ASKED instead. {@code RSAKey}, {@code DSAKey}, {@code DHKey} and
 * {@code ECKey} all expose their own parameters, and a modulus or field bit
 * length is exact and identical across generations. Only where a key exposes
 * nothing does the bucketed encoded length remain, and there it is safe: the
 * PQC families have fixed-length encodings with no INTEGER to strip a leading
 * zero from.
 *
 * <p>The same instinct as querying OpenSSL for a fixed value rather than
 * transcribing it - ask the object, do not measure something derived from it.
 *
 */
public final class Descriptors
{
    private Descriptors()
    {
    }

    /** Bucket width, in bytes. Wide enough to absorb DER wobble, narrow enough to separate key sizes. */
    private static final int BUCKET = 16;

    /** Caller-visible shape of one key: algorithm, format, bucketed encoded size. */
    public static String of(Key k)
    {
        if (k == null)
        {
            return "null-key";
        }
        // Ask the key for its size wherever it can answer. Exact, and identical
        // across generations - unlike anything derived from the encoding.
        String asked = askedSize(k);
        if (asked != null)
        {
            return k.getAlgorithm() + "/" + k.getFormat() + "/" + asked;
        }
        byte[] enc = k.getEncoded();
        if (enc == null)
        {
            return k.getAlgorithm() + "/" + k.getFormat() + "/no-encoding";
        }
        // Bucket ONLY the DER-shaped formats. A RAW symmetric key's length is
        // exact - there is no INTEGER to strip a leading zero from - so
        // bucketing it destroys real information: at a 16-byte bucket a
        // 24-byte DESede key and a 16-byte AES key both read "~16B", which is
        // precisely the distinction the descriptor exists to carry.
        boolean der = "X.509".equals(k.getFormat()) || "PKCS#8".equals(k.getFormat());
        String size = der ? ("~" + ((enc.length / BUCKET) * BUCKET) + "B") : (enc.length + "B");
        return k.getAlgorithm() + "/" + k.getFormat() + "/" + size;
    }

    /** The key's own statement of its size, or null when it makes none. */
    private static String askedSize(Key k)
    {
        if (k instanceof RSAKey)
        {
            return ((RSAKey) k).getModulus().bitLength() + "bit";
        }
        if (k instanceof DSAKey && ((DSAKey) k).getParams() != null)
        {
            return ((DSAKey) k).getParams().getP().bitLength() + "bit";
        }
        if (k instanceof javax.crypto.interfaces.DHKey)
        {
            return ((javax.crypto.interfaces.DHKey) k).getParams().getP().bitLength() + "bit";
        }
        if (k instanceof ECKey && ((ECKey) k).getParams() != null)
        {
            return ((ECKey) k).getParams().getCurve().getField().getFieldSize() + "bit";
        }
        return null;
    }

    /** Caller-visible shape of a keypair: both halves, public first. */
    public static String of(KeyPair kp)
    {
        if (kp == null)
        {
            return "null-keypair";
        }
        return "pub[" + of(kp.getPublic()) + "] priv[" + of(kp.getPrivate()) + "]";
    }

    /** What a generator produced twice, and whether the descriptor held. */
    public static final class Stability
    {
        public final boolean stable;
        public final String first;
        public final String second;

        Stability(String first, String second)
        {
            this.first = first;
            this.second = second;
            this.stable = first.equals(second);
        }

        @Override
        public String toString()
        {
            return stable ? ("stable: " + first) : ("UNSTABLE: " + first + " vs " + second);
        }
    }

    /** Produces one descriptor; called twice by {@link #generationStable}. */
    public interface Generation
    {
        String describe() throws Throwable;
    }

    /**
     * Generate twice on one provider and require the descriptors to agree.
     *
     * <p>The self-witness. A family whose descriptor is not stable against its
     * OWN generator cannot be evidence about another provider's, so the survey
     * reports it rather than comparing it.
     */
    public static Stability generationStable(Generation g)
    {
        String a;
        String b;
        try
        {
            a = g.describe();
            b = g.describe();
        }
        catch (Throwable t)
        {
            return new Stability("threw: " + t.getClass().getSimpleName(), "n/a");
        }
        return new Stability(a, b);
    }
}
