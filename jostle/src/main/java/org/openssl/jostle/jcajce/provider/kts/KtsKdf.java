/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider.kts;

import org.openssl.jostle.util.Arrays;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;

/**
 * The key-derivation functions the KTS ciphers accept, and the derivations
 * themselves.
 *
 * <p>Shared by {@code RSAKEMCipherSpi} and {@code MLKEMKTSCipherSpi} so the
 * derivations and the refusal messages exist once rather than in four files
 * (each SPI has a {@code java9/} copy). Every primitive is taken from the
 * calling SPI's own provider instance, never from JCA order.
 *
 * <p>This package is deliberately not exported.
 */
public final class KtsKdf
{
    /** X9.44 KDF2. Its AlgorithmIdentifier carries a digest AlgorithmIdentifier. */
    public static final String ID_KDF_KDF2 = "1.3.133.16.840.9.44.1.1";

    /** X9.44 KDF3 (NIST concatenation KDF). Same parameter shape as KDF2. */
    public static final String ID_KDF_KDF3 = "1.3.133.16.840.9.44.1.2";

    private static final String ID_HKDF_SHA256 = "1.2.840.113549.1.9.16.3.28";
    private static final String ID_HKDF_SHA384 = "1.2.840.113549.1.9.16.3.29";
    private static final String ID_HKDF_SHA512 = "1.2.840.113549.1.9.16.3.30";

    /** Named in both refusal messages so the caller learns what IS accepted. */
    private static final String ACCEPTED = "KDF2, KDF3, HKDF-SHA256/384/512";

    private KtsKdf()
    {
    }

    /** Which family a KDF OID names, and how its parameters are shaped. */
    public enum Kind
    {
        /** {@code Hash(Z || counter || otherInfo)}, counter from 1. */
        KDF2,
        /** {@code Hash(counter || Z || otherInfo)}, counter from 1. */
        KDF3,
        /** RFC 5869, IKM = Z, salt absent, info = otherInfo. */
        HKDF
    }

    /**
     * @return the family the OID names, or null when it names none.
     */
    public static Kind kindForOid(String kdfOid)
    {
        if (ID_KDF_KDF2.equals(kdfOid))
        {
            return Kind.KDF2;
        }
        if (ID_KDF_KDF3.equals(kdfOid))
        {
            return Kind.KDF3;
        }
        if (ID_HKDF_SHA256.equals(kdfOid) || ID_HKDF_SHA384.equals(kdfOid) || ID_HKDF_SHA512.equals(kdfOid))
        {
            return Kind.HKDF;
        }
        return null;
    }

    /**
     * The digest an HKDF OID names. RFC 8619 gives one OID per digest and
     * requires the parameters be absent, so the digest can only come from here.
     */
    public static String hkdfDigestForOid(String kdfOid)
    {
        if (ID_HKDF_SHA256.equals(kdfOid))
        {
            return "SHA-256";
        }
        if (ID_HKDF_SHA384.equals(kdfOid))
        {
            return "SHA-384";
        }
        if (ID_HKDF_SHA512.equals(kdfOid))
        {
            return "SHA-512";
        }
        return null;
    }

    /** Identical in both SPIs, so a caller sees one sentence whichever it used. */
    public static String unsupportedKdfMessage(String kdfOid)
    {
        return "unsupported KDF " + kdfOid + "; supported: " + ACCEPTED;
    }

    /** Likewise. RFC 8619 forbids the parameter on HKDF, X9.44 requires it. */
    public static String digestParameterRequiredMessage()
    {
        return "KDF2 and KDF3 require a digest AlgorithmIdentifier parameter";
    }

    /**
     * RFC 8619 requires HKDF's parameters be absent, so a present one is
     * malformed. BouncyCastle refuses it too, but with an unchecked
     * {@code IllegalStateException("HDKF parameter support not added")}
     * (measured, 1.85.2); {@code engineInit}'s contract names
     * {@code InvalidAlgorithmParameterException}, so we diverge deliberately.
     */
    public static String hkdfParametersForbiddenMessage()
    {
        return "HKDF must carry absent parameters (RFC 8619)";
    }

    /**
     * Derive {@code outLen} bytes of key-encryption key.
     *
     * @param ownProvider the calling SPI's provider instance; primitives come
     *                    from it and never from JCA order.
     */
    public static byte[] derive(Provider ownProvider, Kind kind, String digestName,
                                byte[] z, byte[] otherInfo, int outLen)
        throws NoSuchAlgorithmException
    {
        switch (kind)
        {
        case KDF2:
            return x944(ownProvider, digestName, z, otherInfo, outLen, false);
        case KDF3:
            return x944(ownProvider, digestName, z, otherInfo, outLen, true);
        case HKDF:
            return hkdf(ownProvider, digestName, z, otherInfo, outLen);
        default:
            throw new NoSuchAlgorithmException("unhandled KDF kind " + kind);
        }
    }

    /**
     * X9.44 KDF2 and KDF3. They differ only in whether the counter precedes or
     * follows Z, so one loop serves both and the pair cannot drift apart.
     * Byte-for-byte BouncyCastle's {@code KDF2BytesGenerator} and
     * {@code ConcatenationKDFGenerator} respectively.
     */
    private static byte[] x944(Provider ownProvider, String digestName, byte[] z,
                               byte[] otherInfo, int outLen, boolean counterFirst)
        throws NoSuchAlgorithmException
    {
        MessageDigest md = digestFromOwnProvider(ownProvider, digestName);
        byte[] out = new byte[outLen];
        byte[] counter = new byte[4];
        int pos = 0;
        int i = 1;
        while (pos < outLen)
        {
            counter[0] = (byte) (i >>> 24);
            counter[1] = (byte) (i >>> 16);
            counter[2] = (byte) (i >>> 8);
            counter[3] = (byte) i;
            if (counterFirst)
            {
                md.update(counter);
                md.update(z);
            }
            else
            {
                md.update(z);
                md.update(counter);
            }
            if (otherInfo != null && otherInfo.length != 0)
            {
                md.update(otherInfo);
            }
            byte[] block = md.digest();
            int n = Math.min(block.length, outLen - pos);
            System.arraycopy(block, 0, out, pos, n);
            // block is KEK-derivation material — scrub each iteration.
            Arrays.fill(block, (byte) 0);
            pos += n;
            i++;
        }
        return out;
    }

    /**
     * RFC 5869 HKDF. RFC 9629 section 5 fixes the inputs for KEMRecipientInfo:
     * IKM is the shared secret, info is the DER-encoded CMSORIforKEMOtherInfo,
     * and the salt is carried as a parameter to the KDF AlgorithmIdentifier
     * only when one is present — which for RFC 8619's HKDF OIDs it never is
     * ("the parameters component of that type SHALL be absent"), so the salt is
     * absent here. RFC 5869 section 2.2 says an absent salt is HashLen zeros.
     */
    private static byte[] hkdf(Provider ownProvider, String digestName, byte[] z,
                               byte[] info, int outLen)
        throws NoSuchAlgorithmException
    {
        Mac mac = macFromOwnProvider(ownProvider, digestName);
        int hashLen = mac.getMacLength();
        if (outLen > 255 * hashLen)
        {
            throw new NoSuchAlgorithmException(
                    "HKDF cannot produce " + outLen + " bytes with " + digestName);
        }

        byte[] prk = null;
        byte[] t = new byte[0];
        byte[] out = new byte[outLen];
        try
        {
            // Extract: an absent salt is HashLen zero octets (RFC 5869 2.2).
            mac.init(new SecretKeySpec(new byte[hashLen], mac.getAlgorithm()));
            prk = mac.doFinal(z);

            // Expand (RFC 5869 2.3).
            mac.init(new SecretKeySpec(prk, mac.getAlgorithm()));
            int pos = 0;
            for (int i = 1; pos < outLen; i++)
            {
                mac.update(t);
                if (info != null && info.length != 0)
                {
                    mac.update(info);
                }
                mac.update((byte) i);
                byte[] next = mac.doFinal();
                Arrays.fill(t, (byte) 0);
                t = next;
                int n = Math.min(t.length, outLen - pos);
                System.arraycopy(t, 0, out, pos, n);
                pos += n;
            }
        }
        catch (InvalidKeyException e)
        {
            // Both keys are byte arrays we just built, so this cannot happen.
            throw new NoSuchAlgorithmException("HKDF could not be keyed: " + e.getMessage(), e);
        }
        finally
        {
            Arrays.fill(t, (byte) 0);
            if (prk != null)
            {
                Arrays.fill(prk, (byte) 0);
            }
        }
        return out;
    }

    private static Mac macFromOwnProvider(Provider ownProvider, String digestName)
        throws NoSuchAlgorithmException
    {
        // "SHA-256" -> "HMACSHA256", the spelling both providers register.
        String macName = "HMAC" + digestName.replace("-", "");
        if (ownProvider == null)
        {
            throw new NoSuchAlgorithmException(
                    "this cipher was constructed outside any provider, so the " + macName
                            + " KDF MAC cannot be computed by it; obtain the Cipher from a "
                            + "Jostle provider rather than constructing the SPI directly");
        }
        try
        {
            return Mac.getInstance(macName, ownProvider);
        }
        catch (NoSuchAlgorithmException e)
        {
            throw new NoSuchAlgorithmException(
                    "provider " + ownProvider.getName() + " does not serve " + macName
                            + ", so the KDF MAC cannot be computed by it", e);
        }
    }

    private static MessageDigest digestFromOwnProvider(Provider ownProvider, String name)
        throws NoSuchAlgorithmException
    {
        if (ownProvider == null)
        {
            throw new NoSuchAlgorithmException(
                    "this cipher was constructed outside any provider, so the " + name
                            + " KDF digest cannot be computed by it; obtain the Cipher from a "
                            + "Jostle provider rather than constructing the SPI directly");
        }
        try
        {
            return MessageDigest.getInstance(name, ownProvider);
        }
        catch (NoSuchAlgorithmException e)
        {
            throw new NoSuchAlgorithmException(
                    "provider " + ownProvider.getName() + " does not serve " + name
                            + ", so the KDF digest cannot be computed by it", e);
        }
    }
}
