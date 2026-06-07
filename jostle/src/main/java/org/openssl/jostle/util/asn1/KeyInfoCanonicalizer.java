/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.util.asn1;

import org.openssl.jostle.util.Arrays;

/**
 * Canonicalises the {@code AlgorithmIdentifier} carried in a
 * SubjectPublicKeyInfo or PrivateKeyInfo so it is acceptable to OpenSSL.
 * <p>
 * FIPS 203 (ML-KEM), FIPS 204 (ML-DSA) and FIPS 205 (SLH-DSA), together with
 * the LAMPS certificate/key profiles, require the {@code parameters} field of
 * the AlgorithmIdentifier to be <em>absent</em>. Some providers instead encode
 * the absent parameters as an explicit ASN.1 NULL — notably the JDK's
 * {@code sun.security.x509.X509Key}, which re-encodes a key for an algorithm it
 * does not itself recognise and emits {@code 05 00}. OpenSSL's decoders reject
 * such an encoding (it surfaces as an {@code X509_PUBKEY_get0} / key-decode
 * error), so these helpers rebuild the structure with the stray NULL removed
 * before the bytes reach OpenSSL.
 * <p>
 * Only an exact NULL parameters element is stripped. Any input that does not
 * match the expected shape (or carries non-NULL parameters) is returned
 * unchanged, leaving OpenSSL to report the original error.
 */
public final class KeyInfoCanonicalizer
{
    private KeyInfoCanonicalizer()
    {
    }

    /**
     * Strip a stray NULL {@code parameters} from the AlgorithmIdentifier of a
     * {@code SubjectPublicKeyInfo ::= SEQUENCE { AlgorithmIdentifier, BIT STRING }}.
     */
    public static byte[] subjectPublicKeyInfo(byte[] spki)
    {
        try
        {
            int[] pos = {0};
            int end = readSequenceHeader(spki, pos);        // SubjectPublicKeyInfo
            int[] algPos = {pos[0]};
            int algEnd = readSequenceHeader(spki, algPos);  // AlgorithmIdentifier

            byte[] algId = strippedAlgorithmIdentifier(spki, algPos[0], algEnd);
            if (algId == null)
            {
                return spki;
            }

            byte[] subjectPublicKey = Arrays.copyOfRange(spki, algEnd, end);
            return derSequence(Arrays.concatenate(algId, subjectPublicKey));
        }
        catch (RuntimeException e)
        {
            return spki;
        }
    }

    /**
     * Strip a stray NULL {@code parameters} from the privateKeyAlgorithm of a
     * {@code PrivateKeyInfo ::= SEQUENCE { INTEGER version, AlgorithmIdentifier,
     * OCTET STRING privateKey, ... }}. Any trailing fields (attributes [0],
     * publicKey [1]) are preserved verbatim.
     */
    public static byte[] privateKeyInfo(byte[] pki)
    {
        try
        {
            int[] pos = {0};
            int end = readSequenceHeader(pki, pos);         // PrivateKeyInfo
            int versionStart = pos[0];
            int[] versionPos = {versionStart};
            skipTlv(pki, versionPos);                       // version INTEGER
            int algStart = versionPos[0];
            int[] algPos = {algStart};
            int algEnd = readSequenceHeader(pki, algPos);   // privateKeyAlgorithm

            byte[] algId = strippedAlgorithmIdentifier(pki, algPos[0], algEnd);
            if (algId == null)
            {
                return pki;
            }

            byte[] version = Arrays.copyOfRange(pki, versionStart, algStart);
            byte[] rest = Arrays.copyOfRange(pki, algEnd, end);  // OCTET STRING + optional fields
            return derSequence(Arrays.concatenate(version, algId, rest));
        }
        catch (RuntimeException e)
        {
            return pki;
        }
    }

    /**
     * If the AlgorithmIdentifier whose content spans {@code [algContentStart, algEnd)}
     * carries exactly an OBJECT IDENTIFIER followed by a NULL, return a rebuilt
     * AlgorithmIdentifier TLV ({@code SEQUENCE { OID }}) with the NULL removed;
     * otherwise return {@code null} to signal "nothing to canonicalise".
     */
    private static byte[] strippedAlgorithmIdentifier(byte[] data, int algContentStart, int algEnd)
    {
        int[] pos = {algContentStart};
        int oidStart = pos[0];
        skipTlv(data, pos);                                 // algorithm OBJECT IDENTIFIER
        int oidEnd = pos[0];

        if (pos[0] >= algEnd)
        {
            return null;                                    // no parameters -> already conformant
        }
        // Only an exact NULL (05 00) filling the remainder of the AlgorithmIdentifier is stripped.
        if (algEnd - pos[0] != 2
                || (data[pos[0]] & 0xFF) != 0x05
                || (data[pos[0] + 1] & 0xFF) != 0x00)
        {
            return null;
        }
        return derSequence(Arrays.copyOfRange(data, oidStart, oidEnd));
    }

    /**
     * Consume a SEQUENCE tag and length starting at {@code pos[0]}, advance
     * {@code pos[0]} to the first content byte, and return the offset one past
     * the SEQUENCE content.
     */
    private static int readSequenceHeader(byte[] data, int[] pos)
    {
        if (pos[0] >= data.length || (data[pos[0]++] & 0xFF) != 0x30)
        {
            throw new IllegalArgumentException("expected SEQUENCE");
        }
        int len = readLength(data, pos);
        int end = pos[0] + len;
        if (end > data.length)
        {
            throw new IllegalArgumentException("SEQUENCE length overrun");
        }
        return end;
    }

    /** Skip a single (single-byte-tag) TLV, advancing {@code pos[0]} past it. */
    private static void skipTlv(byte[] data, int[] pos)
    {
        if (pos[0] >= data.length)
        {
            throw new IllegalArgumentException("truncated TLV");
        }
        pos[0]++;   // tag
        int len = readLength(data, pos);
        pos[0] += len;
        if (pos[0] > data.length)
        {
            throw new IllegalArgumentException("TLV length overrun");
        }
    }

    private static int readLength(byte[] data, int[] pos)
    {
        if (pos[0] >= data.length)
        {
            throw new IllegalArgumentException("truncated length");
        }
        int b = data[pos[0]++] & 0xFF;
        if ((b & 0x80) == 0)
        {
            return b;
        }
        int count = b & 0x7F;
        if (count == 0 || count > 4)
        {
            throw new IllegalArgumentException("unsupported length");
        }
        int len = 0;
        for (int i = 0; i < count; i++)
        {
            if (pos[0] >= data.length)
            {
                throw new IllegalArgumentException("truncated length");
            }
            len = (len << 8) | (data[pos[0]++] & 0xFF);
        }
        if (len < 0)
        {
            throw new IllegalArgumentException("length out of range");
        }
        return len;
    }

    private static byte[] derSequence(byte[] content)
    {
        return Arrays.concatenate(new byte[]{0x30}, derLength(content.length), content);
    }

    private static byte[] derLength(int len)
    {
        if (len < 0x80)
        {
            return new byte[]{(byte) len};
        }
        if (len < 0x100)
        {
            return new byte[]{(byte) 0x81, (byte) len};
        }
        if (len < 0x10000)
        {
            return new byte[]{(byte) 0x82, (byte) (len >>> 8), (byte) len};
        }
        if (len < 0x1000000)
        {
            return new byte[]{(byte) 0x83, (byte) (len >>> 16), (byte) (len >>> 8), (byte) len};
        }
        return new byte[]{(byte) 0x84, (byte) (len >>> 24), (byte) (len >>> 16), (byte) (len >>> 8), (byte) len};
    }
}
