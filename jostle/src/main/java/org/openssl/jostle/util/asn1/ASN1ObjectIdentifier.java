/*
 *  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.util.asn1;

import java.math.BigInteger;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * A minimal representation of the ASN.1 OBJECT IDENTIFIER type, carrying the OID
 * as its dotted-decimal string form.
 * <p>
 * The validation gates mirror BouncyCastle's {@code org.bouncycastle.asn1.ASN1ObjectIdentifier}:
 * a contents-octet length cap and an identifier-string length cap (both
 * DoS guards against pathologically long OIDs whose decimal conversion would
 * otherwise blow up), identifier-format validation (first arc 0&ndash;2, second
 * arc &lt; 40 when the first is 0 or 1, decimal sub-identifiers with no leading
 * zeros), and minimal-encoding / non-truncation validation of the contents
 * octets. {@link #intern()} pools instances so equal OIDs collapse to one
 * reference, exactly as the BC parser does.
 */
public class ASN1ObjectIdentifier
{
    /**
     * Implementation limit on the length of the contents octets, matching BC
     * (which adopts OpenJDK's value). Converting an arbitrarily long OID to its
     * decimal string is a denial-of-service vector; this caps it.
     */
    private static final int MAX_CONTENTS_LENGTH = 4096;
    private static final int MAX_IDENTIFIER_LENGTH = MAX_CONTENTS_LENGTH * 4 + 1;

    private static final long LONG_LIMIT = (Long.MAX_VALUE >> 7) - 0x7F;

    /**
     * Pool of interned OIDs, keyed by the canonical dotted-decimal form. Used by
     * {@link #intern()} to limit the number of duplicated OID objects in
     * circulation.
     */
    private static final ConcurrentMap<String, ASN1ObjectIdentifier> pool =
            new ConcurrentHashMap<String, ASN1ObjectIdentifier>();

    private final String id;

    /**
     * Create an OID from its dotted-decimal string form.
     *
     * @param id a string representation of an OID.
     * @throws NullPointerException     if {@code id} is null.
     * @throws IllegalArgumentException if {@code id} exceeds the length limit or
     *                                  is not a syntactically valid OID.
     */
    public ASN1ObjectIdentifier(String id)
    {
        checkIdentifier(id);
        this.id = id;
    }

    /**
     * Return an OID that creates a branch under the current one.
     *
     * @param branchID node numbers for the new branch (a relative OID).
     * @return the OID for the new created branch.
     * @throws IllegalArgumentException if {@code branchID} is not a valid relative OID.
     */
    public ASN1ObjectIdentifier branch(String branchID)
    {
        checkRelativeIdentifier(branchID);
        return new ASN1ObjectIdentifier(id + "." + branchID);
    }

    /**
     * Return the OID as a string.
     *
     * @return the string representation of the OID carried by this object.
     */
    public String getId()
    {
        return id;
    }

    public String toString()
    {
        return getId();
    }

    public boolean equals(Object o)
    {
        if (this == o)
        {
            return true;
        }
        if (!(o instanceof ASN1ObjectIdentifier))
        {
            return false;
        }
        return id.equals(((ASN1ObjectIdentifier) o).id);
    }

    public int hashCode()
    {
        return id.hashCode();
    }

    /**
     * Return a reference to a pooled instance equal to this one, adding this
     * instance to the pool if no equal instance is present yet. Mirrors BC's
     * {@code intern()} — callers that decode many OIDs from the wire can collapse
     * duplicates to a single shared reference.
     *
     * @return the pooled reference for this OID.
     */
    public ASN1ObjectIdentifier intern()
    {
        ASN1ObjectIdentifier oid = pool.get(id);
        if (oid == null)
        {
            synchronized (pool)
            {
                if (!pool.containsKey(id))
                {
                    pool.put(id, this);
                    return this;
                }
                return pool.get(id);
            }
        }
        return oid;
    }

    /**
     * Reconstruct an OID from the <em>contents octets</em> of its DER
     * {@code OBJECT IDENTIFIER} encoding — the value bytes that follow the tag
     * and length, NOT the full TLV. Callers that walk a larger structure read
     * the {@code 0x06} tag and length themselves, then hand the contents range
     * here; this is the one place the base-128 sub-identifier decoding lives.
     * <p>
     * The contents are validated before decoding: the length is bounded by
     * {@link #MAX_CONTENTS_LENGTH}, no sub-identifier may use a non-minimal
     * leading {@code 0x80} octet, and the final octet must complete a
     * sub-identifier (no dangling continuation bit).
     * <p>
     * The intern pool is <em>consulted</em>: if an equal OID has already been
     * interned, the shared instance is returned. Like BC's parser path, a miss
     * does NOT add to the pool — only {@link #intern()} populates it, so decoding
     * a stream of distinct (e.g. attacker-supplied) OIDs cannot grow the static
     * pool without bound.
     *
     * @param data buffer holding the contents octets.
     * @param off  offset of the first contents octet.
     * @param len  number of contents octets.
     * @return the reconstructed OID, shared with the pool when already interned.
     * @throws IllegalArgumentException if the range is out of bounds, exceeds the
     *                                  length limit, or the encoding is malformed.
     */
    public static ASN1ObjectIdentifier fromContents(byte[] data, int off, int len)
    {
        if (data == null || off < 0 || len <= 0 || len > data.length - off)
        {
            throw new IllegalArgumentException("invalid OID encoding");
        }
        checkContentsLength(len);
        if (!isValidContents(data, off, len))
        {
            throw new IllegalArgumentException("invalid OID contents");
        }

        String id = parseContents(data, off, len);
        ASN1ObjectIdentifier pooled = pool.get(id);
        if (pooled != null)
        {
            return pooled;
        }
        return new ASN1ObjectIdentifier(id);
    }

    private static int checkContentsLength(int contentsLength)
    {
        if (contentsLength > MAX_CONTENTS_LENGTH)
        {
            throw new IllegalArgumentException("exceeded OID contents length limit");
        }
        return contentsLength;
    }

    static void checkIdentifier(String identifier)
    {
        if (identifier == null)
        {
            throw new NullPointerException("'identifier' cannot be null");
        }
        if (identifier.length() > MAX_IDENTIFIER_LENGTH)
        {
            throw new IllegalArgumentException("exceeded OID contents length limit");
        }
        if (!isValidIdentifier(identifier))
        {
            throw new IllegalArgumentException("string " + identifier + " not a valid OID");
        }
    }

    private static void checkRelativeIdentifier(String branchID)
    {
        if (branchID == null)
        {
            throw new NullPointerException("'branchID' cannot be null");
        }
        if (branchID.length() > MAX_IDENTIFIER_LENGTH)
        {
            throw new IllegalArgumentException("exceeded OID contents length limit");
        }
        if (!isValidRelativeIdentifier(branchID, 0))
        {
            throw new IllegalArgumentException("string " + branchID + " not a valid branch");
        }
    }

    /**
     * Validate a full OID identifier: first arc 0&ndash;2, '.' separator, valid
     * decimal sub-identifiers, and (when the first arc is 0 or 1) a second arc
     * below 40. Ported from BC.
     */
    private static boolean isValidIdentifier(String identifier)
    {
        if (identifier.length() < 3 || identifier.charAt(1) != '.')
        {
            return false;
        }

        char first = identifier.charAt(0);
        if (first < '0' || first > '2')
        {
            return false;
        }

        if (!isValidRelativeIdentifier(identifier, 2))
        {
            return false;
        }

        if (first == '2')
        {
            return true;
        }

        if (identifier.length() == 3 || identifier.charAt(3) == '.')
        {
            return true;
        }

        if (identifier.length() == 4 || identifier.charAt(4) == '.')
        {
            return identifier.charAt(2) < '4';
        }

        return false;
    }

    /**
     * Validate the sub-identifiers of a (relative) OID from index {@code from}:
     * non-empty, decimal-only, with no leading zero in a multi-digit group.
     * Ported from BC's {@code ASN1RelativeOID.isValidIdentifier}.
     */
    private static boolean isValidRelativeIdentifier(String identifier, int from)
    {
        int digitCount = 0;

        int pos = identifier.length();
        while (--pos >= from)
        {
            char ch = identifier.charAt(pos);

            if (ch == '.')
            {
                if (0 == digitCount || (digitCount > 1 && identifier.charAt(pos + 1) == '0'))
                {
                    return false;
                }

                digitCount = 0;
            }
            else if ('0' <= ch && ch <= '9')
            {
                ++digitCount;
            }
            else
            {
                return false;
            }
        }

        if (0 == digitCount || (digitCount > 1 && identifier.charAt(pos + 1) == '0'))
        {
            return false;
        }

        return true;
    }

    /**
     * Validate OID contents octets: at least one octet, no sub-identifier with a
     * non-minimal leading {@code 0x80} octet, and a final octet that completes a
     * sub-identifier. Ported from BC's {@code ASN1RelativeOID.isValidContents}.
     */
    private static boolean isValidContents(byte[] data, int off, int len)
    {
        if (len < 1)
        {
            return false;
        }

        boolean subIDStart = true;
        for (int i = 0; i < len; ++i)
        {
            if (subIDStart && (data[off + i] & 0xFF) == 0x80)
            {
                return false;
            }

            subIDStart = (data[off + i] & 0x80) == 0;
        }

        return subIDStart;
    }

    /**
     * Decode validated contents octets to the dotted-decimal form. Uses a
     * {@code long} accumulator, switching to {@link BigInteger} for
     * sub-identifiers that would overflow it. Ported from BC.
     */
    private static String parseContents(byte[] data, int off, int len)
    {
        StringBuilder objId = new StringBuilder();
        long value = 0;
        BigInteger bigValue = null;
        boolean first = true;

        for (int i = 0; i < len; i++)
        {
            int b = data[off + i] & 0xFF;

            if (value <= LONG_LIMIT)
            {
                value += b & 0x7F;
                if ((b & 0x80) == 0)
                {
                    if (first)
                    {
                        if (value < 40)
                        {
                            objId.append('0');
                        }
                        else if (value < 80)
                        {
                            objId.append('1');
                            value -= 40;
                        }
                        else
                        {
                            objId.append('2');
                            value -= 80;
                        }
                        first = false;
                    }

                    objId.append('.');
                    objId.append(value);
                    value = 0;
                }
                else
                {
                    value <<= 7;
                }
            }
            else
            {
                if (bigValue == null)
                {
                    bigValue = BigInteger.valueOf(value);
                }
                bigValue = bigValue.or(BigInteger.valueOf(b & 0x7F));
                if ((b & 0x80) == 0)
                {
                    if (first)
                    {
                        objId.append('2');
                        bigValue = bigValue.subtract(BigInteger.valueOf(80));
                        first = false;
                    }

                    objId.append('.');
                    objId.append(bigValue);
                    bigValue = null;
                    value = 0;
                }
                else
                {
                    bigValue = bigValue.shiftLeft(7);
                }
            }
        }

        return objId.toString();
    }

}
