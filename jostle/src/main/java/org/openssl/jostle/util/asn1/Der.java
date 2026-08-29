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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;

/**
 * Minimal DER reader/writer for the parameter codecs in
 * {@code jcajce.provider.*}, so none of them has to resolve an
 * {@code AlgorithmParameters} from another provider to encode or decode its
 * own registered service's parameters.
 *
 * <p>Scope is deliberately narrow: the definite-length TLVs that appear in
 * RFC 5084 GCM/CCM parameters, PKCS#3 and X9.42 Diffie-Hellman parameters,
 * DSA parameters and named-curve EC parameters. It is NOT a general ASN.1
 * library — indefinite lengths, constructed strings and tagged CHOICE
 * resolution are all rejected rather than guessed at.
 *
 * <p>Long-form lengths ARE handled, unlike the short-form-only reader inside
 * {@code CCMAlgorithmParameters}: a CCM nonce is bounded at 13 bytes, but a
 * GCM nonce is not, and a DSA or DH prime is always long-form.
 *
 * <p><b>Invariant: an allocation is sized only by bytes actually PRESENT,
 * never by a length the input claims.</b> A claimed length is checked against
 * the bytes remaining before any reader over that content exists, and
 * {@link Reader#remaining()} copies only the region already proved to be
 * there. This is the property that defeats length-claim over-read and
 * allocation attacks — the class a security report flagged against another
 * library's ASN.1 layer — so an edit that sizes a buffer from a parsed length
 * is breaking a named contract, not merely changing style.
 *
 * <p>Note the scope: this bounds a claim against the buffer. It does NOT bound
 * the buffer itself, so a caller that hands over an attacker-sized array still
 * gets an attacker-sized field. Per-field maxima are a separate control (see
 * MT-23) and neither substitutes for the other.
 */
public final class Der
{
    public static final int SEQUENCE = 0x30;
    public static final int INTEGER = 0x02;
    public static final int OCTET_STRING = 0x04;
    public static final int OBJECT_IDENTIFIER = 0x06;

    private Der()
    {
    }

    /**
     * Number of octets DER needs for a definite length: the minimum, big-endian.
     *
     * <p>The bound of 4 is not decoration. Java's shift count is taken mod 32,
     * so {@code len >>> 32} is {@code len >>> 0} — an unbounded loop testing
     * {@code (len >>> (8 * bytes)) != 0} never terminates once {@code bytes}
     * reaches 4, which is every length from 2^24 up. That made a 16 MiB IV a
     * hang rather than an encoding.
     */
    static int lengthOctets(int len)
    {
        int bytes = 1;
        while (bytes < 4 && (len >>> (8 * bytes)) != 0)
        {
            bytes++;
        }
        return bytes;
    }

    /** Encode one TLV, choosing short or long form for the length as DER requires. */
    public static byte[] tlv(int tag, byte[] content)
    {
        ByteArrayOutputStream out = new ByteArrayOutputStream(content.length + 8);
        out.write(tag);
        int len = content.length;
        if (len < 0x80)
        {
            out.write(len);
        }
        else
        {
            int bytes = lengthOctets(len);
            out.write(0x80 | bytes);
            for (int i = bytes - 1; i >= 0; i--)
            {
                out.write((len >>> (8 * i)) & 0xFF);
            }
        }
        out.write(content, 0, content.length);
        return out.toByteArray();
    }

    /** A non-negative INTEGER TLV. */
    public static byte[] integer(BigInteger v)
    {
        // BigInteger.toByteArray is already the minimal two's-complement form
        // DER wants, including the leading 0x00 when the top bit would be set.
        return tlv(INTEGER, v.toByteArray());
    }

    /** A small non-negative INTEGER TLV. */
    public static byte[] integer(int v)
    {
        return integer(BigInteger.valueOf(v));
    }

    /**
     * Upper bound on the arcs in an OBJECT IDENTIFIER this codec will encode or
     * decode. Every OID in the JCA surface has fewer than ten; 32 refuses a
     * pathological input without ruling out anything real.
     */
    public static final int MAX_OID_ARCS = 32;

    /**
     * Upper bound on an OBJECT IDENTIFIER's content octets. Mirrors
     * EC_CURVE_MAX_OID_BYTES in ec.h. The longest OID this provider handles is
     * the 20-character brainpool one; 128 leaves room without being open-ended.
     */
    public static final int MAX_OID_CONTENT_BYTES = 128;

    /**
     * Widest single arc, in bits. Nine base-128 octets carry 63 bits, which is
     * the most a Java {@code long} holds without becoming negative. An arc
     * beyond it is REFUSED rather than allowed to wrap — a silently wrapped arc
     * would decode to a different, valid-looking OID.
     */
    private static final int MAX_OID_ARC_BITS = 63;

    /**
     * Encode a dotted-decimal OBJECT IDENTIFIER TLV.
     *
     * <p>Rejects anything X.690 8.19 does not permit: fewer than two arcs, a
     * first arc outside 0..2, a second arc above 39 when the first is 0 or 1,
     * a negative or non-numeric arc, and an arc wider than
     * {@link #MAX_OID_ARC_BITS}.
     *
     * @throws IllegalArgumentException if {@code dotted} is not a valid OID.
     */
    public static byte[] objectIdentifier(String dotted)
    {
        if (dotted == null || dotted.isEmpty())
        {
            throw new IllegalArgumentException("empty object identifier");
        }
        String[] parts = dotted.split("\\.", -1);
        if (parts.length < 2)
        {
            throw new IllegalArgumentException(
                    "object identifier needs at least two arcs: " + dotted);
        }
        if (parts.length > MAX_OID_ARCS)
        {
            throw new IllegalArgumentException(
                    "object identifier has more than " + MAX_OID_ARCS + " arcs");
        }
        long[] arcs = new long[parts.length];
        for (int i = 0; i < parts.length; i++)
        {
            arcs[i] = parseArc(parts[i], dotted);
        }
        if (arcs[0] > 2)
        {
            throw new IllegalArgumentException(
                    "first arc of an object identifier must be 0, 1 or 2: " + dotted);
        }
        if (arcs[0] < 2 && arcs[1] > 39)
        {
            throw new IllegalArgumentException(
                    "second arc must be below 40 when the first is 0 or 1: " + dotted);
        }
        if (arcs[0] == 2 && arcs[1] > Long.MAX_VALUE - 80)
        {
            throw new IllegalArgumentException("second arc overflows: " + dotted);
        }

        // Bounded by construction: at most MAX_OID_ARCS arcs, each at most
        // nine base-128 octets, so the buffer cannot exceed 32 * 9 bytes
        // however hostile the input string is.
        ByteArrayOutputStream body = new ByteArrayOutputStream(MAX_OID_ARCS * 9);
        writeBase128(body, arcs[0] * 40 + arcs[1]);
        for (int i = 2; i < arcs.length; i++)
        {
            writeBase128(body, arcs[i]);
        }
        byte[] content = body.toByteArray();
        if (content.length > MAX_OID_CONTENT_BYTES)
        {
            throw new IllegalArgumentException(
                    "object identifier encodes to more than "
                            + MAX_OID_CONTENT_BYTES + " octets: " + dotted);
        }
        return tlv(OBJECT_IDENTIFIER, content);
    }

    private static long parseArc(String text, String dotted)
    {
        if (text.isEmpty())
        {
            throw new IllegalArgumentException("empty arc in object identifier: " + dotted);
        }
        // Deliberately not Long.parseLong: it accepts a leading '+' or '-',
        // neither of which belongs in an OID, and would then be rejected only
        // by the range check below on the '-' case.
        long value = 0;
        for (int i = 0; i < text.length(); i++)
        {
            char c = text.charAt(i);
            if (c < '0' || c > '9')
            {
                throw new IllegalArgumentException(
                        "non-numeric arc in object identifier: " + dotted);
            }
            if (value > (Long.MAX_VALUE - (c - '0')) / 10)
            {
                throw new IllegalArgumentException(
                        "arc too large in object identifier: " + dotted);
            }
            value = value * 10 + (c - '0');
        }
        return value;
    }

    private static void writeBase128(ByteArrayOutputStream out, long value)
    {
        if (value < 0 || 64 - Long.numberOfLeadingZeros(value) > MAX_OID_ARC_BITS)
        {
            throw new IllegalArgumentException("arc wider than "
                    + MAX_OID_ARC_BITS + " bits in object identifier");
        }
        int shift = 63;
        while (shift > 0 && (value >>> shift) == 0)
        {
            shift -= 7;
        }
        for (; shift > 0; shift -= 7)
        {
            out.write((int) ((value >>> shift) & 0x7F) | 0x80);
        }
        out.write((int) (value & 0x7F));
    }

    public static byte[] octetString(byte[] v)
    {
        return tlv(OCTET_STRING, v);
    }

    public static byte[] sequence(byte[]... items)
    {
        int n = 0;
        for (byte[] i : items)
        {
            n += i.length;
        }
        byte[] body = new byte[n];
        int off = 0;
        for (byte[] i : items)
        {
            System.arraycopy(i, 0, body, off, i.length);
            off += i.length;
        }
        return tlv(SEQUENCE, body);
    }

    /** Reader over one definite-length region. */
    public static final class Reader
    {
        private final byte[] buf;
        private int pos;
        private final int end;

        public Reader(byte[] buf)
        {
            this(buf, 0, buf.length);
        }

        private Reader(byte[] buf, int off, int len)
        {
            this.buf = buf;
            this.pos = off;
            this.end = off + len;
        }

        public boolean atEnd()
        {
            return pos >= end;
        }

        public void requireEnd(String message) throws IOException
        {
            if (pos != end)
            {
                throw new IOException(message);
            }
        }

        /** Tag of the next TLV without consuming it, or -1 at end. */
        public int peekTag()
        {
            return pos < end ? buf[pos] & 0xFF : -1;
        }

        /** Read one TLV of the expected tag; returns a Reader over its content. */
        public Reader readTLV(int expectedTag, String what) throws IOException
        {
            if (end - pos < 2)
            {
                throw new IOException("truncated " + what);
            }
            int tag = buf[pos++] & 0xFF;
            if (tag != expectedTag)
            {
                throw new IOException("expected " + what + " (tag 0x" + Integer.toHexString(expectedTag)
                        + "), got tag 0x" + Integer.toHexString(tag));
            }
            int len = buf[pos++] & 0xFF;
            if ((len & 0x80) != 0)
            {
                int count = len & 0x7F;
                if (count == 0)
                {
                    throw new IOException("indefinite length not permitted in " + what);
                }
                if (count > 4 || count > end - pos)
                {
                    throw new IOException("unsupported length form in " + what);
                }
                // DER requires the minimum octet count, so the first one
                // cannot be zero — 82 00 90 is BER, not DER.
                if (buf[pos] == 0)
                {
                    throw new IOException("non-minimal length encoding (leading zero octet) in " + what);
                }
                len = 0;
                for (int i = 0; i < count; i++)
                {
                    len = (len << 8) | (buf[pos++] & 0xFF);
                }
                if (len < 0)
                {
                    throw new IOException("length exceeds Integer.MAX_VALUE in " + what);
                }
                if (len < 0x80)
                {
                    throw new IOException("non-minimal length encoding in " + what);
                }
            }
            if (len > end - pos)
            {
                throw new IOException("truncated content in " + what);
            }
            Reader content = new Reader(buf, pos, len);
            pos += len;
            return content;
        }

        /** Remaining content bytes as a fresh array. */
        public byte[] remaining()
        {
            byte[] out = new byte[end - pos];
            System.arraycopy(buf, pos, out, 0, out.length);
            pos = end;
            return out;
        }

        /**
         * Read an OBJECT IDENTIFIER and return it in dotted-decimal form.
         *
         * <p>Strict per X.690 8.19 and DER: empty contents, a subidentifier
         * whose first octet is 0x80 (non-minimal base-128), a final octet that
         * still carries the continuation bit (truncated), an arc wider than 63
         * bits, and contents beyond {@link Der#MAX_OID_CONTENT_BYTES} are all
         * rejected.
         */
        public String readObjectIdentifier(String what) throws IOException
        {
            byte[] content = readTLV(OBJECT_IDENTIFIER, what).remaining();
            if (content.length == 0)
            {
                throw new IOException("empty OBJECT IDENTIFIER in " + what);
            }
            if (content.length > MAX_OID_CONTENT_BYTES)
            {
                throw new IOException("OBJECT IDENTIFIER longer than "
                        + MAX_OID_CONTENT_BYTES + " octets in " + what);
            }
            // Bounded by the check above: at most MAX_OID_CONTENT_BYTES
            // subidentifiers can appear in that many octets, so the builder
            // cannot grow past a few hundred characters.
            StringBuilder sb = new StringBuilder(MAX_OID_CONTENT_BYTES * 4);
            int arcs = 0;
            int i = 0;
            while (i < content.length)
            {
                if ((content[i] & 0xFF) == 0x80)
                {
                    throw new IOException(
                            "non-minimal subidentifier (leading 0x80) in " + what);
                }
                long value = 0;
                int bits = 0;
                while (true)
                {
                    if (i >= content.length)
                    {
                        throw new IOException(
                                "truncated subidentifier in " + what);
                    }
                    int octet = content[i++] & 0xFF;
                    bits += 7;
                    if (bits > MAX_OID_ARC_BITS)
                    {
                        throw new IOException("arc wider than "
                                + MAX_OID_ARC_BITS + " bits in " + what);
                    }
                    value = (value << 7) | (octet & 0x7F);
                    if ((octet & 0x80) == 0)
                    {
                        break;
                    }
                }
                if (++arcs > MAX_OID_ARCS)
                {
                    throw new IOException("more than " + MAX_OID_ARCS
                            + " arcs in " + what);
                }
                if (arcs == 1)
                {
                    // X.690 8.19.4: the first octet encodes 40 * arc1 + arc2.
                    long first = value < 40 ? 0 : (value < 80 ? 1 : 2);
                    sb.append(first).append('.').append(value - first * 40);
                }
                else
                {
                    sb.append('.').append(value);
                }
            }
            return sb.toString();
        }

        /** Read a non-negative INTEGER's value. */
        public BigInteger readInteger(String what) throws IOException
        {
            byte[] content = readTLV(INTEGER, what).remaining();
            if (content.length == 0)
            {
                throw new IOException("empty INTEGER in " + what);
            }
            // DER requires the shortest two's-complement form: a leading 0x00
            // is permitted ONLY to clear a top bit that would read as negative.
            if (content.length > 1 && content[0] == 0 && (content[1] & 0x80) == 0)
            {
                throw new IOException("non-minimal INTEGER encoding in " + what);
            }
            if (content.length > 1 && content[0] == (byte) 0xFF && (content[1] & 0x80) != 0)
            {
                throw new IOException("non-minimal INTEGER encoding in " + what);
            }
            BigInteger v = new BigInteger(content);
            if (v.signum() < 0)
            {
                throw new IOException("negative INTEGER in " + what);
            }
            return v;
        }

        /** Read an INTEGER that must fit in a non-negative int. */
        public int readSmallInteger(String what) throws IOException
        {
            BigInteger v = readInteger(what);
            if (v.bitLength() > 31)
            {
                throw new IOException("INTEGER out of range in " + what);
            }
            return v.intValue();
        }
    }
}
