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
