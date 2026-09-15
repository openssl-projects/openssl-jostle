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

import org.openssl.jostle.util.Properties;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.TimeZone;

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
    public static final int BIT_STRING = 0x03;
    public static final int UTF8_STRING = 0x0C;
    public static final int GENERALIZED_TIME = 0x18;
    public static final int NULL = 0x05;

    /**
     * First octet of a constructed, context-specific tag numbered {@code n}
     * (0..30): {@code 0xA0 | n}. Used for {@code [n] EXPLICIT} fields --
     * {@code SignatureCheck.certificates} and {@code ObjectStoreIntegrityCheck}'s
     * {@code [0] SignatureCheck} arm are both {@code [0] EXPLICIT}.
     *
     * @throws IllegalArgumentException if {@code n} is outside 0..30 (31
     *         is the high-tag-number form, which none of this codec's
     *         structures use).
     */
    static int explicitTag(int n)
    {
        if (n < 0 || n > 30)
        {
            throw new IllegalArgumentException("tag number out of range: " + n);
        }
        return 0xA0 | n;
    }

    /**
     * First octet of a primitive, context-specific tag numbered {@code n}
     * (0..30): {@code 0x80 | n}. Used for {@code [n] IMPLICIT} fields --
     * {@code PbkdKeyData}'s {@code salt}/{@code iterationCount}/{@code encoded}
     * fields are all {@code [n] IMPLICIT}. Unlike EXPLICIT, an IMPLICIT tag
     * replaces the underlying type's own tag rather than wrapping it, so the
     * content octets are exactly what the underlying type (OCTET STRING,
     * INTEGER) would encode -- only the tag byte differs.
     *
     * @throws IllegalArgumentException if {@code n} is outside 0..30, per
     *         {@link #explicitTag}.
     */
    static int implicitTag(int n)
    {
        if (n < 0 || n > 30)
        {
            throw new IllegalArgumentException("tag number out of range: " + n);
        }
        return 0x80 | n;
    }

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
        return tlv(INTEGER, integerContent(v));
    }

    /** A small non-negative INTEGER TLV. */
    public static byte[] integer(int v)
    {
        return integer(BigInteger.valueOf(v));
    }

    /**
     * An INTEGER's content octets alone -- the minimal two's-complement form
     * DER wants, including the leading 0x00 when the top bit would be set.
     * Shared by {@link #integer(BigInteger)} and {@link #implicitInteger},
     * whose tag differs but whose content encoding does not.
     */
    private static byte[] integerContent(BigInteger v)
    {
        return v.toByteArray();
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
     * Ceiling on an OCTET STRING's content octets, and the JCA property that
     * overrides it.
     *
     * <p>This is the TIER-1 backstop of a two-tier model: a ceiling here
     * applies even when a call site declares nothing, and a call site may
     * tighten further for its own field. The same shape already exists in this
     * codebase one layer up — {@code DSAKeyPairGenerator.MAX_P_BITS} (3072)
     * bounds GENERATION while {@code DSAKeyFactorySpi.MAX_COMPONENT_BITS}
     * (16384) bounds ACCEPTANCE, deliberately looser.
     *
     * <p>64 KiB is generous against every octet string the provider actually
     * serves — the largest legitimate one is a 16-byte IV — while refusing the
     * shape that motivated the bound: an 8 MiB nonce, with the bytes genuinely
     * present, was accepted by the IV and GCM codecs and then held in SPI
     * state and copied again on every {@code getIV()} / {@code getEncoded()}.
     * The figure matches the 64 KiB presize cap {@code
     * ExposedByteArrayOutputStream} already applies for the same reason.
     *
     * <p>Overridable because an octet-string field is not bounded by any spec
     * in general. Values below 1 are ignored and the default used.
     */
    public static final int DEFAULT_MAX_OCTET_STRING_BYTES = 64 * 1024;

    /** JCA/system property overriding {@link #DEFAULT_MAX_OCTET_STRING_BYTES}. */
    public static final String MAX_OCTET_STRING_PROPERTY =
            "org.openssl.jostle.asn1.max_octet_string_bytes";

    /**
     * Ceiling on an INTEGER's content octets, and the JCA property that
     * overrides it.
     *
     * <p>2048 octets is 16384 bits, which is exactly the acceptance ceiling
     * the provider already applies to a big-integer key component —
     * {@code DSAKeyFactorySpi.MAX_COMPONENT_BITS} and
     * {@code RSAKeyPairGenerator.MAX_KEY_SIZE_BITS} are both 16384. Reusing it
     * keeps one number rather than inventing a second, and a DH or DSA p
     * beyond it is refused before it becomes a BigInteger.
     *
     * <p>Overridable because a modulus size is open-ended by spec. Values
     * below 1 are ignored and the default used.
     */
    public static final int DEFAULT_MAX_INTEGER_BYTES = 2048;

    /** JCA/system property overriding {@link #DEFAULT_MAX_INTEGER_BYTES}. */
    public static final String MAX_INTEGER_PROPERTY =
            "org.openssl.jostle.asn1.max_integer_bytes";

    /**
     * The configured ceiling for {@code tag}, or -1 when the type carries no
     * ceiling. Read per call so the property is settable at runtime, which is
     * the BouncyCastle {@code Properties} convention; parameter decoding is
     * not a hot path.
     */
    private static int typeCeiling(int tag)
    {
        switch (tag)
        {
        case OCTET_STRING:
        case BIT_STRING:
        case UTF8_STRING:
            // BIT STRING and UTF8String share the octet-string ceiling;
            // BCFKS's widest uses are far under it.
            return usableOr(MAX_OCTET_STRING_PROPERTY, DEFAULT_MAX_OCTET_STRING_BYTES);
        case INTEGER:
            return usableOr(MAX_INTEGER_PROPERTY, DEFAULT_MAX_INTEGER_BYTES);
        case OBJECT_IDENTIFIER:
            // Spec-bounded, so a hard constant: configurability is for
            // open-endedness, not for permitting a spec violation.
            return MAX_OID_CONTENT_BYTES;
        default:
            return -1;
        }
    }

    /**
     * The configured value when it is usable, otherwise {@code fallback}.
     *
     * <p>{@code Properties.asInteger} throws {@link NumberFormatException} on a
     * non-numeric value, and an operator typo in a configuration property must
     * not become an exception out of every parameter decode. A value of zero or
     * less is equally unusable — it would refuse every field.
     *
     * <p>The trade-off is stated rather than hidden: falling back is
     * fail-OPEN relative to an operator who meant to TIGHTEN the ceiling, since
     * they get the (larger) default instead of their intended bound. That is
     * accepted because the default is itself a safe bound, whereas the
     * alternative breaks decoding outright.
     */
    private static int usableOr(String propertyName, int fallback)
    {
        try
        {
            int configured = Properties.asInteger(propertyName, fallback);
            return configured > 0 ? configured : fallback;
        }
        catch (NumberFormatException e)
        {
            return fallback;
        }
    }

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

    /**
     * A byte-aligned BIT STRING: one leading zero octet (unused-bit count),
     * then the content. Every BIT STRING this codec writes — a signature
     * value — is a whole number of bytes, so no other unused-bit count is
     * needed and none is accepted on read.
     */
    public static byte[] bitString(byte[] content)
    {
        byte[] withUnusedBits = new byte[content.length + 1];
        withUnusedBits[0] = 0;
        System.arraycopy(content, 0, withUnusedBits, 1, content.length);
        return tlv(BIT_STRING, withUnusedBits);
    }

    /** A UTF8String TLV, encoded per {@link StandardCharsets#UTF_8}. */
    public static byte[] utf8String(String s)
    {
        return tlv(UTF8_STRING, s.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * The NULL TLV (X.690 8.8): a zero-length content octet. Used for the
     * explicit {@code parameters} field HMAC {@code AlgorithmIdentifier}s
     * conventionally carry, rather than omitting the field.
     */
    public static byte[] nullValue()
    {
        return tlv(NULL, new byte[0]);
    }

    /**
     * A GeneralizedTime TLV in DER canonical form: {@code YYYYMMDDHHMMSSZ},
     * UTC, no fractional seconds (X.690 11.7). Matches the form BouncyCastle
     * writes (r1rv86,
     * core/src/main/java/org/bouncycastle/asn1/ASN1GeneralizedTime.java:141-148,
     * {@code new SimpleDateFormat("yyyyMMddHHmmss'Z'")} under a fixed
     * {@code SimpleTimeZone(0, "Z")}).
     *
     * <p>The formatter's {@code Locale} is forced to {@code Locale.ENGLISH}
     * rather than left at the JVM default, for the same reason BouncyCastle's
     * own (Date, Locale) overload documents: a non-Gregorian default calendar
     * (Thai Buddhist, Japanese Imperial) would format the wrong year.
     */
    public static byte[] generalizedTime(Date d)
    {
        SimpleDateFormat fmt =
                new SimpleDateFormat("yyyyMMddHHmmss'Z'", Locale.ENGLISH);
        fmt.setTimeZone(TimeZone.getTimeZone("UTC"));
        return tlv(GENERALIZED_TIME, fmt.format(d).getBytes(StandardCharsets.US_ASCII));
    }

    /**
     * Wrap one complete inner TLV as {@code [tagNo] EXPLICIT}: a constructed
     * context-specific tag whose content is the inner encoding verbatim.
     */
    public static byte[] explicit(int tagNo, byte[] innerTlv)
    {
        return tlv(explicitTag(tagNo), innerTlv);
    }

    /**
     * An OCTET STRING's value as {@code [tagNo] IMPLICIT}: the tag replaces
     * OCTET STRING's own, the content octets are unchanged.
     */
    public static byte[] implicitOctetString(int tagNo, byte[] v)
    {
        return tlv(implicitTag(tagNo), v);
    }

    /** An INTEGER's value as {@code [tagNo] IMPLICIT}. */
    public static byte[] implicitInteger(int tagNo, int v)
    {
        return tlv(implicitTag(tagNo), integerContent(BigInteger.valueOf(v)));
    }

    /**
     * {@code AlgorithmIdentifier ::= SEQUENCE { algorithm OBJECT IDENTIFIER,
     * parameters ANY DEFINED BY algorithm OPTIONAL }}. {@code params} is the
     * complete encoded parameters TLV (opaque to this codec — interpreting
     * it is the specific algorithm's job), or {@code null} to omit the field.
     */
    public static byte[] algorithmIdentifier(String oid, byte[] params)
    {
        byte[] oidTlv = objectIdentifier(oid);
        return params == null ? sequence(oidTlv) : sequence(oidTlv, params);
    }

    /**
     * RFC 5084 line 485 (s3.2): {@code CCMParameters ::= SEQUENCE { aes-nonce OCTET
     * STRING (SIZE(7..13)), aes-ICVlen AES-CCM-ICVlen DEFAULT 12 }}. Per DER,
     * the ICV length is omitted when it is the default. Range checks are the
     * caller's — this is a codec, not a validator — matching every other
     * writer in this class.
     */
    public static byte[] ccmParameters(byte[] nonce, int icvBytes)
    {
        byte[] nonceTlv = octetString(nonce);
        return icvBytes == 12 ? sequence(nonceTlv) : sequence(nonceTlv, integer(icvBytes));
    }

    /**
     * RFC 5958 s2 (line 267): {@code EncryptedPrivateKeyInfo ::= SEQUENCE {
     * encryptionAlgorithm AlgorithmIdentifier, encryptedData OCTET STRING }}.
     * {@code algorithmIdentifierTlv} is a complete {@link #algorithmIdentifier}
     * encoding.
     */
    public static byte[] encryptedPrivateKeyInfo(byte[] algorithmIdentifierTlv, byte[] encryptedData)
    {
        return sequence(algorithmIdentifierTlv, octetString(encryptedData));
    }

    /**
     * RFC 8018 A.4 (line 1423): {@code PBES2-params ::= SEQUENCE {
     * keyDerivationFunc AlgorithmIdentifier, encryptionScheme
     * AlgorithmIdentifier }}. Both arguments are complete
     * {@link #algorithmIdentifier} encodings.
     */
    public static byte[] pbes2Params(byte[] keyDerivationFuncTlv, byte[] encryptionSchemeTlv)
    {
        return sequence(keyDerivationFuncTlv, encryptionSchemeTlv);
    }

    /**
     * RFC 8018 A.2 (line 1272): {@code PBKDF2-params ::= SEQUENCE { salt
     * OCTET STRING, iterationCount INTEGER, keyLength INTEGER OPTIONAL, prf
     * AlgorithmIdentifier DEFAULT algid-hmacWithSHA1 }}. This codec writes
     * only the {@code specified OCTET STRING} salt CHOICE — the
     * {@code otherSource AlgorithmIdentifier} CHOICE has no BCFKS writer and
     * is out of scope. {@code prfTlv} is a complete
     * {@link #algorithmIdentifier} encoding, or {@code null} to omit it (the
     * DEFAULT then applies on read, per the caller's own convention — this
     * codec does not interpret DEFAULT).
     *
     * @param keyLength content octets of the derived key, or {@code null} to
     *                  omit the OPTIONAL field.
     */
    public static byte[] pbkdf2Params(byte[] salt, int iterationCount, Integer keyLength, byte[] prfTlv)
    {
        List<byte[]> parts = new ArrayList<byte[]>();
        parts.add(octetString(salt));
        parts.add(integer(iterationCount));
        if (keyLength != null)
        {
            parts.add(integer(keyLength.intValue()));
        }
        if (prfTlv != null)
        {
            parts.add(prfTlv);
        }
        return sequence(parts.toArray(new byte[0][]));
    }

    /**
     * RFC 7914 s7 (line 416): {@code scrypt-params ::= SEQUENCE { salt OCTET
     * STRING, costParameter INTEGER (1..MAX), blockSize INTEGER (1..MAX),
     * parallelizationParameter INTEGER (1..MAX), keyLength INTEGER (1..MAX)
     * OPTIONAL }}.
     *
     * @param keyLength content octets of the derived key, or {@code null} to
     *                  omit the OPTIONAL field.
     */
    public static byte[] scryptParams(byte[] salt, long costParameter, int blockSize,
                                       int parallelizationParameter, Integer keyLength)
    {
        List<byte[]> parts = new ArrayList<byte[]>();
        parts.add(octetString(salt));
        parts.add(integer(BigInteger.valueOf(costParameter)));
        parts.add(integer(blockSize));
        parts.add(integer(parallelizationParameter));
        if (keyLength != null)
        {
            parts.add(integer(keyLength.intValue()));
        }
        return sequence(parts.toArray(new byte[0][]));
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
            // Tier-1 ceiling: applies even where the call site declares
            // nothing, so no decode path can forget to bound its field.
            int ceiling = typeCeiling(tag);
            if (ceiling >= 0 && len > ceiling)
            {
                throw new IOException(what + " exceeds the " + ceiling
                        + "-byte ceiling for this type (" + len + " bytes)");
            }
            Reader content = new Reader(buf, pos, len);
            pos += len;
            return content;
        }

        /**
         * Read one TLV of the expected tag and return its COMPLETE encoding,
         * tag and length octets included.
         *
         * <p>{@link #readTLV} hands back the CONTENT, which is what a field
         * decoder wants. A container whose members are themselves whole
         * encodings — the certificates in a PkiPath or a PKCS#7 bag — needs the
         * bytes back exactly as they lay on the wire, so that re-parsing them
         * cannot depend on this class having understood them.
         */
        public byte[] readEncodedTLV(int expectedTag, String what) throws IOException
        {
            int start = pos;
            readTLV(expectedTag, what);
            byte[] out = new byte[pos - start];
            System.arraycopy(buf, start, out, 0, out.length);
            return out;
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
            return parseIntegerContent(readTLV(INTEGER, what).remaining(), what);
        }

        /**
         * The shared validation {@link #readInteger} and {@link
         * #readImplicitInteger} both need -- non-negative, minimally
         * encoded -- applied to already-extracted content octets, since an
         * IMPLICIT INTEGER's content encoding is identical to a plain one's;
         * only the tag differs, and the caller has already checked that.
         */
        private static BigInteger parseIntegerContent(byte[] content, String what) throws IOException
        {
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

        /**
         * An OCTET STRING's content read via {@code [tagNo] IMPLICIT} instead
         * of its own tag.
         */
        public byte[] readImplicitOctetString(int tagNo, String what) throws IOException
        {
            return readTLV(implicitTag(tagNo), what).remaining();
        }

        /**
         * An INTEGER read via {@code [tagNo] IMPLICIT} instead of its own
         * tag, bounded to fit a non-negative {@code int} exactly as {@link
         * #readSmallInteger} bounds a plain one.
         */
        public int readImplicitSmallInteger(int tagNo, String what) throws IOException
        {
            BigInteger v = parseIntegerContent(readTLV(implicitTag(tagNo), what).remaining(), what);
            if (v.bitLength() > 31)
            {
                throw new IOException("INTEGER out of range in " + what);
            }
            return v.intValue();
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

        /**
         * A byte-aligned BIT STRING's content, with the leading unused-bit
         * count validated as zero. Every BIT STRING BCFKS reads (a signature
         * value) is a whole number of bytes; anything else is refused rather
         * than silently masked, since a nonzero unused-bit count on a value
         * this codec treats as opaque bytes would silently drop bits.
         */
        public byte[] readBitString(String what) throws IOException
        {
            byte[] raw = readTLV(BIT_STRING, what).remaining();
            if (raw.length == 0)
            {
                throw new IOException("empty BIT STRING in " + what);
            }
            if (raw[0] != 0)
            {
                throw new IOException("non-byte-aligned BIT STRING in " + what);
            }
            byte[] content = new byte[raw.length - 1];
            System.arraycopy(raw, 1, content, 0, content.length);
            return content;
        }

        /** A UTF8String's content, decoded as UTF-8. */
        public String readUTF8String(String what) throws IOException
        {
            byte[] content = readTLV(UTF8_STRING, what).remaining();
            return new String(content, StandardCharsets.UTF_8);
        }

        /**
         * A GeneralizedTime in DER canonical form: exactly
         * {@code YYYYMMDDHHMMSSZ} (15 octets, no fractional seconds, UTC).
         * Any other form — a local-time suffix, a UTC offset, fractional
         * seconds, a non-canonical length — is refused rather than guessed
         * at; this codec only needs to read what {@link #generalizedTime}
         * (and BouncyCastle, per its javadoc) write.
         */
        public Date readGeneralizedTime(String what) throws IOException
        {
            byte[] content = readTLV(GENERALIZED_TIME, what).remaining();
            if (content.length != 15)
            {
                throw new IOException(
                        "GeneralizedTime must be exactly 15 octets (YYYYMMDDHHMMSSZ) in " + what);
            }
            String text = new String(content, StandardCharsets.US_ASCII);
            for (int i = 0; i < 14; i++)
            {
                char c = text.charAt(i);
                if (c < '0' || c > '9')
                {
                    throw new IOException("malformed GeneralizedTime in " + what);
                }
            }
            if (text.charAt(14) != 'Z')
            {
                throw new IOException("GeneralizedTime must end with Z in " + what);
            }
            SimpleDateFormat fmt =
                    new SimpleDateFormat("yyyyMMddHHmmss'Z'", Locale.ENGLISH);
            fmt.setTimeZone(TimeZone.getTimeZone("UTC"));
            fmt.setLenient(false);
            try
            {
                return fmt.parse(text);
            }
            catch (ParseException e)
            {
                throw new IOException("malformed GeneralizedTime in " + what, e);
            }
        }

        /**
         * Read {@code [tagNo] EXPLICIT}: a constructed context-specific tag,
         * returning a Reader over its one inner TLV.
         */
        public Reader readExplicit(int tagNo, String what) throws IOException
        {
            return readTLV(explicitTag(tagNo), what);
        }

        /**
         * {@code AlgorithmIdentifier ::= SEQUENCE { algorithm OBJECT
         * IDENTIFIER, parameters ANY DEFINED BY algorithm OPTIONAL }}. The
         * parameters field, when present, is captured as its complete raw
         * TLV — this codec does not know how to interpret every algorithm's
         * parameters, so it hands the caller the bytes to decode themselves.
         */
        public AlgorithmIdentifier readAlgorithmIdentifier(String what) throws IOException
        {
            Reader seq = readTLV(SEQUENCE, what);
            String oid = seq.readObjectIdentifier(what + " algorithm");
            byte[] params = null;
            if (!seq.atEnd())
            {
                int tag = seq.peekTag();
                params = seq.readEncodedTLV(tag, what + " parameters");
            }
            seq.requireEnd("trailing bytes in " + what);
            return new AlgorithmIdentifier(oid, params);
        }

        /**
         * RFC 5084 line 485 (s3.2): {@code CCMParameters}. The nonce length (7..13) and
         * ICV length (4,6,8,10,12,14,16) are NOT range-checked here — those
         * are the CCM cipher's own bounds, and this codec is a container
         * reader, not a validator, matching {@link #readAlgorithmIdentifier}.
         */
        public CcmParameters readCcmParameters(String what) throws IOException
        {
            Reader seq = readTLV(SEQUENCE, what);
            byte[] nonce = seq.readTLV(OCTET_STRING, what + " aes-nonce").remaining();
            int icvBytes = 12;
            if (!seq.atEnd())
            {
                icvBytes = seq.readSmallInteger(what + " aes-ICVlen");
            }
            seq.requireEnd("trailing bytes in " + what);
            return new CcmParameters(nonce, icvBytes);
        }

        /** RFC 5958 s2 (line 267): {@code EncryptedPrivateKeyInfo}. */
        public EncryptedPrivateKeyInfo readEncryptedPrivateKeyInfo(String what) throws IOException
        {
            Reader seq = readTLV(SEQUENCE, what);
            AlgorithmIdentifier algId = seq.readAlgorithmIdentifier(what + " encryptionAlgorithm");
            byte[] encryptedData = seq.readTLV(OCTET_STRING, what + " encryptedData").remaining();
            seq.requireEnd("trailing bytes in " + what);
            return new EncryptedPrivateKeyInfo(algId, encryptedData);
        }

        /** RFC 8018 A.4 (line 1423): {@code PBES2-params}. */
        public Pbes2Params readPbes2Params(String what) throws IOException
        {
            Reader seq = readTLV(SEQUENCE, what);
            AlgorithmIdentifier kdf = seq.readAlgorithmIdentifier(what + " keyDerivationFunc");
            AlgorithmIdentifier enc = seq.readAlgorithmIdentifier(what + " encryptionScheme");
            seq.requireEnd("trailing bytes in " + what);
            return new Pbes2Params(kdf, enc);
        }

        /**
         * RFC 8018 A.2 (line 1272): {@code PBKDF2-params}. Reads only the
         * {@code specified OCTET STRING} salt CHOICE, matching
         * {@link #pbkdf2Params} — the {@code otherSource AlgorithmIdentifier}
         * CHOICE has no writer and is refused (as a tag mismatch on the salt
         * field) rather than silently accepted.
         */
        public Pbkdf2Params readPbkdf2Params(String what) throws IOException
        {
            Reader seq = readTLV(SEQUENCE, what);
            byte[] salt = seq.readTLV(OCTET_STRING, what + " salt").remaining();
            int iterationCount = seq.readSmallInteger(what + " iterationCount");
            Integer keyLength = null;
            AlgorithmIdentifier prf = null;
            if (!seq.atEnd() && seq.peekTag() == INTEGER)
            {
                keyLength = Integer.valueOf(seq.readSmallInteger(what + " keyLength"));
            }
            if (!seq.atEnd())
            {
                prf = seq.readAlgorithmIdentifier(what + " prf");
            }
            seq.requireEnd("trailing bytes in " + what);
            return new Pbkdf2Params(salt, iterationCount, keyLength, prf);
        }

        /** RFC 7914 s7 (line 416): {@code scrypt-params}. */
        public ScryptParams readScryptParams(String what) throws IOException
        {
            Reader seq = readTLV(SEQUENCE, what);
            byte[] salt = seq.readTLV(OCTET_STRING, what + " salt").remaining();
            BigInteger costBig = seq.readInteger(what + " costParameter");
            long costParameter;
            try
            {
                costParameter = costBig.longValueExact();
            }
            catch (ArithmeticException e)
            {
                throw new IOException("costParameter out of range in " + what, e);
            }
            int blockSize = seq.readSmallInteger(what + " blockSize");
            int parallelizationParameter = seq.readSmallInteger(what + " parallelizationParameter");
            Integer keyLength = null;
            if (!seq.atEnd())
            {
                keyLength = Integer.valueOf(seq.readSmallInteger(what + " keyLength"));
            }
            seq.requireEnd("trailing bytes in " + what);
            return new ScryptParams(salt, costParameter, blockSize, parallelizationParameter, keyLength);
        }
    }

    /** {@code AlgorithmIdentifier}: an OID plus its opaque parameters TLV (or none). */
    public static final class AlgorithmIdentifier
    {
        public final String oid;
        /** The complete parameters TLV, or {@code null} when the field was absent. */
        public final byte[] parameters;

        AlgorithmIdentifier(String oid, byte[] parameters)
        {
            this.oid = oid;
            this.parameters = parameters;
        }
    }

    /** RFC 5084 {@code CCMParameters}. */
    public static final class CcmParameters
    {
        public final byte[] nonce;
        public final int icvBytes;

        CcmParameters(byte[] nonce, int icvBytes)
        {
            this.nonce = nonce;
            this.icvBytes = icvBytes;
        }
    }

    /** RFC 5958 {@code EncryptedPrivateKeyInfo}. */
    public static final class EncryptedPrivateKeyInfo
    {
        public final AlgorithmIdentifier encryptionAlgorithm;
        public final byte[] encryptedData;

        EncryptedPrivateKeyInfo(AlgorithmIdentifier encryptionAlgorithm, byte[] encryptedData)
        {
            this.encryptionAlgorithm = encryptionAlgorithm;
            this.encryptedData = encryptedData;
        }
    }

    /** RFC 8018 A.4 {@code PBES2-params}. */
    public static final class Pbes2Params
    {
        public final AlgorithmIdentifier keyDerivationFunc;
        public final AlgorithmIdentifier encryptionScheme;

        Pbes2Params(AlgorithmIdentifier keyDerivationFunc, AlgorithmIdentifier encryptionScheme)
        {
            this.keyDerivationFunc = keyDerivationFunc;
            this.encryptionScheme = encryptionScheme;
        }
    }

    /** RFC 8018 A.2 {@code PBKDF2-params} (specified-salt CHOICE only). */
    public static final class Pbkdf2Params
    {
        public final byte[] salt;
        public final int iterationCount;
        /** {@code null} when the OPTIONAL field was absent. */
        public final Integer keyLength;
        /** {@code null} when absent (the DEFAULT hmacWithSHA1 then applies). */
        public final AlgorithmIdentifier prf;

        Pbkdf2Params(byte[] salt, int iterationCount, Integer keyLength, AlgorithmIdentifier prf)
        {
            this.salt = salt;
            this.iterationCount = iterationCount;
            this.keyLength = keyLength;
            this.prf = prf;
        }
    }

    /** RFC 7914 s7 {@code scrypt-params}. */
    public static final class ScryptParams
    {
        public final byte[] salt;
        public final long costParameter;
        public final int blockSize;
        public final int parallelizationParameter;
        /** {@code null} when the OPTIONAL field was absent. */
        public final Integer keyLength;

        ScryptParams(byte[] salt, long costParameter, int blockSize,
                     int parallelizationParameter, Integer keyLength)
        {
            this.salt = salt;
            this.costParameter = costParameter;
            this.blockSize = blockSize;
            this.parallelizationParameter = parallelizationParameter;
            this.keyLength = keyLength;
        }
    }
}
