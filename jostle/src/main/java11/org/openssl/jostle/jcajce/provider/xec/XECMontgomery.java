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

package org.openssl.jostle.jcajce.provider.xec;

import org.openssl.jostle.jcajce.spec.OSSLKeyType;

import java.math.BigInteger;

/**
 * Montgomery-key encoding helpers shared by the Java 11+ XDH classes.
 *
 * <h2>Why fixed prefixes rather than a DER parser</h2>
 *
 * <p>RFC 8410 gives X25519/X448 keys a fixed layout with NO algorithm
 * parameters: section 4 puts the raw public key directly in the
 * SubjectPublicKeyInfo BIT STRING, and section 7 defines
 * {@code CurvePrivateKey ::= OCTET STRING} nested inside the PrivateKeyInfo's
 * {@code privateKey} OCTET STRING. So every encoding of a given type has the
 * same leading octets and a fixed-length tail.
 *
 * <p>Measured on this provider, three generations per type, all stable and
 * exactly minimal in length — so OpenSSL emits no optional {@code publicKey}
 * and no {@code attributes}:
 *
 * <pre>
 *   X25519  SPKI   44 = 12 prefix + 32     PKCS#8  48 = 16 prefix + 32
 *   X448    SPKI   68 = 12 prefix + 56     PKCS#8  72 = 16 prefix + 56
 * </pre>
 *
 * <p>These bytes are OURS — produced by {@code ASN1Encoder} from a key we
 * hold — so a prefix mismatch is an invariant violation, not caller error, and
 * throws {@link IllegalStateException} naming what would have to have changed.
 * That is deliberately louder than a lenient parse: a silent mis-read would
 * hand back a wrong coordinate, which is the worst outcome available here.
 */
final class XECMontgomery
{
    private XECMontgomery()
    {
    }

    /** 2^255 - 19, the X25519 field prime (RFC 7748 section 4.1). */
    static final BigInteger X25519_P =
            BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(19));

    /** 2^448 - 2^224 - 1, the X448 field prime (RFC 7748 section 4.2). */
    static final BigInteger X448_P =
            BigInteger.ONE.shiftLeft(448)
                    .subtract(BigInteger.ONE.shiftLeft(224))
                    .subtract(BigInteger.ONE);

    private static final byte[] SPKI_PREFIX_X25519 = {
            (byte) 0x30, (byte) 0x2a, (byte) 0x30, (byte) 0x05, (byte) 0x06,
            (byte) 0x03, (byte) 0x2b, (byte) 0x65, (byte) 0x6e, (byte) 0x03,
            (byte) 0x21, (byte) 0x00};

    private static final byte[] SPKI_PREFIX_X448 = {
            (byte) 0x30, (byte) 0x42, (byte) 0x30, (byte) 0x05, (byte) 0x06,
            (byte) 0x03, (byte) 0x2b, (byte) 0x65, (byte) 0x6f, (byte) 0x03,
            (byte) 0x39, (byte) 0x00};

    private static final byte[] P8_PREFIX_X25519 = {
            (byte) 0x30, (byte) 0x2e, (byte) 0x02, (byte) 0x01, (byte) 0x00,
            (byte) 0x30, (byte) 0x05, (byte) 0x06, (byte) 0x03, (byte) 0x2b,
            (byte) 0x65, (byte) 0x6e, (byte) 0x04, (byte) 0x22, (byte) 0x04,
            (byte) 0x20};

    private static final byte[] P8_PREFIX_X448 = {
            (byte) 0x30, (byte) 0x46, (byte) 0x02, (byte) 0x01, (byte) 0x00,
            (byte) 0x30, (byte) 0x05, (byte) 0x06, (byte) 0x03, (byte) 0x2b,
            (byte) 0x65, (byte) 0x6f, (byte) 0x04, (byte) 0x3a, (byte) 0x04,
            (byte) 0x38};

    static boolean isX448(OSSLKeyType type)
    {
        return OSSLKeyType.X448 == type;
    }

    /** Raw key length in octets: 32 for X25519, 56 for X448 (RFC 7748 s5). */
    static int rawLength(OSSLKeyType type)
    {
        return isX448(type) ? 56 : 32;
    }

    static BigInteger fieldPrime(OSSLKeyType type)
    {
        return isX448(type) ? X448_P : X25519_P;
    }

    /** The raw tail of an SPKI we produced, with the prefix asserted. */
    static byte[] rawFromSpki(OSSLKeyType type, byte[] spki)
    {
        return tail(spki, isX448(type) ? SPKI_PREFIX_X448 : SPKI_PREFIX_X25519,
                rawLength(type), "SubjectPublicKeyInfo");
    }

    /**
     * The raw tail of a PKCS#8 we produced, with the prefix asserted.
     *
     * <p>The enclosing encoding is CLEARED before returning: it holds the
     * private scalar in the clear, and dropping it for the collector would
     * leave a second copy in the heap. The import side in
     * {@code XECKeyFactorySpi} wipes its constructed encoding for the same
     * reason; the export side must match it.
     */
    static byte[] rawFromPkcs8(OSSLKeyType type, byte[] p8)
    {
        try
        {
            return tail(p8, isX448(type) ? P8_PREFIX_X448 : P8_PREFIX_X25519,
                    rawLength(type), "PrivateKeyInfo");
        }
        finally
        {
            org.openssl.jostle.util.Arrays.clear(p8);
        }
    }

    private static byte[] tail(byte[] enc, byte[] prefix, int rawLen, String what)
    {
        if (enc == null || enc.length != prefix.length + rawLen)
        {
            throw new IllegalStateException(what + " length is "
                    + (enc == null ? "null" : String.valueOf(enc.length))
                    + ", expected " + (prefix.length + rawLen)
                    + "; OpenSSL would have to have started emitting an optional"
                    + " publicKey or attributes for this to happen");
        }
        for (int i = 0; i < prefix.length; i++)
        {
            if (enc[i] != prefix[i])
            {
                throw new IllegalStateException(what + " prefix differs at octet " + i
                        + "; the RFC 8410 algorithm identifier for this key type"
                        + " would have to have changed");
            }
        }
        byte[] raw = new byte[rawLen];
        System.arraycopy(enc, prefix.length, raw, 0, rawLen);
        return raw;
    }

    /**
     * Little-endian octets to unsigned {@link BigInteger}.
     *
     * <p>RFC 7748 section 5: "The u-coordinates ... are encoded as an array of
     * bytes, u, in little-endian order such that u[0] + 256*u[1] + ... +
     * 256^(n-1)*u[n-1] is congruent to the value modulo p".
     *
     * <p>The same section adds, for X25519 only: "When receiving such an array,
     * implementations of X25519 (but not X448) MUST mask the most significant
     * bit in the final byte." That mask is applied here, and NOT for X448.
     */
    static BigInteger uFromLittleEndian(OSSLKeyType type, byte[] raw)
    {
        byte[] le = raw.clone();
        if (!isX448(type))
        {
            le[le.length - 1] &= (byte) 0x7f;
        }
        byte[] be = new byte[le.length + 1];        // leading 0 keeps it unsigned
        for (int i = 0; i < le.length; i++)
        {
            be[be.length - 1 - i] = le[i];
        }
        // Reduced mod p, both types, so getU() agrees with the JDK's own
        // XDHPublicKeyImpl for the same stored bytes. A no-op for a canonical
        // key; it matters only for a non-canonical one, where an unreduced
        // value would differ from what the JDK reports.
        return new BigInteger(be).mod(fieldPrime(type));
    }

    /**
     * Unsigned {@link BigInteger} to little-endian octets of the type's length.
     *
     * <p>RFC 7748 section 5 requires a receiver to accept non-canonical values:
     * "Implementations MUST accept non-canonical values and process them as if
     * they had been reduced modulo the field prime." So the value is reduced
     * mod p here rather than refused — the opposite of the Edwards rule.
     */
    static byte[] uToLittleEndian(OSSLKeyType type, BigInteger u)
    {
        int len = rawLength(type);
        BigInteger reduced = u.mod(fieldPrime(type));   // mod, so a negative also lands in range
        byte[] be = reduced.toByteArray();
        byte[] le = new byte[len];
        int copy = Math.min(be.length, len);
        for (int i = 0; i < copy; i++)
        {
            le[i] = be[be.length - 1 - i];
        }
        return le;
    }
}
