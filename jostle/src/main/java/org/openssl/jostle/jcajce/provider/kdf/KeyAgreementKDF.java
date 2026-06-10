/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider.kdf;

import org.openssl.jostle.jcajce.spec.UserKeyingMaterialSpec;
import org.openssl.jostle.util.Arrays;

import java.io.ByteArrayOutputStream;
import java.lang.reflect.Method;
import java.security.InvalidAlgorithmParameterException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;

/**
 * The two single-pass key-derivation functions CMS key agreement layers on
 * top of a raw Diffie-Hellman / ECDH shared secret, plus the wrap-algorithm
 * key-size table. Pure Java: a {@link MessageDigest} over the shared secret
 * and some framing — no native dependency.
 *
 * <ul>
 *   <li>{@link #x942} — ANSI X9.42 / RFC 2631 KDF (the {@code DHwithRFC2631KDF}
 *       used by {@code id-alg-ESDH} / {@code id-alg-SSDH}). Byte-for-byte
 *       equivalent to BouncyCastle's
 *       {@code org.bouncycastle.crypto.agreement.kdf.DHKEKGenerator}: the SPI
 *       builds the {@code OtherInfo} structure (wrap OID + counter + key length
 *       + optional UKM) and hashes {@code ZZ || DER(OtherInfo)} once per
 *       output block.</li>
 *   <li>{@link #x963} — ANSI X9.63 KDF (= ISO-18033 KDF2), the
 *       {@code dhSinglePass-stdDH-sha*kdf-scheme} EC schemes. Byte-for-byte
 *       equivalent to BouncyCastle's {@code KDF2BytesGenerator}: hashes
 *       {@code ZZ || counter || sharedInfo}. The {@code sharedInfo} is passed
 *       through verbatim — for CMS it is the {@code ECC-CMS-SharedInfo} that
 *       the CMS layer pre-builds and hands over as the UKM.</li>
 * </ul>
 *
 * <p>Both KDFs number their counter from 1 (big-endian, 4 bytes) and take the
 * leftmost {@code keyLenBytes} of the concatenated digest blocks.
 */
public final class KeyAgreementKDF
{
    private KeyAgreementKDF()
    {
    }

    /**
     * ANSI X9.42 / RFC 2631 KDF. {@code wrapOid} is the key-wrap algorithm
     * OID embedded in {@code KeySpecificInfo}; {@code keyLenBytes} is the
     * requested KEK length (also encoded, in bits, into {@code suppPubInfo});
     * {@code ukm} is the optional {@code partyAInfo} (null when absent).
     */
    public static byte[] x942(String digest, byte[] zz, String wrapOid, int keyLenBytes, byte[] ukm)
            throws NoSuchAlgorithmException
    {
        MessageDigest md = MessageDigest.getInstance(digest);
        int digLen = md.getDigestLength();
        int blocks = (keyLenBytes + digLen - 1) / digLen;

        byte[] out = new byte[blocks * digLen];
        int counter = 1;
        for (int i = 0; i < blocks; i++)
        {
            md.update(zz, 0, zz.length);
            byte[] otherInfo = x942OtherInfo(wrapOid, counter, keyLenBytes * 8, ukm);
            md.update(otherInfo, 0, otherInfo.length);
            byte[] dig = md.digest();
            System.arraycopy(dig, 0, out, i * digLen, digLen);
            Arrays.fill(dig, (byte) 0);
            counter++;
        }
        return truncateAndScrub(out, keyLenBytes);
    }

    /**
     * ANSI X9.63 KDF (ISO-18033 KDF2). {@code sharedInfo} may be null.
     */
    public static byte[] x963(String digest, byte[] zz, int keyLenBytes, byte[] sharedInfo)
            throws NoSuchAlgorithmException
    {
        MessageDigest md = MessageDigest.getInstance(digest);
        int digLen = md.getDigestLength();
        int blocks = (keyLenBytes + digLen - 1) / digLen;

        byte[] out = new byte[blocks * digLen];
        int counter = 1;
        for (int i = 0; i < blocks; i++)
        {
            md.update(zz, 0, zz.length);
            md.update(intToBytes(counter), 0, 4);
            if (sharedInfo != null)
            {
                md.update(sharedInfo, 0, sharedInfo.length);
            }
            byte[] dig = md.digest();
            System.arraycopy(dig, 0, out, i * digLen, digLen);
            Arrays.fill(dig, (byte) 0);
            counter++;
        }
        return truncateAndScrub(out, keyLenBytes);
    }

    /**
     * Return the leftmost {@code keyLenBytes} of {@code derived}, zeroing the
     * working buffer when a truncated copy is taken so no KEK material lingers
     * on the heap beyond the returned array (which the SPI hands to the
     * {@code SecretKeySpec}).
     */
    private static byte[] truncateAndScrub(byte[] derived, int keyLenBytes)
    {
        if (derived.length == keyLenBytes)
        {
            return derived;
        }
        byte[] kek = Arrays.copyOfRange(derived, 0, keyLenBytes);
        Arrays.fill(derived, (byte) 0);
        return kek;
    }

    /**
     * KEK length, in bytes, for a key-wrap algorithm named by OID (or, as a
     * convenience, by JCE name). Returns -1 when the algorithm is unknown —
     * callers raise {@code NoSuchAlgorithmException} so the failure surfaces
     * with the offending identifier, matching the JCE contract.
     */
    public static int wrapKeyLenBytes(String alg)
    {
        switch (alg)
        {
        // AES key wrap (NIST), plain and padded — 128 / 192 / 256.
        case "2.16.840.1.101.3.4.1.5":   // aes128-wrap
        case "2.16.840.1.101.3.4.1.8":   // aes128-wrap-pad
            return 16;
        case "2.16.840.1.101.3.4.1.25":  // aes192-wrap
        case "2.16.840.1.101.3.4.1.28":  // aes192-wrap-pad
            return 24;
        case "2.16.840.1.101.3.4.1.45":  // aes256-wrap
        case "2.16.840.1.101.3.4.1.48":  // aes256-wrap-pad
            return 32;
        // RFC 3217 / CMS 3-key Triple-DES key wrap.
        case "1.2.840.113549.1.9.16.3.6":
            return 24;
        default:
            return -1;
        }
    }

    /**
     * The JCE key-algorithm name to stamp onto the derived {@code SecretKey}
     * so the subsequent key-wrap {@code Cipher} accepts it. Mirrors the wrap
     * cipher family the OID denotes. Returns null when unknown.
     */
    public static String wrapKeyAlgName(String alg)
    {
        switch (alg)
        {
        case "2.16.840.1.101.3.4.1.5":
        case "2.16.840.1.101.3.4.1.8":
        case "2.16.840.1.101.3.4.1.25":
        case "2.16.840.1.101.3.4.1.28":
        case "2.16.840.1.101.3.4.1.45":
        case "2.16.840.1.101.3.4.1.48":
            return "AES";
        case "1.2.840.113549.1.9.16.3.6":
            return "DESede";
        default:
            return null;
        }
    }

    /**
     * Extract the UKM bytes from the spec a key-agreement SPI was initialised
     * with. Accepts Jostle's {@link UserKeyingMaterialSpec}, BouncyCastle's
     * same-named spec (reflectively — the CMS layer passes it and we do not
     * compile against bcprov), and null (no UKM). Any other spec type is
     * rejected, which is also how MQV / hybrid specs surface as unsupported.
     */
    public static byte[] extractUkm(AlgorithmParameterSpec params)
            throws InvalidAlgorithmParameterException
    {
        if (params == null)
        {
            return null;
        }
        if (params instanceof UserKeyingMaterialSpec)
        {
            return ((UserKeyingMaterialSpec) params).getUserKeyingMaterial();
        }
        if ("org.bouncycastle.jcajce.spec.UserKeyingMaterialSpec".equals(params.getClass().getName()))
        {
            try
            {
                Method m = params.getClass().getMethod("getUserKeyingMaterial");
                return (byte[]) m.invoke(params);
            }
            catch (Exception e)
            {
                throw new InvalidAlgorithmParameterException(
                        "unable to read UserKeyingMaterialSpec", e);
            }
        }
        throw new InvalidAlgorithmParameterException(
                "unsupported parameter spec for key-agreement KDF: "
                        + params.getClass().getName());
    }

    // ----- X9.42 OtherInfo DER -----

    /**
     * DER-encode the RFC 2631 {@code OtherInfo}:
     * <pre>
     * OtherInfo ::= SEQUENCE {
     *     keyInfo      KeySpecificInfo,
     *     partyAInfo   [0] EXPLICIT OCTET STRING OPTIONAL,
     *     suppPubInfo  [2] EXPLICIT OCTET STRING }
     * KeySpecificInfo ::= SEQUENCE {
     *     algorithm    OBJECT IDENTIFIER,
     *     counter      OCTET STRING (SIZE (4)) }
     * </pre>
     */
    private static byte[] x942OtherInfo(String wrapOid, int counter, int keyBits, byte[] ukm)
    {
        byte[] keySpecificInfo = derSequence(concat(
                derOid(wrapOid),
                derOctetString(intToBytes(counter))));

        ByteArrayOutputStream body = new ByteArrayOutputStream();
        writeAll(body, keySpecificInfo);
        if (ukm != null)
        {
            // [0] EXPLICIT OCTET STRING
            writeAll(body, derExplicitTagged(0, derOctetString(ukm)));
        }
        // [2] EXPLICIT OCTET STRING (key length in bits, 4 bytes)
        writeAll(body, derExplicitTagged(2, derOctetString(intToBytes(keyBits))));

        return derSequence(body.toByteArray());
    }

    // ----- minimal DER writer -----

    private static byte[] derSequence(byte[] contents)
    {
        return tlv(0x30, contents);
    }

    private static byte[] derOctetString(byte[] contents)
    {
        return tlv(0x04, contents);
    }

    /** Context-specific, constructed (EXPLICIT) tag wrapping a single TLV. */
    private static byte[] derExplicitTagged(int tagNo, byte[] inner)
    {
        return tlv(0xA0 | tagNo, inner);
    }

    private static byte[] derOid(String oid)
    {
        return tlv(0x06, oidContents(oid));
    }

    /** Encode the contents octets of an OBJECT IDENTIFIER. */
    private static byte[] oidContents(String oid)
    {
        String[] parts = oid.split("\\.");
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        // First two arcs combine: 40*arc0 + arc1.
        long first = Long.parseLong(parts[0]) * 40 + Long.parseLong(parts[1]);
        writeBase128(out, first);
        for (int i = 2; i < parts.length; i++)
        {
            writeBase128(out, Long.parseLong(parts[i]));
        }
        return out.toByteArray();
    }

    private static void writeBase128(ByteArrayOutputStream out, long value)
    {
        // Big-endian base-128, high bit set on all but the final octet.
        int shift = 63;
        while (shift > 0 && (value >>> shift) == 0)
        {
            shift -= 7;
        }
        // Round down to a 7-bit boundary.
        shift -= shift % 7;
        for (; shift > 0; shift -= 7)
        {
            out.write((int) (((value >>> shift) & 0x7f) | 0x80));
        }
        out.write((int) (value & 0x7f));
    }

    private static byte[] tlv(int tag, byte[] contents)
    {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(tag);
        writeLength(out, contents.length);
        writeAll(out, contents);
        return out.toByteArray();
    }

    private static void writeLength(ByteArrayOutputStream out, int len)
    {
        if (len < 0x80)
        {
            out.write(len);
            return;
        }
        // Long form: minimal number of length octets, big-endian.
        int bytes = 0;
        for (int v = len; v != 0; v >>>= 8)
        {
            bytes++;
        }
        out.write(0x80 | bytes);
        for (int i = (bytes - 1) * 8; i >= 0; i -= 8)
        {
            out.write((len >>> i) & 0xff);
        }
    }

    private static byte[] intToBytes(int value)
    {
        return new byte[]{
                (byte) (value >>> 24),
                (byte) (value >>> 16),
                (byte) (value >>> 8),
                (byte) value
        };
    }

    private static byte[] concat(byte[] a, byte[] b)
    {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    private static void writeAll(ByteArrayOutputStream out, byte[] data)
    {
        out.write(data, 0, data.length);
    }
}
