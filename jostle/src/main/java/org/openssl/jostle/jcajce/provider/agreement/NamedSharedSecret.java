/**
 *   Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *   Licensed under the Apache License 2.0 (the "License"). You may not use
 *   this file except in compliance with the License.  You can obtain a copy
 *   in the file LICENSE in the source distribution or at
 *   https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 */

package org.openssl.jostle.jcajce.provider.agreement;

import org.openssl.jostle.util.Arrays;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

/**
 * Sizes a shared secret to the key algorithm a caller names.
 *
 * <p>{@code KeyAgreement.generateSecret(String)} asks for a key of a named
 * algorithm, not for the raw agreement output. A plain agreement that returns
 * the whole secret under that name hands back something that is not the key
 * the caller asked for: X448 would answer a 56-byte "AES-256" key and 2048-bit
 * DH a 256-byte one.
 *
 * <p>The table below is a TRANSCRIPTION of BouncyCastle's, so it decays the
 * moment BouncyCastle's moves. {@code NamedSecretSizingParityTest} measures
 * live BouncyCastle against every entry.
 *
 * <p>Entries are listed one by one and never as a range. The NIST AES arc
 * carries sizes at .1-.7, .21-.27 and .41-.47 only: wrap-pad (.8, .28, .48)
 * and GMAC (.9) are absent, so a range would size four identifiers that must
 * fall through to the whole secret.
 *
 * <p>NAMING AND SIZING ARE SEPARATE TABLES, and the naming one is far wider.
 * The whole NIST AES arc answers {@code AES} while only 21 of its identifiers
 * carry a size, and hmacWithSHA224 answers {@code HmacSHA224} while its four
 * siblings alone are sized. Folding the two would size everything either table
 * mentions. The two GOST KeyWrap identifiers run the other way: sized, but
 * named nowhere, so they answer with the identifier itself.
 *
 * <p>The AES name is a bare arc PREFIX, measured rather than assumed: it also
 * claims {@code 2.16.840.1.101.3.4.10} and {@code 2.16.840.1.101.3.4.1x},
 * which no dotted-arc test would match. Reproduced as measured.
 */
public final class NamedSharedSecret
{
    /** No size is known for the name; the caller keeps the whole secret. */
    private static final int UNKNOWN = -1;

    /** Sizes keyed by upper-case name. The lookup ignores case; the reply does not. */
    private static final Map<String, Integer> NAME_SIZES = new HashMap<String, Integer>();

    /** Sizes keyed by object identifier. */
    private static final Map<String, Integer> OID_SIZES = new HashMap<String, Integer>();

    /** Algorithm strings for the identifiers that have one. */
    private static final Map<String, String> OID_NAMES = new HashMap<String, String>();

    /** Every identifier under this arc answers "AES", sized or not. */
    private static final String AES_ARC = "2.16.840.1.101.3.4.1";

    static
    {
        NAME_SIZES.put("AES", 32);
        NAME_SIZES.put("DES", 8);
        NAME_SIZES.put("DESEDE", 24);
        NAME_SIZES.put("BLOWFISH", 16);
        NAME_SIZES.put("SM4", 16);

        // ---- sizes. Enumerated; .8, .9, .28, .29, .48 and .49 are absent.
        for (int i = 1; i <= 7; i++)
        {
            OID_SIZES.put(AES_ARC + "." + i, 16);
            OID_SIZES.put(AES_ARC + "." + (i + 20), 24);
            OID_SIZES.put(AES_ARC + "." + (i + 40), 32);
        }
        OID_SIZES.put("1.2.392.200011.61.1.1.3.2", 16);
        OID_SIZES.put("1.2.392.200011.61.1.1.3.3", 24);
        OID_SIZES.put("1.2.392.200011.61.1.1.3.4", 32);
        OID_SIZES.put("1.2.410.200004.7.1.1.1", 16);
        OID_SIZES.put("1.2.156.10197.1.104.2", 16);
        OID_SIZES.put("1.2.156.10197.1.104.8", 16);
        OID_SIZES.put("1.2.156.10197.1.104.9", 16);
        OID_SIZES.put("1.2.156.10197.1.104.11", 16);
        OID_SIZES.put("1.2.156.10197.1.104.12", 16);
        OID_SIZES.put("1.2.643.2.2.21", 32);
        OID_SIZES.put("1.2.643.2.2.13.0", 32);
        OID_SIZES.put("1.2.643.2.2.13.1", 32);
        OID_SIZES.put("1.2.840.113549.1.9.16.3.6", 24);
        OID_SIZES.put("1.2.840.113549.3.7", 24);
        OID_SIZES.put("1.3.14.3.2.7", 8);
        OID_SIZES.put("1.2.840.113549.2.7", 20);
        OID_SIZES.put("1.2.840.113549.2.9", 32);
        OID_SIZES.put("1.2.840.113549.2.10", 48);
        OID_SIZES.put("1.2.840.113549.2.11", 64);

        // ---- names. Wider than the sizes: an identifier here but not above
        // yields the WHOLE secret under this name.
        OID_NAMES.put("1.2.392.200011.61.1.1.1.2", "Camellia");
        OID_NAMES.put("1.2.392.200011.61.1.1.1.3", "Camellia");
        OID_NAMES.put("1.2.392.200011.61.1.1.1.4", "Camellia");
        OID_NAMES.put("1.2.392.200011.61.1.1.3.2", "Camellia");
        OID_NAMES.put("1.2.392.200011.61.1.1.3.3", "Camellia");
        OID_NAMES.put("1.2.392.200011.61.1.1.3.4", "Camellia");
        OID_NAMES.put("1.2.410.200004.7.1.1.1", "SEED");
        OID_NAMES.put("1.2.410.200004.1.4", "SEED");
        OID_NAMES.put("1.2.156.10197.1.104.2", "SM4");
        OID_NAMES.put("1.2.156.10197.1.104.8", "SM4");
        OID_NAMES.put("1.2.156.10197.1.104.9", "SM4");
        OID_NAMES.put("1.2.156.10197.1.104.11", "SM4");
        OID_NAMES.put("1.2.156.10197.1.104.12", "SM4");
        OID_NAMES.put("1.2.643.2.2.21", "GOST28147");
        OID_NAMES.put("1.2.840.113549.1.9.16.3.6", "DESede");
        OID_NAMES.put("1.2.840.113549.3.7", "DESede");
        OID_NAMES.put("1.3.14.3.2.7", "DES");
        OID_NAMES.put("1.2.840.113549.2.7", "HmacSHA1");
        OID_NAMES.put("1.2.840.113549.2.8", "HmacSHA224");
        OID_NAMES.put("1.2.840.113549.2.9", "HmacSHA256");
        OID_NAMES.put("1.2.840.113549.2.10", "HmacSHA384");
        OID_NAMES.put("1.2.840.113549.2.11", "HmacSHA512");
        // The two GOST KeyWraps are deliberately absent: sized, never named.
    }

    private NamedSharedSecret()
    {
    }

    /**
     * Build the key a caller named from a shared secret.
     *
     * <p>The secret is not cleared here — the caller owns it and scrubs it.
     *
     * @param secret    the raw agreement output
     * @param algorithm the name the caller passed to {@code generateSecret}
     * @throws NoSuchAlgorithmException if the name carries an unusable key
     *                                  size, or the secret is too short for it
     */
    public static SecretKey fromSharedSecret(byte[] secret, String algorithm)
            throws NoSuchAlgorithmException
    {
        String name = algorithm;
        int bytes;

        int open = algorithm.indexOf('[');
        if (open > 0)
        {
            int close = algorithm.indexOf(']', open);
            if (close < 0)
            {
                throw new NoSuchAlgorithmException(
                        "missing closing bracket on key size for algorithm: " + algorithm);
            }
            int bits;
            try
            {
                bits = Integer.parseInt(algorithm.substring(open + 1, close));
            }
            catch (NumberFormatException e)
            {
                throw new NoSuchAlgorithmException(
                        "unable to parse key size for algorithm: " + algorithm, e);
            }
            if (bits <= 0 || bits % 8 != 0)
            {
                throw new NoSuchAlgorithmException(
                        "key size must be a positive multiple of 8 for algorithm: " + algorithm);
            }
            name = algorithm.substring(0, open);
            bytes = bits / 8;
        }
        else
        {
            bytes = sizeOf(algorithm);
            name = nameOf(algorithm);
        }

        if (bytes == UNKNOWN)
        {
            // No size is known for this name, so the whole secret is the key.
            return new SecretKeySpec(secret, name);
        }
        if (bytes > secret.length)
        {
            throw new NoSuchAlgorithmException("unable to generate a " + (bytes * 8)
                    + " bit key for " + algorithm + ": the shared secret is only "
                    + (secret.length * 8) + " bits; use a key-agreement that applies a KDF");
        }

        byte[] key = Arrays.copyOfRange(secret, 0, bytes);
        try
        {
            // DES and DESede keys carry odd parity in their low bits. Keyed on
            // the RESOLVED algorithm string, which is why the identifiers that
            // answer "DESede" do not take it while the name "DESEDE" does.
            if ("DES".equals(name) || "DESEDE".equals(name))
            {
                setOddParity(key);
            }
            return new SecretKeySpec(key, name);
        }
        finally
        {
            Arrays.clear(key);
        }
    }

    /**
     * Leading zero bytes off, keeping at least one byte.
     *
     * <p>Returns the SAME array when there is nothing to trim, so a caller
     * that clears the original must first check it got a copy. Clearing
     * unconditionally wipes the key itself on the 255-in-256 of secrets that
     * need no trimming.
     *
     * <p>Keeps one byte where BouncyCastle returns an empty array for an
     * all-zero secret. Deliberate: unreachable for a valid agreement, and an
     * empty array is refused by SecretKeySpec anyway.
     */
    public static byte[] trimLeadingZeroes(byte[] secret)
    {
        int i = 0;
        while (i < secret.length - 1 && secret[i] == 0)
        {
            i++;
        }
        return i == 0 ? secret : Arrays.copyOfRange(secret, i, secret.length);
    }

    /** The algorithm a name resolves to, or the name itself. */
    private static String nameOf(String algorithm)
    {
        if (algorithm.startsWith(AES_ARC))
        {
            return "AES";
        }
        String named = OID_NAMES.get(algorithm);
        return named == null ? algorithm : named;
    }

    /** Size for a name, ignoring case, or {@link #UNKNOWN}. */
    private static int sizeOf(String algorithm)
    {
        Integer byName = NAME_SIZES.get(algorithm.toUpperCase(Locale.ROOT));
        if (byName != null)
        {
            return byName.intValue();
        }
        Integer byOid = OID_SIZES.get(algorithm);
        if (byOid != null)
        {
            return byOid.intValue();
        }
        return UNKNOWN;
    }

    /** Set each byte's low bit so the byte carries an odd number of set bits. */
    private static void setOddParity(byte[] key)
    {
        for (int i = 0; i < key.length; i++)
        {
            int b = key[i] & 0xFE;
            int set = 0;
            for (int m = b; m != 0; m >>= 1)
            {
                if ((m & 1) != 0)
                {
                    set++;
                }
            }
            key[i] = (byte) (set % 2 == 0 ? b | 1 : b);
        }
    }
}
