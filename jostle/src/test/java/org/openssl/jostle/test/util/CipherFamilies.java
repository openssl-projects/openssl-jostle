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

package org.openssl.jostle.test.util;

/**
 * Per-family inputs to {@link CipherSurfaceDriver}: the SPI class-name prefix
 * and the key length each registered name needs. Shared rather than per-class
 * because JSL and JSLFIPS need identical values and would otherwise drift.
 *
 * <p><b>The OID rules key on the LAST ARC, never a string prefix.</b> NIST's
 * {@code ….1.2} is AES-128-CBC while {@code ….1.22} is AES-192-CBC, so
 * {@code startsWith} picks the wrong width and the guard reports "invalid key
 * size" for a registration that is fine. Same shape in the other arcs.
 */
public final class CipherFamilies
{
    private CipherFamilies()
    {
    }

    public static final String AES_PREFIX = "org.openssl.jostle.jcajce.provider.blockcipher.AES";
    public static final String ARIA_PREFIX = "org.openssl.jostle.jcajce.provider.blockcipher.ARIA";
    public static final String CAMELLIA_PREFIX = "org.openssl.jostle.jcajce.provider.blockcipher.CAMELLIA";
    public static final String SM4_PREFIX = "org.openssl.jostle.jcajce.provider.blockcipher.SM4";
    public static final String CHACHA20_PREFIX = "org.openssl.jostle.jcajce.provider.blockcipher.ChaCha20";
    public static final String DESEDE_PREFIX = "org.openssl.jostle.jcajce.provider.blockcipher.DESede";

    // Every prefix above is the SPI class-name stem, so it discriminates the
    // family without naming a transformation. AES's AlgorithmParameters
    // ({GCM,CCM,CBC}AlgorithmParameters) are deliberately outside AES_PREFIX —
    // every caller filters types to {"Cipher"}.
    //
    // RSA and ML-KEM have no per-family class stem, so their prefix is the
    // package. That also pulls in Signature / KeyFactory / KeyPairGenerator,
    // which is why the service types passed to ProviderSurfaceGuard are
    // required and explicit.
    public static final String RSA_PREFIX = "org.openssl.jostle.jcajce.provider.rsa.";
    public static final String MLKEM_PREFIX = "org.openssl.jostle.jcajce.provider.mlkem.";
    public static final String MLDSA_PREFIX = "org.openssl.jostle.jcajce.provider.mldsa.";
    public static final String SLHDSA_PREFIX = "org.openssl.jostle.jcajce.provider.slhdsa.";
    public static final String DSA_PREFIX = "org.openssl.jostle.jcajce.provider.dsa.";
    public static final String EC_PREFIX = "org.openssl.jostle.jcajce.provider.ec.";
    public static final String ED_PREFIX = "org.openssl.jostle.jcajce.provider.ed.";
    public static final String DH_PREFIX = "org.openssl.jostle.jcajce.provider.dh.";
    public static final String XEC_PREFIX = "org.openssl.jostle.jcajce.provider.xec.";

    /**
     * NIST's AES arc: {@code 2.16.840.1.101.3.4.1.{1..9}} is AES-128,
     * {@code .{21..29}} AES-192, {@code .{41..49}} AES-256. XTS is the
     * exception among the names — its key is key1||key2, so the length alone
     * picks the cipher.
     */
    public static final CipherSurfaceDriver.KeyLength AES = new CipherSurfaceDriver.KeyLength()
    {
        public int bytesFor(String n)
        {
            if (n.contains("XTS"))
            {
                return 64;
            }
            if (n.startsWith("2.16.840.1.101.3.4.1."))
            {
                int arc = Integer.parseInt(n.substring("2.16.840.1.101.3.4.1.".length()));
                return arc < 20 ? 16 : arc < 40 ? 24 : 32;
            }
            return byWidthInName(n);
        }
    };

    /**
     * KISA's ARIA arc: {@code 1.2.410.200046.1.1.{1..5}} are the 128-bit
     * modes, {@code .{6..10}} the 192-bit ones, {@code .{11..15}} the 256-bit
     * ones.
     */
    public static final CipherSurfaceDriver.KeyLength ARIA = new CipherSurfaceDriver.KeyLength()
    {
        public int bytesFor(String n)
        {
            if (n.startsWith("1.2.410.200046.1.1."))
            {
                int arc = Integer.parseInt(n.substring("1.2.410.200046.1.1.".length()));
                return arc <= 5 ? 16 : arc <= 10 ? 24 : 32;
            }
            return byWidthInName(n);
        }
    };

    /** NTT's Camellia CBC arc: {@code .2} = 128, {@code .3} = 192, {@code .4} = 256. */
    public static final CipherSurfaceDriver.KeyLength CAMELLIA = new CipherSurfaceDriver.KeyLength()
    {
        public int bytesFor(String n)
        {
            if (n.startsWith("1.2.392.200011.61.1.1.1."))
            {
                int arc = Integer.parseInt(n.substring("1.2.392.200011.61.1.1.1.".length()));
                return arc == 2 ? 16 : arc == 3 ? 24 : 32;
            }
            return byWidthInName(n);
        }
    };

    /** SM4 is single-width: a 128-bit key, always. */
    public static final CipherSurfaceDriver.KeyLength SM4 = new CipherSurfaceDriver.KeyLength()
    {
        public int bytesFor(String n)
        {
            return 16;
        }
    };

    /** Both ChaCha20 registrations take a 256-bit key (RFC 8439). */
    public static final CipherSurfaceDriver.KeyLength CHACHA20 = new CipherSurfaceDriver.KeyLength()
    {
        public int bytesFor(String n)
        {
            return 32;
        }
    };

    /** Only the 3-key form exists; the module implements no DES-EDE. */
    public static final CipherSurfaceDriver.KeyLength DESEDE = new CipherSurfaceDriver.KeyLength()
    {
        public int bytesFor(String n)
        {
            return 24;
        }
    };

    /**
     * The SPI class ARIA, Camellia and SM4 share for key generation. It is
     * named here as a PREFIX in its own right because none of the three family
     * prefixes matches it, so a per-family guard cannot see those three
     * KeyGenerators at all — measured 2026-09-20, surface 0 for each while
     * {@code KeyGenerator.getInstance("ARIA", "JSL")} succeeds.
     */
    public static final String SYMMETRIC_KEYGEN_PREFIX =
            "org.openssl.jostle.jcajce.provider.blockcipher.SymmetricKeyGenerator";

    /** {@code AES}, the three per-width names, and the eighteen OID arcs. */
    public static final CipherSurfaceDriver.KeyGenLengths AES_KEYGEN =
            new CipherSurfaceDriver.KeyGenLengths()
    {
        public int[] acceptedBits(String n)
        {
            int fixed = fixedAesBits(n);
            return fixed == 0 ? new int[]{128, 192, 256} : new int[]{fixed};
        }

        public int keyBytesFor(String n, int bits)
        {
            return bits / 8;
        }

        public int defaultKeyBytes(String n)
        {
            int fixed = fixedAesBits(n);
            // The bare name defaults to the strongest it serves.
            return fixed == 0 ? 32 : fixed / 8;
        }
    };

    /** Both registrations and both OID spellings take a 256-bit key (RFC 8439). */
    public static final CipherSurfaceDriver.KeyGenLengths CHACHA20_KEYGEN =
            new CipherSurfaceDriver.KeyGenLengths()
    {
        public int[] acceptedBits(String n)
        {
            return new int[]{256};
        }

        public int keyBytesFor(String n, int bits)
        {
            return 32;
        }

        public int defaultKeyBytes(String n)
        {
            return 32;
        }
    };

    /**
     * Only the 3-key form. Both JCE spellings are accepted: 192 is the full
     * width and 168 the effective width with the parity bits discounted.
     */
    public static final CipherSurfaceDriver.KeyGenLengths DESEDE_KEYGEN =
            new CipherSurfaceDriver.KeyGenLengths()
    {
        public int[] acceptedBits(String n)
        {
            return new int[]{168, 192};
        }

        public int keyBytesFor(String n, int bits)
        {
            // 168 yields 24 bytes, not 21: the parity bits are carried in the
            // key material even though they do not count towards its strength.
            return 24;
        }

        public int defaultKeyBytes(String n)
        {
            return 24;
        }
    };

    /**
     * The three families served by {@link #SYMMETRIC_KEYGEN_PREFIX}. ARIA and
     * Camellia carry the three AES widths; SM4 is single-width.
     */
    public static final CipherSurfaceDriver.KeyGenLengths SYMMETRIC_KEYGEN =
            new CipherSurfaceDriver.KeyGenLengths()
    {
        public int[] acceptedBits(String n)
        {
            return "SM4".equals(n) ? new int[]{128} : new int[]{128, 192, 256};
        }

        public int keyBytesFor(String n, int bits)
        {
            return bits / 8;
        }

        public int defaultKeyBytes(String n)
        {
            return "SM4".equals(n) ? 16 : 32;
        }
    };

    /**
     * The one width an AES KeyGenerator name pins, or 0 when the name pins
     * none. The OID arc decides for the OID spellings, exactly as it does for
     * the Cipher names in {@link #AES}.
     */
    private static int fixedAesBits(String n)
    {
        String bare = n.startsWith("OID.") ? n.substring(4) : n;
        if (bare.startsWith("2.16.840.1.101.3.4.1."))
        {
            int arc = Integer.parseInt(bare.substring("2.16.840.1.101.3.4.1.".length()));
            return arc < 20 ? 128 : arc < 40 ? 192 : 256;
        }
        if (bare.contains("128"))
        {
            return 128;
        }
        if (bare.contains("192"))
        {
            return 192;
        }
        if (bare.contains("256"))
        {
            return 256;
        }
        return 0;
    }

    /** The width is in the name for the per-size registrations; 256 otherwise. */
    private static int byWidthInName(String n)
    {
        if (n.contains("128"))
        {
            return 16;
        }
        if (n.contains("192"))
        {
            return 24;
        }
        return 32;
    }
}
