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

    public static final String AES_PREFIX = "org.openssl.jostle.jcajce.provider.ProvAES";
    public static final String ARIA_PREFIX = "org.openssl.jostle.jcajce.provider.ProvARIA";
    public static final String CAMELLIA_PREFIX = "org.openssl.jostle.jcajce.provider.ProvCAMELLIA";
    public static final String SM4_PREFIX = "org.openssl.jostle.jcajce.provider.ProvSM4";
    public static final String CHACHA20_PREFIX = "org.openssl.jostle.jcajce.provider.ProvChaCha20";
    public static final String DESEDE_PREFIX = "org.openssl.jostle.jcajce.provider.ProvDESede";

    // RSA and ML-KEM register through SPI classes named after the SPI, not
    // after the Prov class, so their prefix is the package. That also pulls in
    // Signature / KeyFactory / KeyPairGenerator, which is why the service
    // types passed to ProviderSurfaceGuard are required and explicit.
    public static final String RSA_PREFIX = "org.openssl.jostle.jcajce.provider.rsa.";
    public static final String MLKEM_PREFIX = "org.openssl.jostle.jcajce.provider.mlkem.";

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
