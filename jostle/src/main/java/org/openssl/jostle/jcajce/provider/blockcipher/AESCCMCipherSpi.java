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

package org.openssl.jostle.jcajce.provider.blockcipher;

/**
 * AES-CCM Cipher SPI. Subclass of {@link CCMCipherSpi} that pre-binds
 * the cipher family to AES. JCE callers reach this via
 * {@code Cipher.getInstance("AES/CCM/NoPadding")}.
 */
public class AESCCMCipherSpi extends CCMCipherSpi
{
    public AESCCMCipherSpi()
    {
        super(CipherFamily.AES);
    }

    public AESCCMCipherSpi(java.security.Provider providerInstance)
    {
        super(CipherFamily.AES, providerInstance);
    }

    /**
     * Pinned to one AES key size, for the registrations under the NIST CCM OIDs
     * (id-aes128-CCM and friends). Those OIDs NAME a key size, so a key of a
     * different length is refused rather than silently performing a different
     * algorithm under that OID's name.
     */
    public AESCCMCipherSpi(OSSLCipher mandatedCipher)
    {
        super(CipherFamily.AES, mandatedCipher);
    }

    public AESCCMCipherSpi(OSSLCipher mandatedCipher, java.security.Provider providerInstance)
    {
        super(CipherFamily.AES, mandatedCipher, providerInstance);
    }

    //
    // NI-binding constructor for the FIPS provider: identical behaviour,
    // bound to the FIPS interface library's CCMCipherNI.
    //
    public AESCCMCipherSpi(CCMCipherNI cipherNI)
    {
        super(cipherNI, CipherFamily.AES);
    }

    public AESCCMCipherSpi(CCMCipherNI cipherNI, java.security.Provider providerInstance)
    {
        super(cipherNI, CipherFamily.AES, providerInstance);
    }

    //
    // NI-binding + size-pinned, for the FIPS provider's OID registrations.
    //
    public AESCCMCipherSpi(CCMCipherNI cipherNI, OSSLCipher mandatedCipher)
    {
        super(cipherNI, CipherFamily.AES, mandatedCipher);
    }

    public AESCCMCipherSpi(CCMCipherNI cipherNI, OSSLCipher mandatedCipher,
                           java.security.Provider providerInstance)
    {
        super(cipherNI, CipherFamily.AES, mandatedCipher, providerInstance);
    }
}
