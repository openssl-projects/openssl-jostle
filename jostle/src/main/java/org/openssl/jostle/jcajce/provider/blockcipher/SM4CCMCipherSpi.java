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
 * SM4-CCM Cipher SPI. Subclass of {@link CCMCipherSpi} that pre-binds
 * the cipher family to SM4. JCE callers reach this via
 * {@code Cipher.getInstance("SM4/CCM/NoPadding")}.
 */
public class SM4CCMCipherSpi extends CCMCipherSpi
{
    public SM4CCMCipherSpi()
    {
        super(CipherFamily.SM4);
    }
}
