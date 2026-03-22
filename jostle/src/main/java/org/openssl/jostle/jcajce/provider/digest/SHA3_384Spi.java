/*
 *  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
 */
package org.openssl.jostle.jcajce.provider.digest;

/** SPI for SHA3-384 via native interface. */
public final class SHA3_384Spi extends DigestSpiBase
{
    public SHA3_384Spi()
    {
        super("SHA3-384");
    }
}
