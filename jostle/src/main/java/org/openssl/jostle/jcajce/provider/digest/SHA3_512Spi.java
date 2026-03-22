/*
 *  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
 */
package org.openssl.jostle.jcajce.provider.digest;

/** SPI for SHA3-512 via native interface. */
public final class SHA3_512Spi extends DigestSpiBase
{
    public SHA3_512Spi()
    {
        super("SHA3-512");
    }
}
