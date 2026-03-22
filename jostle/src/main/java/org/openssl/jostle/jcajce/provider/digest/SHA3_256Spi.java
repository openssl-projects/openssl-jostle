/*
 *  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
 */
package org.openssl.jostle.jcajce.provider.digest;

/** SPI for SHA3-256 via native interface. */
public final class SHA3_256Spi extends DigestSpiBase
{
    public SHA3_256Spi()
    {
        super("SHA3-256");
    }
}
