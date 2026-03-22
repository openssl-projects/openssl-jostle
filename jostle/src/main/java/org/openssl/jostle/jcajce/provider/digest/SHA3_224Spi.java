/*
 *  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
 */
package org.openssl.jostle.jcajce.provider.digest;

/** SPI for SHA3-224 via native interface. */
public final class SHA3_224Spi extends DigestSpiBase
{
    public SHA3_224Spi()
    {
        super("SHA3-224");
    }
}
