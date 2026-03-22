/*
 *  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
 */
package org.openssl.jostle.jcajce.provider.digest;

/** SPI for MD5 via native interface. */
public final class MD5Spi extends DigestSpiBase
{
    public MD5Spi()
    {
        super("MD5");
    }
}
