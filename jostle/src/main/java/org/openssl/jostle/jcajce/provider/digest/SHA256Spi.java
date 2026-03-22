/*
 *  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider.digest;

/**
 * SHA-256 MessageDigest backed by OpenSSL via Jostle.
 * <p>
 * Uses {@link DigestSpiBase} for all native bridging; this class only
 * supplies the algorithm name.
 */
public final class SHA256Spi extends DigestSpiBase
{
    public SHA256Spi()
    {
        super("SHA-256");
    }
}
