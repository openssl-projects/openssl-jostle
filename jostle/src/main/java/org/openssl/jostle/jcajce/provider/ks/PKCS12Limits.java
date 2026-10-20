/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider.ks;

import org.openssl.jostle.util.Properties;

import java.io.IOException;

/**
 * The ceiling on a PKCS#12 load, applied to the stream before any native call.
 * 64 MiB, matching the BCFKS store and the X.509 container ceilings: a
 * keystore holding many certificates and keys is the same shape of container.
 * The bytes bound everything parsed from them, the bag and entry counts too.
 */
final class PKCS12Limits
{
    static final int DEFAULT_MAX_STORE_BYTES = 64 * 1024 * 1024;

    /** Property that moves the ceiling, named in the refusal. */
    static final String MAX_STORE_BYTES_PROPERTY = "org.openssl.jostle.pkcs12.max_store_bytes";

    private PKCS12Limits()
    {
    }

    /** Read once per load; a value that is not an integer is refused, not defaulted. */
    static int maxStoreBytes()
        throws IOException
    {
        try
        {
            int configured = Properties.asInteger(MAX_STORE_BYTES_PROPERTY, DEFAULT_MAX_STORE_BYTES);
            return configured < 1 ? DEFAULT_MAX_STORE_BYTES : configured;
        }
        catch (NumberFormatException e)
        {
            throw new IOException(MAX_STORE_BYTES_PROPERTY + " is not an integer", e);
        }
    }

    static IOException ceilingExceeded()
    {
        String message = "key store input exceeds the configured ceiling; raise " + MAX_STORE_BYTES_PROPERTY;
        return new IOException(message, new CeilingExceededException(message));
    }

    /** A ceiling refusal, distinct from a malformed store. */
    static final class CeilingExceededException
        extends Exception
    {
        CeilingExceededException(String message)
        {
            super(message);
        }
    }
}
