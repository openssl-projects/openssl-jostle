/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider;

/**
 * Runtime exception thrown by NI-level DER decode entry points when a
 * well-formed value decoded successfully but trailing bytes remained in
 * the input ({@code JO_DER_TRAILING_DATA}). Strict parsers reject
 * trailing garbage; accepting it silently can mask corruption.
 *
 * <p>Subclasses {@link OpenSSLException} so the KeyFactory decode paths
 * that already translate decoder failures into
 * {@link java.security.spec.InvalidKeySpecException} keep working
 * without code changes; limit tests can pin this specific type.
 */
public class Asn1TrailingDataException extends OpenSSLException
{
    public Asn1TrailingDataException()
    {
    }

    public Asn1TrailingDataException(String message)
    {
        super(message);
    }

    public Asn1TrailingDataException(String message, Throwable cause)
    {
        super(message, cause);
    }

    public Asn1TrailingDataException(Throwable cause)
    {
        super(cause);
    }
}
