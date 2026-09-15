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
 * Runtime exception thrown by the NI-level X.509 entry points when a
 * certificate's structure decodes but its content cannot be represented — a
 * duplicated or undecodable extension, or a keyUsage declaring more bits than
 * the provider will carry.
 *
 * <p>Subclasses {@link OpenSSLException}, so a caller handling the generic
 * OpenSSL path keeps working, while one that wants to separate "this is not a
 * usable certificate" from "OpenSSL failed" can catch this first.
 *
 * <p>The CertificateFactory SPI translates it into
 * {@link java.security.cert.CertificateParsingException} at the parse
 * boundary, which is where both the JDK and BouncyCastle raise for the same
 * inputs — measured on a certificate carrying a duplicated basicConstraints:
 * SUN throws {@code CertificateParsingException("Duplicate extensions not
 * allowed")} and BouncyCastle a subclass of it, while OpenSSL parses the file
 * happily. The refusal is ours to make, so it has to be made here.
 */
public class CertificateParseException extends OpenSSLException
{
    public CertificateParseException()
    {
    }

    public CertificateParseException(String message)
    {
        super(message);
    }

    public CertificateParseException(String message, Throwable cause)
    {
        super(message, cause);
    }
}
