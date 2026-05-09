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
 * Runtime exception thrown by NI-level decrypt entry points when the
 * underlying OpenSSL operation fails in a way that indicates a corrupted
 * ciphertext rather than a configuration / state problem. Examples
 * include OAEP padding-check failure and ciphertext-out-of-range.
 *
 * <p>Subclasses {@link OpenSSLException} so callers that handle the
 * generic OpenSSL error path keep working without code changes; callers
 * that want to react specifically to invalid ciphertext (e.g. surface
 * a more useful diagnostic, or count failures distinctly) can catch
 * {@code InvalidCipherTextException} ahead of {@code OpenSSLException}.
 *
 * <p>JCE-facing SPIs translate this into
 * {@link javax.crypto.BadPaddingException} at the {@code engineDoFinal}
 * boundary so the JCE contract is unchanged.
 */
public class InvalidCipherTextException extends OpenSSLException
{
    public InvalidCipherTextException()
    {
    }

    public InvalidCipherTextException(String message)
    {
        super(message);
    }

    public InvalidCipherTextException(String message, Throwable cause)
    {
        super(message, cause);
    }

    public InvalidCipherTextException(Throwable cause)
    {
        super(cause);
    }
}
