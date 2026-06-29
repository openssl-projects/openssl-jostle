/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce;

import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyStore;

/**
 * A {@link KeyStore.LoadStoreParameter} for the Jostle PKCS#12 KeyStore that
 * carries the I/O stream alongside the protection parameter, so callers can use
 * the parameter-object forms
 * {@link KeyStore#load(KeyStore.LoadStoreParameter)} and
 * {@link KeyStore#store(KeyStore.LoadStoreParameter)} with a stream-backed
 * keystore.
 *
 * <p>The JCA {@code LoadStoreParameter} interface itself exposes only a
 * {@code ProtectionParameter} (it was designed for non-stream stores such as
 * PKCS#11 tokens), so a stream-carrying implementation is required to drive a
 * file/stream PKCS#12 through that API. This is the Jostle analogue of
 * BouncyCastle's {@code org.bouncycastle.jcajce.PKCS12LoadStoreParameter}.
 *
 * <p>The standard {@code KeyStore.load(InputStream, char[])} /
 * {@code KeyStore.store(OutputStream, char[])} forms do not need this type.
 */
public final class PKCS12LoadStoreParameter
    implements KeyStore.LoadStoreParameter
{
    private final InputStream inputStream;
    private final OutputStream outputStream;
    private final KeyStore.ProtectionParameter protectionParameter;

    public PKCS12LoadStoreParameter(InputStream inputStream,
                                    KeyStore.ProtectionParameter protectionParameter)
    {
        this(inputStream, null, protectionParameter);
    }

    public PKCS12LoadStoreParameter(OutputStream outputStream,
                                    KeyStore.ProtectionParameter protectionParameter)
    {
        this(null, outputStream, protectionParameter);
    }

    public PKCS12LoadStoreParameter(InputStream inputStream,
                                    OutputStream outputStream,
                                    KeyStore.ProtectionParameter protectionParameter)
    {
        this.inputStream = inputStream;
        this.outputStream = outputStream;
        this.protectionParameter = protectionParameter;
    }

    public InputStream getInputStream()
    {
        return inputStream;
    }

    public OutputStream getOutputStream()
    {
        return outputStream;
    }

    @Override
    public KeyStore.ProtectionParameter getProtectionParameter()
    {
        return protectionParameter;
    }
}
