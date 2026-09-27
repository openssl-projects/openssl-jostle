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
 *
 * <p>The {@link SecretKeyBagForm} chooses how {@code store} writes a secret-key
 * entry; {@code load} reads either. An RFC 7292 bag has no protection of its
 * own, so after a load its key is protected by the store password only; a SunJCE
 * bag is encrypted under its entry's password, which reading it back requires.
 */
public final class PKCS12LoadStoreParameter
    implements KeyStore.LoadStoreParameter
{
    private final InputStream inputStream;
    private final OutputStream outputStream;
    private final KeyStore.ProtectionParameter protectionParameter;
    private final SecretKeyBagForm secretKeyBagForm;

    /**
     * How a secret-key entry is written. {@link #RFC7292} is the RFC 7292
     * secretBag BouncyCastle writes and reads, holding the key OID and the key;
     * SunJCE cannot read it. {@link #SUNJCE} is the form SunJCE writes and reads,
     * an encrypted PKCS#8 inside the bag; BouncyCastle reads it only when its
     * {@code org.bouncycastle.pkcs12.allow_sun_secret_keys} property is set.
     */
    public enum SecretKeyBagForm
    {
        RFC7292,
        SUNJCE
    }

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
        this(inputStream, outputStream, protectionParameter, SecretKeyBagForm.RFC7292);
    }

    /**
     * For {@code store}: write secret-key entries in {@code secretKeyBagForm}.
     */
    public PKCS12LoadStoreParameter(OutputStream outputStream,
                                    KeyStore.ProtectionParameter protectionParameter,
                                    SecretKeyBagForm secretKeyBagForm)
    {
        this(null, outputStream, protectionParameter, secretKeyBagForm);
    }

    public PKCS12LoadStoreParameter(InputStream inputStream,
                                    OutputStream outputStream,
                                    KeyStore.ProtectionParameter protectionParameter,
                                    SecretKeyBagForm secretKeyBagForm)
    {
        if (secretKeyBagForm == null)
        {
            throw new NullPointerException("secretKeyBagForm must not be null");
        }
        this.inputStream = inputStream;
        this.outputStream = outputStream;
        this.protectionParameter = protectionParameter;
        this.secretKeyBagForm = secretKeyBagForm;
    }

    public InputStream getInputStream()
    {
        return inputStream;
    }

    public OutputStream getOutputStream()
    {
        return outputStream;
    }

    /**
     * How {@code store} writes a secret-key entry; RFC7292 unless one was given.
     */
    public SecretKeyBagForm getSecretKeyBagForm()
    {
        return secretKeyBagForm;
    }

    @Override
    public KeyStore.ProtectionParameter getProtectionParameter()
    {
        return protectionParameter;
    }
}
