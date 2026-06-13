/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider.rsa;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Coerces an arbitrary RSA key to a JSL-native key object. JSL keys are used
 * directly; a foreign RSA key — e.g. {@code sun.security.rsa.RSAPublicKeyImpl}
 * from {@code X509Certificate.getPublicKey()}, or a BouncyCastle key — is
 * re-imported through {@link RSAKeyFactorySpi#engineTranslateKey} so external
 * callers interoperate without pre-converting keys.
 *
 * <p>Shared by the RSA signature and {@code Cipher} SPIs: the signature SPI has
 * always translated foreign keys, and the Cipher SPIs must do the same so CMS
 * RSA key transport (which wraps the CEK to a certificate's public key) works.
 */
public final class RSAKeyImport
{
    private RSAKeyImport()
    {
    }

    /** Default message used by the signature SPIs. */
    private static final String DEFAULT_PUBLIC_MESSAGE = "expected an RSAPublicKey from the Jostle provider";
    private static final String DEFAULT_PRIVATE_MESSAGE = "expected an RSAPrivateKey from the Jostle provider";

    public static JORSAPublicKey importPublic(Key key) throws InvalidKeyException
    {
        return importPublic(key, DEFAULT_PUBLIC_MESSAGE);
    }

    /**
     * As {@link #importPublic(Key)} but with a caller-supplied failure message,
     * so the Cipher SPIs can keep their operation-specific wording
     * (e.g. "encrypt/wrap requires an RSAPublicKey").
     */
    public static JORSAPublicKey importPublic(Key key, String failMessage) throws InvalidKeyException
    {
        if (key instanceof JORSAPublicKey)
        {
            return (JORSAPublicKey) key;
        }
        if (key instanceof PublicKey)
        {
            try
            {
                Key translated = new RSAKeyFactorySpi().engineTranslateKey(key);
                if (translated instanceof JORSAPublicKey)
                {
                    return (JORSAPublicKey) translated;
                }
            }
            catch (InvalidKeyException e)
            {
                // Wrong-algorithm or unparseable key — fall through to the canonical message.
            }
        }
        throw new InvalidKeyException(failMessage);
    }

    public static JORSAPrivateKey importPrivate(Key key) throws InvalidKeyException
    {
        return importPrivate(key, DEFAULT_PRIVATE_MESSAGE);
    }

    /** Private-key counterpart to {@link #importPublic(Key, String)}. */
    public static JORSAPrivateKey importPrivate(Key key, String failMessage) throws InvalidKeyException
    {
        if (key instanceof JORSAPrivateKey)
        {
            return (JORSAPrivateKey) key;
        }
        if (key instanceof PrivateKey)
        {
            try
            {
                Key translated = new RSAKeyFactorySpi().engineTranslateKey(key);
                if (translated instanceof JORSAPrivateKey)
                {
                    return (JORSAPrivateKey) translated;
                }
            }
            catch (InvalidKeyException e)
            {
                // Wrong-algorithm or unparseable key — fall through to the canonical message.
            }
        }
        throw new InvalidKeyException(failMessage);
    }
}
