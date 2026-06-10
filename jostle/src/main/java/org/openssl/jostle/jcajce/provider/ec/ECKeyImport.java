/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider.ec;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Coerces an arbitrary EC key to a JSL-native key object. JSL keys are used
 * directly; a foreign EC key — e.g. {@code sun.security.ec.*} from
 * {@code X509Certificate.getPublicKey()}, or a BouncyCastle key — is
 * re-imported through {@link ECKeyFactorySpi#engineTranslateKey} so external
 * callers interoperate without pre-converting keys.
 *
 * <p>Shared by the ECDSA signature and ECDH key-agreement SPIs (and the
 * CMS EC-with-KDF agreement subclass), mirroring {@code RSAKeyImport}.
 */
public final class ECKeyImport
{
    private ECKeyImport()
    {
    }

    private static final String DEFAULT_PUBLIC_MESSAGE = "expected an ECPublicKey from the Jostle provider";
    private static final String DEFAULT_PRIVATE_MESSAGE = "expected an ECPrivateKey from the Jostle provider";

    public static JOECPublicKey importPublic(Key key) throws InvalidKeyException
    {
        return importPublic(key, DEFAULT_PUBLIC_MESSAGE);
    }

    /**
     * As {@link #importPublic(Key)} but with a caller-supplied failure
     * message, so each SPI keeps its operation-specific wording.
     */
    public static JOECPublicKey importPublic(Key key, String failMessage) throws InvalidKeyException
    {
        if (key instanceof JOECPublicKey)
        {
            return (JOECPublicKey) key;
        }
        if (key instanceof PublicKey)
        {
            try
            {
                Key translated = new ECKeyFactorySpi().engineTranslateKey(key);
                if (translated instanceof JOECPublicKey)
                {
                    return (JOECPublicKey) translated;
                }
            }
            catch (InvalidKeyException e)
            {
                // Wrong-algorithm or unparseable key — fall through to the canonical message.
            }
        }
        throw new InvalidKeyException(failMessage);
    }

    public static JOECPrivateKey importPrivate(Key key) throws InvalidKeyException
    {
        return importPrivate(key, DEFAULT_PRIVATE_MESSAGE);
    }

    /** Private-key counterpart to {@link #importPublic(Key, String)}. */
    public static JOECPrivateKey importPrivate(Key key, String failMessage) throws InvalidKeyException
    {
        if (key instanceof JOECPrivateKey)
        {
            return (JOECPrivateKey) key;
        }
        if (key instanceof PrivateKey)
        {
            try
            {
                Key translated = new ECKeyFactorySpi().engineTranslateKey(key);
                if (translated instanceof JOECPrivateKey)
                {
                    return (JOECPrivateKey) translated;
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
