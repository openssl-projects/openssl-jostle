/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider.xec;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Coerces an arbitrary XDH (X25519/X448) key to a JSL-native key object. JSL
 * keys are used directly; a foreign key — e.g. a {@code sun.security.ec.*}
 * key from {@code X509Certificate.getPublicKey()} or the JDK's XDH
 * KeyFactory — is re-imported through
 * {@link XECKeyFactorySpi#engineTranslateKey} so external callers
 * interoperate without pre-converting keys. Mirrors {@code RSAKeyImport}.
 */
public final class XDHKeyImport
{
    private XDHKeyImport()
    {
    }

    public static JOXECPublicKey importPublic(Key key, String failMessage) throws InvalidKeyException
    {
        if (key instanceof JOXECPublicKey)
        {
            return (JOXECPublicKey) key;
        }
        if (key instanceof PublicKey)
        {
            try
            {
                Key translated = new XECKeyFactorySpi().engineTranslateKey(key);
                if (translated instanceof JOXECPublicKey)
                {
                    return (JOXECPublicKey) translated;
                }
            }
            catch (InvalidKeyException e)
            {
                // Wrong-algorithm or unparseable key — fall through to the canonical message.
            }
        }
        throw new InvalidKeyException(failMessage);
    }

    public static JOXECPrivateKey importPrivate(Key key, String failMessage) throws InvalidKeyException
    {
        if (key instanceof JOXECPrivateKey)
        {
            return (JOXECPrivateKey) key;
        }
        if (key instanceof PrivateKey)
        {
            try
            {
                Key translated = new XECKeyFactorySpi().engineTranslateKey(key);
                if (translated instanceof JOXECPrivateKey)
                {
                    return (JOXECPrivateKey) translated;
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
