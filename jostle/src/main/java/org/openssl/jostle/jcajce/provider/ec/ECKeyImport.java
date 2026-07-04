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

    /** Factory-bound counterpart of {@link #importPublic(Key)}. */
    public static JOECPublicKey importPublic(ECKeyFactorySpi keyFactory, Key key) throws InvalidKeyException
    {
        return importPublic(keyFactory, key, DEFAULT_PUBLIC_MESSAGE);
    }

    /**
     * As {@link #importPublic(Key)} but with a caller-supplied failure
     * message, so each SPI keeps its operation-specific wording.
     */
    public static JOECPublicKey importPublic(Key key, String failMessage) throws InvalidKeyException
    {
        return importPublic(new ECKeyFactorySpi(), key, failMessage);
    }

    /**
     * Variant bound to a specific KeyFactory (and so a specific NI backend):
     * the FIPS provider's SPIs translate foreign keys through the FIPS
     * interface library.
     */
    public static JOECPublicKey importPublic(ECKeyFactorySpi keyFactory, Key key, String failMessage) throws InvalidKeyException
    {
        if (key instanceof JOECPublicKey)
        {
            // Public keys carry no secret material and may cross between the
            // Jostle providers freely (OpenSSL imports the public components
            // into this library's lib ctx); only PRIVATE keys are isolated.
            return (JOECPublicKey) key;
        }
        if (key instanceof PublicKey)
        {
            try
            {
                Key translated = keyFactory.engineTranslateKey(key);
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

    /** Factory-bound counterpart of {@link #importPrivate(Key)}. */
    public static JOECPrivateKey importPrivate(ECKeyFactorySpi keyFactory, Key key) throws InvalidKeyException
    {
        return importPrivate(keyFactory, key, DEFAULT_PRIVATE_MESSAGE);
    }

    /** Private-key counterpart to {@link #importPublic(Key, String)}. */
    public static JOECPrivateKey importPrivate(Key key, String failMessage) throws InvalidKeyException
    {
        return importPrivate(new ECKeyFactorySpi(), key, failMessage);
    }

    /**
     * Variant bound to a specific KeyFactory (and so a specific NI backend):
     * the FIPS provider's SPIs translate foreign keys through the FIPS
     * interface library.
     */
    public static JOECPrivateKey importPrivate(ECKeyFactorySpi keyFactory, Key key, String failMessage) throws InvalidKeyException
    {
        if (key instanceof JOECPrivateKey)
        {
            JOECPrivateKey joKey = (JOECPrivateKey) key;
            if (joKey.getSpec().getSpecNI() != keyFactory.ownSpecNI())
            {
                // Keys are bound to the interface library (and OSSL_LIB_CTX)
                // that created them; JSL and JSLFIPS keys must not cross
                // implicitly.
                throw new InvalidKeyException(
                        "private key was created by a different Jostle provider; encode it with getEncoded() and decode it through this provider's KeyFactory");
            }
            return joKey;
        }
        if (key instanceof PrivateKey)
        {
            try
            {
                Key translated = keyFactory.engineTranslateKey(key);
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
