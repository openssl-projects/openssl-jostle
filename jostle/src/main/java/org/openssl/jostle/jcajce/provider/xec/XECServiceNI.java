/*
 *
 *   Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *   Licensed under the Apache License 2.0 (the "License"). You may not use
 *   this file except in compliance with the License.  You can obtain a copy
 *   in the file LICENSE in the source distribution or at
 *   https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider.xec;

import org.openssl.jostle.jcajce.provider.DefaultServiceNI;
import org.openssl.jostle.jcajce.provider.ErrorCode;
import org.openssl.jostle.rand.RandSource;

/**
 * Native interface for X25519 / X448 (XDH) key generation. Key agreement
 * (the {@code EVP_PKEY_derive} flow) is type-agnostic at the OpenSSL level
 * and is provided by {@code ECServiceNI}'s kex methods — {@code XDHKeyAgreementSpi}
 * reuses those. XEC adds only key generation here.
 */
public interface XECServiceNI extends DefaultServiceNI
{
    /**
     * Generate an X25519 / X448 keypair. {@code name} is the OpenSSL
     * key-type name ("X25519" or "X448"); for these Montgomery key types
     * the name fully determines the key (no curve parameter). OpenSSL
     * consumes RAND during keygen, so a non-null {@link RandSource} is
     * required.
     */
    long ni_generateKeyPair(String name, int[] err, RandSource rndSource);


    default long generateKeyPair(String name, RandSource rndSource)
    {
        int[] err = new int[1];
        long r = ni_generateKeyPair(name, err, rndSource);
        handleErrors(err[0]);
        return r;
    }


    default long handleErrors(long code)
    {
        if (code >= 0)
        {
            return code;
        }

        ErrorCode errorCode = ErrorCode.forCode(code);
        switch (errorCode)
        {
            case JO_INCORRECT_KEY_TYPE:
                throw new IllegalArgumentException("invalid key type for XDH");
            default:
        }

        return baseErrorHandler(code);
    }
}
