/*
 *  Copyright 2005-2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://www.openssl.org/source/license.html
 *
 */

package org.openssl.jostle.jcajce.provider;

import org.openssl.jostle.CryptoServicesRegistrar;

/**
 * Allow setting of OpenSSL Specific parameters
 */
public class OpenSSL
{
    /**
     * Set the OpenSSL Module by name
     *
     * @param provider the name of the provider
     */
    public static void setOSSLProvider(String provider)
    {
        CryptoServicesRegistrar.assertNativeAvailable();

        ErrorCode code = ErrorCode.forCode(() -> NISelector.OpenSSLNI.setOSSLProviderModule(provider));
        switch (code)
        {
            case JO_SUCCESS:
                break;
            case JO_FAIL:
                throw new IllegalStateException("unable to set OpenSSL provider " + provider);
            case JO_OPENSSL_ERROR:
                throw new OpenSSLException(String.format("OpenSSL Error: %s", OpenSSL.getOpenSSLErrors()));
            case JO_PROV_NAME_NULL:
                throw new IllegalArgumentException("provider name is null");
            case JO_PROV_NAME_EMPTY:
                throw new IllegalArgumentException("provider name is empty");
            default:
                throw new IllegalArgumentException("unexpected return code: " + code);
        }

    }

    /**
     * Return a string of any OpenSSL errors, will return null if no
     * errors are available.
     *
     * @return Error message or null if no errors
     */
    public static String getOpenSSLErrors()
    {
        CryptoServicesRegistrar.assertNativeAvailable();
        String error = NISelector.OpenSSLNI.getOSSLErrors();
        if (error.isEmpty())
        {
            error = null;
        }
        return error;
    }

}
