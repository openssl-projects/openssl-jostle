/*
 *  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider;

import org.openssl.jostle.CryptoServicesRegistrar;

/**
 * Allow setting of OpenSSL Specific parameters
 */
public class OpenSSL
{
    private static String lastModuleName;

    /**
     * Set the OpenSSL Module by name
     *
     * @param moduleName the name of the moduleName
     */
    synchronized static void setOSSLProvider(String moduleName)
    {
        if (lastModuleName != null)
        {
            if (lastModuleName.equals(moduleName))
            {
                return;
            }

            throw new IllegalStateException("OpenSSL already initialized to " + lastModuleName);
        }

        if (moduleName == null || moduleName.trim().isEmpty())
        {
            throw new IllegalArgumentException("moduleName is null or empty");
        }

        moduleName = moduleName.trim();

        lastModuleName = moduleName;

        CryptoServicesRegistrar.assertNativeAvailable();

        ErrorCode code = ErrorCode.forCode(NISelector.OpenSSLNI.setOSSLProviderModule(moduleName));
        switch (code)
        {
            case JO_SUCCESS:
                break;
            case JO_FAIL:
                throw new IllegalStateException("unable to set OpenSSL moduleName " + moduleName);
            case JO_OPENSSL_ERROR:
                throw new OpenSSLException(String.format("OpenSSL Error: %s", OpenSSL.getOpenSSLErrors()));
            case JO_PROV_NAME_NULL:
                throw new IllegalArgumentException("moduleName name is null");
            case JO_PROV_NAME_EMPTY:
                throw new IllegalArgumentException("moduleName name is empty");
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
