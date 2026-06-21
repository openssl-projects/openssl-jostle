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

import org.openssl.jostle.jcajce.provider.ks.KSServiceSPI;

import java.util.HashMap;
import java.util.Map;

class ProvKS
{
    private static final String PREFIX = ProvKS.class.getPackage().getName() + ".ks.";

    public void configure(final JostleProvider provider)
    {
        final Map<String, String> attr = new HashMap<String, String>();
        provider.addAlgorithmImplementation("KeyStore", "PKCS12", PREFIX + "KSServiceSPI", attr, (arg) -> new KSServiceSPI());
        provider.addAlias("KeyStore", "PKCS12", "PKCS#12", "P12");
    }
}
