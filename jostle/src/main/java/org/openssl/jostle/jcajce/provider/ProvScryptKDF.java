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

import org.openssl.jostle.jcajce.provider.kdf.ScryptSecretKeyFactory;

import java.util.HashMap;
import java.util.Map;
import org.openssl.jostle.util.asn1.oids.MiscObjectIdentifiers;

class ProvScryptKDF
{
    private static final Map<String, String> generalKDFAttributes = new HashMap<String, String>();



    public void configure(final JostleProvider provider)
    {
        provider.addAlgorithmImplementation("SecretKeyFactory", "SCRYPT", ScryptSecretKeyFactory.class.getName(), generalKDFAttributes, (arg) -> new ScryptSecretKeyFactory());
        provider.addAlgorithmImplementation("SecretKeyFactory", MiscObjectIdentifiers.id_scrypt.getId(), ScryptSecretKeyFactory.class.getName(), generalKDFAttributes, (arg) -> new ScryptSecretKeyFactory());

    }
}
