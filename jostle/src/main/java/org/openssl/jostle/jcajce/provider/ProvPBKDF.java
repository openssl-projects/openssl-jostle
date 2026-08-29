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

import org.openssl.jostle.jcajce.provider.kdf.PBKDF2SecretKeyFactory;

import java.util.HashMap;
import java.util.Map;

class ProvPBKDF
{
    private static final Map<String, String> generalKDFAttributes = new HashMap<String, String>();

    static
    {
        generalKDFAttributes.put("SupportedKeyClasses", "javax.crypto.PBESecretKey");
        generalKDFAttributes.put("SupportedKeyFormats", "RAW");
    }


    public void configure(final JostleProvider provider)
    {

        provider.addAlgorithmImplementation("SecretKeyFactory", "PBKDF2", PBKDF2SecretKeyFactory.class.getName(), generalKDFAttributes, (arg) -> new PBKDF2SecretKeyFactory());
        provider.addAlgorithmImplementation("SecretKeyFactory", "PBKDF2WITHHMACSHA1", PBKDF2SecretKeyFactory.class.getName(), generalKDFAttributes, (arg) -> new PBKDF2SecretKeyFactory("SHA-1"));
        provider.addAlgorithmImplementation("SecretKeyFactory", "PBKDF2WITHHMACSHA224", PBKDF2SecretKeyFactory.class.getName(), generalKDFAttributes, (arg) -> new PBKDF2SecretKeyFactory("SHA-224"));
        provider.addAlgorithmImplementation("SecretKeyFactory", "PBKDF2WITHHMACSHA256", PBKDF2SecretKeyFactory.class.getName(), generalKDFAttributes, (arg) -> new PBKDF2SecretKeyFactory("SHA-256"));
        provider.addAlgorithmImplementation("SecretKeyFactory", "PBKDF2WITHHMACSHA384", PBKDF2SecretKeyFactory.class.getName(), generalKDFAttributes, (arg) -> new PBKDF2SecretKeyFactory("SHA-384"));
        provider.addAlgorithmImplementation("SecretKeyFactory", "PBKDF2WITHHMACSHA512", PBKDF2SecretKeyFactory.class.getName(), generalKDFAttributes, (arg) -> new PBKDF2SecretKeyFactory("SHA-512"));

        provider.addAlgorithmImplementation("SecretKeyFactory", "PBKDF2WITHHMACSHA512-224", PBKDF2SecretKeyFactory.class.getName(), generalKDFAttributes, (arg) -> new PBKDF2SecretKeyFactory("SHA-512/224"));
        provider.addAlgorithmImplementation("SecretKeyFactory", "PBKDF2WITHHMACSHA512-256", PBKDF2SecretKeyFactory.class.getName(), generalKDFAttributes, (arg) -> new PBKDF2SecretKeyFactory("SHA-512/256"));

        provider.addAlgorithmImplementation("SecretKeyFactory", "PBKDF2WITHHMACSHA3-224", PBKDF2SecretKeyFactory.class.getName(), generalKDFAttributes, (arg) -> new PBKDF2SecretKeyFactory("SHA3-224"));
        provider.addAlgorithmImplementation("SecretKeyFactory", "PBKDF2WITHHMACSHA3-256", PBKDF2SecretKeyFactory.class.getName(), generalKDFAttributes, (arg) -> new PBKDF2SecretKeyFactory("SHA3-256"));
        provider.addAlgorithmImplementation("SecretKeyFactory", "PBKDF2WITHHMACSHA3-384", PBKDF2SecretKeyFactory.class.getName(), generalKDFAttributes, (arg) -> new PBKDF2SecretKeyFactory("SHA3-384"));
        provider.addAlgorithmImplementation("SecretKeyFactory", "PBKDF2WITHHMACSHA3-512", PBKDF2SecretKeyFactory.class.getName(), generalKDFAttributes, (arg) -> new PBKDF2SecretKeyFactory("SHA3-512"));

        provider.addAlgorithmImplementation("SecretKeyFactory", "PBKDF2WITHHMACBLAKE2B-512", PBKDF2SecretKeyFactory.class.getName(), generalKDFAttributes, (arg) -> new PBKDF2SecretKeyFactory("BLAKE2B-512"));
        provider.addAlgorithmImplementation("SecretKeyFactory", "PBKDF2WITHHMACBLAKE2S-256", PBKDF2SecretKeyFactory.class.getName(), generalKDFAttributes, (arg) -> new PBKDF2SecretKeyFactory("BLAKE2s-256"));

        provider.addAlgorithmImplementation("SecretKeyFactory", "PBKDF2WITHHMACSM3", PBKDF2SecretKeyFactory.class.getName(), generalKDFAttributes, (arg) -> new PBKDF2SecretKeyFactory("SM3"));
        provider.addAlgorithmImplementation("SecretKeyFactory", "PBKDF2WITHHMACMD5", PBKDF2SecretKeyFactory.class.getName(), generalKDFAttributes, (arg) -> new PBKDF2SecretKeyFactory("MD5"));
        provider.addAlgorithmImplementation("SecretKeyFactory", "PBKDF2WITHHMACMD5-SHA1", PBKDF2SecretKeyFactory.class.getName(), generalKDFAttributes, (arg) -> new PBKDF2SecretKeyFactory("MD5-SHA1"));
        provider.addAlgorithmImplementation("SecretKeyFactory", "PBKDF2WITHHMACRIPEMD160", PBKDF2SecretKeyFactory.class.getName(), generalKDFAttributes, (arg) -> new PBKDF2SecretKeyFactory("RIPEMD160"));

    }
}
