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

import org.openssl.jostle.jcajce.provider.kdf.PBEKDF2SecretKeyFactory;

import java.util.HashMap;
import java.util.Map;

class ProvPBEKDF
{
    private static final Map<String, String> generalKDFAttributes = new HashMap<String, String>();

    static
    {
        generalKDFAttributes.put("SupportedKeyClasses", "javax.crypto.PBESecretKey");
        generalKDFAttributes.put("SupportedKeyFormats", "RAW");
    }

    private static final String PREFIX = ProvPBEKDF.class.getName();

    public void configure(final JostleProvider provider)
    {

        provider.addAlgorithmImplementation("SecretKeyFactory", "PBKDF2", PREFIX + "Base", generalKDFAttributes, (arg) -> new PBEKDF2SecretKeyFactory());
        provider.addAlgorithmImplementation("SecretKeyFactory", "PBKDF2WITHHMACSHA1", PREFIX + "BaseSHA1", generalKDFAttributes, (arg) -> new PBEKDF2SecretKeyFactory("SHA-1"));
        provider.addAlgorithmImplementation("SecretKeyFactory", "PBKDF2WITHHMACSHA224", PREFIX + "BaseSHA224", generalKDFAttributes, (arg) -> new PBEKDF2SecretKeyFactory("SHA-224"));
        provider.addAlgorithmImplementation("SecretKeyFactory", "PBKDF2WITHHMACSHA256", PREFIX + "BaseSHA256", generalKDFAttributes, (arg) -> new PBEKDF2SecretKeyFactory("SHA-256"));
        provider.addAlgorithmImplementation("SecretKeyFactory", "PBKDF2WITHHMACSHA384", PREFIX + "BaseSHA384", generalKDFAttributes, (arg) -> new PBEKDF2SecretKeyFactory("SHA-384"));
        provider.addAlgorithmImplementation("SecretKeyFactory", "PBKDF2WITHHMACSHA512", PREFIX + "BaseSHA512", generalKDFAttributes, (arg) -> new PBEKDF2SecretKeyFactory("SHA-512"));

        provider.addAlgorithmImplementation("SecretKeyFactory", "PBKDF2WITHHMACSHA512-224", PREFIX + "BaseSHA512_224", generalKDFAttributes, (arg) -> new PBEKDF2SecretKeyFactory("SHA-512/224"));
        provider.addAlgorithmImplementation("SecretKeyFactory", "PBKDF2WITHHMACSHA512-256", PREFIX + "BaseSHA512_256", generalKDFAttributes, (arg) -> new PBEKDF2SecretKeyFactory("SHA-512/256"));

        provider.addAlgorithmImplementation("SecretKeyFactory", "PBKDF2WITHHMACSHA3-224", PREFIX + "BaseSHA3_224", generalKDFAttributes, (arg) -> new PBEKDF2SecretKeyFactory("SHA3-224"));
        provider.addAlgorithmImplementation("SecretKeyFactory", "PBKDF2WITHHMACSHA3-256", PREFIX + "BaseSHA3_256", generalKDFAttributes, (arg) -> new PBEKDF2SecretKeyFactory("SHA3-256"));
        provider.addAlgorithmImplementation("SecretKeyFactory", "PBKDF2WITHHMACSHA3-384", PREFIX + "BaseSHA3_384", generalKDFAttributes, (arg) -> new PBEKDF2SecretKeyFactory("SHA3-384"));
        provider.addAlgorithmImplementation("SecretKeyFactory", "PBKDF2WITHHMACSHA3-512", PREFIX + "BaseSHA3_512", generalKDFAttributes, (arg) -> new PBEKDF2SecretKeyFactory("SHA3-512"));

        provider.addAlgorithmImplementation("SecretKeyFactory","PBKDF2WITHHMACBLAKE2B-512",PREFIX+"BLAKE2B_512",generalKDFAttributes,(arg)->new PBEKDF2SecretKeyFactory("BLAKE2B-512"));
        provider.addAlgorithmImplementation("SecretKeyFactory","PBKDF2WITHHMACBLAKE2S-256",PREFIX+"BLAKE2S_256",generalKDFAttributes,(arg)->new PBEKDF2SecretKeyFactory("BLAKE2s-256"));

        provider.addAlgorithmImplementation("SecretKeyFactory", "PBKDF2WITHHMACSM3", PREFIX + "SM3", generalKDFAttributes, (arg) -> new PBEKDF2SecretKeyFactory("SM3"));
        provider.addAlgorithmImplementation("SecretKeyFactory", "PBKDF2WITHHMACMD5", PREFIX + "MD5", generalKDFAttributes, (arg) -> new PBEKDF2SecretKeyFactory("MD5"));
        provider.addAlgorithmImplementation("SecretKeyFactory", "PBKDF2WITHHMACMD5-SHA1", PREFIX + "MD5_SHA1", generalKDFAttributes, (arg) -> new PBEKDF2SecretKeyFactory("MD5-SHA1"));
        provider.addAlgorithmImplementation("SecretKeyFactory", "PBKDF2WITHHMACRIPEMD160", PREFIX + "RIPEMD160", generalKDFAttributes, (arg) -> new PBEKDF2SecretKeyFactory("RIPEMD160"));

    }
}
