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

import org.openssl.jostle.jcajce.provider.kdf.PBESecretKeyFactory;

import java.util.HashMap;
import java.util.Map;

class ProvKDF
{
    private static final Map<String, String> generalKDFAttributes = new HashMap<String, String>();

    static
    {
        generalKDFAttributes.put("SupportedKeyClasses", "javax.crypto.PBESecretKey");
        generalKDFAttributes.put("SupportedKeyFormats", "RAW");
    }

    private static final String PREFIX = ProvKDF.class.getName();

    public void configure(final JostleProvider provider)
    {

        provider.addAlgorithmImplementation("SecretKeyFactory", "PBKDF2", PREFIX + "Base", generalKDFAttributes, (arg) -> new PBESecretKeyFactory());
        provider.addAlgorithmImplementation("SecretKeyFactory", "PBKDF2WITHHMACSHA1", PREFIX + "BaseSHA1", generalKDFAttributes, (arg) -> new PBESecretKeyFactory("SHA-1"));
        provider.addAlgorithmImplementation("SecretKeyFactory", "PBKDF2WITHHMACSHA224", PREFIX + "BaseSHA224", generalKDFAttributes, (arg) -> new PBESecretKeyFactory("SHA-224"));
        provider.addAlgorithmImplementation("SecretKeyFactory", "PBKDF2WITHHMACSHA256", PREFIX + "BaseSHA224", generalKDFAttributes, (arg) -> new PBESecretKeyFactory("SHA-256"));
        provider.addAlgorithmImplementation("SecretKeyFactory", "PBKDF2WITHHMACSHA384", PREFIX + "BaseSHA384", generalKDFAttributes, (arg) -> new PBESecretKeyFactory("SHA-384"));
        provider.addAlgorithmImplementation("SecretKeyFactory", "PBKDF2WITHHMACSHA512", PREFIX + "BaseSHA512", generalKDFAttributes, (arg) -> new PBESecretKeyFactory("SHA-512"));

        provider.addAlgorithmImplementation("SecretKeyFactory", "PBKDF2WITHHMACSHA512-224", PREFIX + "BaseSHA512_224", generalKDFAttributes, (arg) -> new PBESecretKeyFactory("SHA-512/224"));
        provider.addAlgorithmImplementation("SecretKeyFactory", "PBKDF2WITHHMACSHA512-256", PREFIX + "BaseSHA512_256", generalKDFAttributes, (arg) -> new PBESecretKeyFactory("SHA-512/256"));

        provider.addAlgorithmImplementation("SecretKeyFactory", "PBKDF2WITHHMACSHA3-224", PREFIX + "BaseSHA3_224", generalKDFAttributes, (arg) -> new PBESecretKeyFactory("SHA3-224"));
        provider.addAlgorithmImplementation("SecretKeyFactory", "PBKDF2WITHHMACSHA3-256", PREFIX + "BaseSHA3_224", generalKDFAttributes, (arg) -> new PBESecretKeyFactory("SHA3-256"));
        provider.addAlgorithmImplementation("SecretKeyFactory", "PBKDF2WITHHMACSHA3-384", PREFIX + "BaseSHA3_384", generalKDFAttributes, (arg) -> new PBESecretKeyFactory("SHA3-384"));
        provider.addAlgorithmImplementation("SecretKeyFactory", "PBKDF2WITHHMACSHA3-512", PREFIX + "BaseSHA3_512", generalKDFAttributes, (arg) -> new PBESecretKeyFactory("SHA3-512"));

// TODO check output to confirm if the following are HMAC-Digest or just Digest

//        provider.addAlgorithmImplementation("SecretKeyFactory","PBKDF2WITHHMACKECCAK-128",PREFIX+"BaseKECCAK_128",generalKDFAttributes,(arg)->new PBESecretKeyFactory("KECCAK-128"));
//        provider.addAlgorithmImplementation("SecretKeyFactory","PBKDF2WITHHMACKECCAK-256",PREFIX+"BaseKECCAK_256",generalKDFAttributes,(arg)->new PBESecretKeyFactory("KECCAK-256"));
//        provider.addAlgorithmImplementation("SecretKeyFactory","PBKDF2WITHHMACKECCAK-384",PREFIX+"BaseKECCAK_384",generalKDFAttributes,(arg)->new PBESecretKeyFactory("KECCAK-384"));
//        provider.addAlgorithmImplementation("SecretKeyFactory","PBKDF2WITHHMACKECCAK-512",PREFIX+"BaseKECCAK_512",generalKDFAttributes,(arg)->new PBESecretKeyFactory("KECCAK-512"));
//
//        provider.addAlgorithmImplementation("SecretKeyFactory","PBKDF2WITHSHAKE-128",PREFIX+"BaseSHAKE_128",generalKDFAttributes,(arg)->new PBESecretKeyFactory("SHAKE-128"));
//        provider.addAlgorithmImplementation("SecretKeyFactory","PBKDF2WITHSHAKE-256",PREFIX+"BaseSHAKE_256",generalKDFAttributes,(arg)->new PBESecretKeyFactory("SHAKE-256"));
//        provider.addAlgorithmImplementation("SecretKeyFactory","PBKDF2WITHKMAC-128",PREFIX+"KMAC_128",generalKDFAttributes,(arg)->new PBESecretKeyFactory("KMAC-128"));
//        provider.addAlgorithmImplementation("SecretKeyFactory","PBKDF2WITHKMAC-256",PREFIX+"KMAC_256",generalKDFAttributes,(arg)->new PBESecretKeyFactory("KMAC-256"));

//        provider.addAlgorithmImplementation("SecretKeyFactory","PBKDF2WITHBLAKE2B-512",PREFIX+"BLAKE2B_512",generalKDFAttributes,(arg)->new PBESecretKeyFactory("BLAKE2B-512"));
//        provider.addAlgorithmImplementation("SecretKeyFactory","PBKDF2WITHBLAKE2S-256",PREFIX+"BLAKE2S_256",generalKDFAttributes,(arg)->new PBESecretKeyFactory("BLAKE2s-256"));

        provider.addAlgorithmImplementation("SecretKeyFactory", "PBKDF2WITHHMACSM3", PREFIX + "SM3", generalKDFAttributes, (arg) -> new PBESecretKeyFactory("SM3"));
        provider.addAlgorithmImplementation("SecretKeyFactory", "PBKDF2WITHHMACMD5", PREFIX + "MD5", generalKDFAttributes, (arg) -> new PBESecretKeyFactory("MD5"));
        provider.addAlgorithmImplementation("SecretKeyFactory", "PBKDF2WITHHMACMD5-SHA1", PREFIX + "MD5_SHA1", generalKDFAttributes, (arg) -> new PBESecretKeyFactory("MD5-SHA1"));
        provider.addAlgorithmImplementation("SecretKeyFactory", "PBKDF2WITHHMACRIPEMD160", PREFIX + "RIPEMD160", generalKDFAttributes, (arg) -> new PBESecretKeyFactory("RIPEMD160"));

    }
}
