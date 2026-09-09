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

        // id-PBKDF2, RFC 8018 A.2. PBES2 / PKCS#8 / PKCS#12 decryptors resolve the
        // key-derivation SecretKeyFactory by this OID rather than by name, so
        // without the alias an OID-driven caller gets NoSuchAlgorithmException
        // even though the algorithm is served.
        //
        // Spelled as a literal rather than through a constants class: the tree's
        // oids package is EXPORTED, so a new interface there is new public API,
        // and one OID does not warrant it. Matches the existing practice for
        // one-off OIDs (ProvEC's "1.3.132.1.12", ProvScryptKDF's scrypt OID).
        provider.addAlias("SecretKeyFactory", "PBKDF2", "1.2.840.113549.1.5.12");
        provider.addAlgorithmImplementation("SecretKeyFactory", "PBKDF2WITHHMACSHA1", PBKDF2SecretKeyFactory.class.getName(), generalKDFAttributes, (arg) -> new PBKDF2SecretKeyFactory("SHA-1"));
        provider.addAlgorithmImplementation("SecretKeyFactory", "PBKDF2WITHHMACSHA224", PBKDF2SecretKeyFactory.class.getName(), generalKDFAttributes, (arg) -> new PBKDF2SecretKeyFactory("SHA-224"));
        provider.addAlgorithmImplementation("SecretKeyFactory", "PBKDF2WITHHMACSHA256", PBKDF2SecretKeyFactory.class.getName(), generalKDFAttributes, (arg) -> new PBKDF2SecretKeyFactory("SHA-256"));
        provider.addAlgorithmImplementation("SecretKeyFactory", "PBKDF2WITHHMACSHA384", PBKDF2SecretKeyFactory.class.getName(), generalKDFAttributes, (arg) -> new PBKDF2SecretKeyFactory("SHA-384"));
        provider.addAlgorithmImplementation("SecretKeyFactory", "PBKDF2WITHHMACSHA512", PBKDF2SecretKeyFactory.class.getName(), generalKDFAttributes, (arg) -> new PBKDF2SecretKeyFactory("SHA-512"));

        // A distinct derivation, not an alias — see the field javadoc on
        // PBKDF2SecretKeyFactory. RFC 3211 CMS callers ask for the alias.
        provider.addAlgorithmImplementation("SecretKeyFactory", "PBKDF2WITHASCII", PBKDF2SecretKeyFactory.class.getName(), generalKDFAttributes, (arg) -> new PBKDF2SecretKeyFactory("SHA-1", true));
        provider.addAlias("SecretKeyFactory", "PBKDF2WITHASCII", "PBKDF2WITH8BIT", "PBKDF2WITHHMACSHA1AND8BIT");

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
