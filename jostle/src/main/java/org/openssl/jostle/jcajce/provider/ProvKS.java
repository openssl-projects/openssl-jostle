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

        // Bare PKCS12 = Jostle's modern default (AES-256/AES-128 + HMAC-SHA256);
        // BCPKCS12 / PKCS12-DEF resolve to the same. BouncyCastle's legacy
        // RC2-cert default is not reproduced (default-provider algorithms only).
        provider.addAlgorithmImplementation("KeyStore", "PKCS12", PREFIX + "KSServiceSPI", attr, (arg) -> new KSServiceSPI());
        provider.addAlias("KeyStore", "PKCS12", "PKCS#12", "P12", "BCPKCS12", "PKCS12-DEF");

        // BC-parity named profiles (default-provider algorithms only). The
        // -DEF- variants are aliases since Jostle resolves through a single
        // OpenSSL provider.
        provider.addAlgorithmImplementation("KeyStore", "PKCS12-3DES-3DES", PREFIX + "KSServiceSPI$PKCS12_3DES_3DES", attr, (arg) -> new KSServiceSPI.PKCS12_3DES_3DES());
        provider.addAlias("KeyStore", "PKCS12-3DES-3DES", "PKCS12-DEF-3DES-3DES");

        provider.addAlgorithmImplementation("KeyStore", "PKCS12-AES256-AES128", PREFIX + "KSServiceSPI$PKCS12_AES256_AES128", attr, (arg) -> new KSServiceSPI.PKCS12_AES256_AES128());
        provider.addAlias("KeyStore", "PKCS12-AES256-AES128", "PKCS12-DEF-AES256-AES128");

        provider.addAlgorithmImplementation("KeyStore", "PKCS12-PBMAC1", PREFIX + "KSServiceSPI$PKCS12_PBMAC1", attr, (arg) -> new KSServiceSPI.PKCS12_PBMAC1());

        // BouncyCastle's PKCS12-AES256-AES128-GCM is intentionally NOT offered:
        // OpenSSL's PKCS#12 PBES2 path does not support AES-GCM key/cert
        // encryption (PKCS12_add_key_ex with a GCM cipher fails to encrypt), so
        // Jostle can neither write nor read a GCM-encrypted keystore. BC uses
        // its own PBES2-GCM implementation; Jostle delegates to OpenSSL.
    }
}
