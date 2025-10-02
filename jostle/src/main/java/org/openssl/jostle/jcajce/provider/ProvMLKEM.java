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

import org.openssl.jostle.jcajce.provider.mlkem.MLKEMKeyFactorySpi;
import org.openssl.jostle.jcajce.provider.mlkem.MLKEMKeyGenerator;
import org.openssl.jostle.jcajce.provider.mlkem.MLKEMKeyPairGenerator;
import org.openssl.jostle.jcajce.spec.MLKEMParameterSpec;
import org.openssl.jostle.jcajce.spec.OSSLKeyType;

import java.util.HashMap;
import java.util.Map;

class ProvMLKEM
{

    private static final String PREFIX = ProvMLKEM.class.getPackage().getName() + ".mlkem.";


    public void configure(final JostleProvider provider)
    {
        configureMLKEM(provider);
    }


    private void configureMLKEM(final JostleProvider provider)
    {

        final Map<String, String> MLKEMKeyGenAttr = new HashMap<String, String>();

        provider.addAlgorithmImplementation("KeyPairGenerator", "MLKEM", PREFIX + "MLKEMKeyPairGenerator", MLKEMKeyGenAttr, (arg) -> new MLKEMKeyPairGenerator("ML-KEM"));
        provider.addAlias("KeyPairGenerator", "MLKEM", "ML-KEM");
        provider.addAlgorithmImplementation("KeyPairGenerator", "ML-KEM-512", PREFIX + "MLKEMKeyPairGenerator$MLKEM512", MLKEMKeyGenAttr, (arg) -> new MLKEMKeyPairGenerator("ML-KEM-512"));
        provider.addAlgorithmImplementation("KeyPairGenerator", "ML-KEM-768", PREFIX + "MLKEMKeyPairGenerator$MLKEM768", MLKEMKeyGenAttr, (arg) -> new MLKEMKeyPairGenerator("ML-KEM-768"));
        provider.addAlgorithmImplementation("KeyPairGenerator", "ML-KEM-1024", PREFIX + "MLKEMKeyPairGenerator$MLKEM1024", MLKEMKeyGenAttr, (arg) -> new MLKEMKeyPairGenerator("ML-KEM-1024"));


        final Map<String, String> mlkemCipherAttr = new HashMap<>();

        provider.addAlgorithmImplementation("KeyGenerator", "MLKEM", PREFIX + "Base", mlkemCipherAttr, (arg) -> new MLKEMKeyGenerator());
        provider.addAlias("KeyGenerator", "MLKEM", "ML-KEM");

        provider.addAlgorithmImplementation("KeyGenerator", "ML-KEM-512", PREFIX + "MLKEM512", mlkemCipherAttr, (arg) -> new MLKEMKeyGenerator(MLKEMParameterSpec.ml_kem_512));
        provider.addAlgorithmImplementation("KeyGenerator", "ML-KEM-768", PREFIX + "MLKEM768", mlkemCipherAttr, (arg) -> new MLKEMKeyGenerator(MLKEMParameterSpec.ml_kem_768));
        provider.addAlgorithmImplementation("KeyGenerator", "ML-KEM-1024", PREFIX + "MLKEM1024", mlkemCipherAttr, (arg) -> new MLKEMKeyGenerator(MLKEMParameterSpec.ml_kem_1024));

        final Map<String, String> MLKEMKfAttr = new HashMap<>();
        provider.addAlgorithmImplementation("KeyFactory", "MLKEM", PREFIX + "MLKEMKeyFactorySpi", MLKEMKfAttr, (arg) -> new MLKEMKeyFactorySpi());
        provider.addAlias("KeyFactory", "MLKEM", "ML-KEM");
        provider.addAlgorithmImplementation("KeyFactory", "ML-KEM-512", PREFIX + "MLKEMKeyFactorySpi$MLKEM512", MLKEMKfAttr, (arg) -> new MLKEMKeyFactorySpi(OSSLKeyType.ML_KEM_512));
        provider.addAlgorithmImplementation("KeyFactory", "ML-KEM-768", PREFIX + "MLKEMKeyFactorySpi$MLKEM768", MLKEMKfAttr, (arg) -> new MLKEMKeyFactorySpi(OSSLKeyType.ML_KEM_768));
        provider.addAlgorithmImplementation("KeyFactory", "ML-KEM-1024", PREFIX + "MLKEMKeyFactorySpi$MLKEM1024", MLKEMKfAttr, (arg) -> new MLKEMKeyFactorySpi(OSSLKeyType.ML_KEM_1024));

    }


}
