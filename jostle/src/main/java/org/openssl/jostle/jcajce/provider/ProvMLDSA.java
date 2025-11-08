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

import org.openssl.jostle.jcajce.provider.mldsa.MLDSAKeyFactorySpiImpl;
import org.openssl.jostle.jcajce.provider.mldsa.MLDSAKeyPairGeneratorImpl;
import org.openssl.jostle.jcajce.provider.mldsa.MLDSASignatureSpi;
import org.openssl.jostle.jcajce.spec.OSSLKeyType;

import java.util.HashMap;
import java.util.Map;

class ProvMLDSA
{

    private static final String PREFIX = ProvMLDSA.class.getPackage().getName() + ".mldsa.";


    public void configure(final JostleProvider provider)
    {
        configureMLDSA(provider);
    }


    private void configureMLDSA(final JostleProvider provider)
    {

        final Map<String, String> mldsaKeyGenAttr = new HashMap<String, String>();

        provider.addAlgorithmImplementation("KeyPairGenerator", "MLDSA", PREFIX + "MLDSAKeyPairGenerator", mldsaKeyGenAttr, (arg) -> new MLDSAKeyPairGeneratorImpl("ML-DSA"));
        provider.addAlias("KeyPairGenerator", "MLDSA", "ML-DSA");
        provider.addAlgorithmImplementation("KeyPairGenerator", "ML-DSA-44", PREFIX + "MLDSAKeyPairGenerator$MLDSA44", mldsaKeyGenAttr, (arg) -> new MLDSAKeyPairGeneratorImpl.MLDSA44());
        provider.addAlgorithmImplementation("KeyPairGenerator", "ML-DSA-65", PREFIX + "MLDSAKeyPairGenerator$MLDSA65", mldsaKeyGenAttr, (arg) -> new MLDSAKeyPairGeneratorImpl.MLDSA65());
        provider.addAlgorithmImplementation("KeyPairGenerator", "ML-DSA-87", PREFIX + "MLDSAKeyPairGenerator$MLDSA87", mldsaKeyGenAttr, (arg) -> new MLDSAKeyPairGeneratorImpl.MLDSA87());



        final Map<String, String> mldsaSigAttr = new HashMap<>();

        provider.addAlgorithmImplementation("Signature", "MLDSA", PREFIX + "MLDSASignatureSpi$MLDSA", mldsaSigAttr, (arg) -> new MLDSASignatureSpi(OSSLKeyType.NONE, MLDSASignatureSpi.MuHandling.INTERNAL));
        provider.addAlias("Signature", "MLDSA", "ML-DSA");

        provider.addAlgorithmImplementation("Signature", "ML-DSA-44", PREFIX + "MLDSASignatureSpi$MLDSA44", mldsaSigAttr, (arg) -> new MLDSASignatureSpi(OSSLKeyType.ML_DSA_44, MLDSASignatureSpi.MuHandling.INTERNAL));
        provider.addAlgorithmImplementation("Signature", "ML-DSA-65", PREFIX + "MLDSASignatureSpi$MLDSA65", mldsaSigAttr, (arg) -> new MLDSASignatureSpi(OSSLKeyType.ML_DSA_65,MLDSASignatureSpi.MuHandling.INTERNAL));
        provider.addAlgorithmImplementation("Signature", "ML-DSA-87", PREFIX + "MLDSASignatureSpi$MLDSA87", mldsaSigAttr, (arg) -> new MLDSASignatureSpi(OSSLKeyType.ML_DSA_87,MLDSASignatureSpi.MuHandling.INTERNAL));
        provider.addAlgorithmImplementation("Signature", "ML-DSA-EXTERNAL-MU", PREFIX + "MLDSASignatureSpi$MLDSAExternalMu", mldsaSigAttr, (arg) -> new MLDSASignatureSpi(OSSLKeyType.NONE, MLDSASignatureSpi.MuHandling.EXTERNAL_MU));
        provider.addAlgorithmImplementation("Signature", "ML-DSA-CALCULATE-MU", PREFIX + "MLDSASignatureSpi$MLDSACalculateMu", mldsaSigAttr, (arg) -> new MLDSASignatureSpi(OSSLKeyType.NONE, MLDSASignatureSpi.MuHandling.CALCULATE_MU));


        final Map<String, String> mldsaKfAttr = new HashMap<>();
        provider.addAlgorithmImplementation("KeyFactory", "MLDSA", PREFIX + "MLDSAKeyFactorySpi", mldsaKfAttr, (arg) -> new MLDSAKeyFactorySpiImpl());
        provider.addAlias("KeyFactory", "MLDSA", "ML-DSA");
        provider.addAlgorithmImplementation("KeyFactory", "ML-DSA-44", PREFIX + "MLDSAKeyFactorySpi$MLDSA44", mldsaKfAttr, (arg) -> new MLDSAKeyFactorySpiImpl(OSSLKeyType.ML_DSA_44));
        provider.addAlgorithmImplementation("KeyFactory", "ML-DSA-65", PREFIX + "MLDSAKeyFactorySpi$MLDSA65", mldsaKfAttr, (arg) -> new MLDSAKeyFactorySpiImpl(OSSLKeyType.ML_DSA_65));
        provider.addAlgorithmImplementation("KeyFactory", "ML-DSA-87", PREFIX + "MLDSAKeyFactorySpi$MLDSA87", mldsaKfAttr, (arg) -> new MLDSAKeyFactorySpiImpl(OSSLKeyType.ML_DSA_87));




    }


}
