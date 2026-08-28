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
import org.openssl.jostle.jcajce.spec.MLDSAParameterSpec;
import org.openssl.jostle.jcajce.spec.OSSLKeyType;
import org.openssl.jostle.util.asn1.oids.NISTObjectIdentifiers;

import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

class ProvMLDSA
{

    private static final String PREFIX = ProvMLDSA.class.getPackage().getName() + ".mldsa.";

    private static final Logger LOG = Logger.getLogger(ProvMLDSA.class.getName());


    public void configure(final JostleProvider provider)
    {
        // Gate: ML-DSA needs OpenSSL 3.5 or later. See Capabilities.
        if (!Capabilities.canFetchKeyMgmt("ML-DSA-65"))
        {
            return;
        }

        // Fail soft: a failure registering the ML-DSA algorithms must not abort
        // JostleProvider's static initialization, which would take the whole
        // provider down with an ExceptionInInitializerError (never retried for
        // the life of the JVM). Log it and let the other Prov* classes register.
        try
        {
            configureMLDSA(provider);
        }
        catch (Throwable t)
        {
            LOG.log(Level.WARNING, "ML-DSA provider registration failed; ML-DSA algorithms will be unavailable", t);
        }
    }


    private void configureMLDSA(final JostleProvider provider)
    {

        final Map<String, String> mldsaKeyGenAttr = new HashMap<String, String>();

        provider.addAlgorithmImplementation("KeyPairGenerator", "MLDSA", PREFIX + "MLDSAKeyPairGenerator", mldsaKeyGenAttr, (arg) -> keyPairGenerator(provider, "ML-DSA"));
        provider.addAlias("KeyPairGenerator", "MLDSA", "ML-DSA");
        provider.addAlgorithmImplementation("KeyPairGenerator", "ML-DSA-44", PREFIX + "MLDSAKeyPairGenerator$MLDSA44", mldsaKeyGenAttr, (arg) -> keyPairGenerator(provider, MLDSAParameterSpec.ml_dsa_44));
        provider.addAlgorithmImplementation("KeyPairGenerator", "ML-DSA-65", PREFIX + "MLDSAKeyPairGenerator$MLDSA65", mldsaKeyGenAttr, (arg) -> keyPairGenerator(provider, MLDSAParameterSpec.ml_dsa_65));
        provider.addAlgorithmImplementation("KeyPairGenerator", "ML-DSA-87", PREFIX + "MLDSAKeyPairGenerator$MLDSA87", mldsaKeyGenAttr, (arg) -> keyPairGenerator(provider, MLDSAParameterSpec.ml_dsa_87));


        final Map<String, String> mldsaSigAttr = new HashMap<>();

        provider.addAlgorithmImplementation("Signature", "MLDSA", PREFIX + "MLDSASignatureSpi$MLDSA", mldsaSigAttr, (arg) -> signature(provider, OSSLKeyType.NONE, MLDSASignatureSpi.MuHandling.INTERNAL));
        provider.addAlias("Signature", "MLDSA", "ML-DSA");

        provider.addAlgorithmImplementation("Signature", "ML-DSA-44", PREFIX + "MLDSASignatureSpi$MLDSA44", mldsaSigAttr, (arg) -> signature(provider, OSSLKeyType.ML_DSA_44, MLDSASignatureSpi.MuHandling.INTERNAL));
        provider.addAlgorithmImplementation("Signature", "ML-DSA-65", PREFIX + "MLDSASignatureSpi$MLDSA65", mldsaSigAttr, (arg) -> signature(provider, OSSLKeyType.ML_DSA_65, MLDSASignatureSpi.MuHandling.INTERNAL));
        provider.addAlgorithmImplementation("Signature", "ML-DSA-87", PREFIX + "MLDSASignatureSpi$MLDSA87", mldsaSigAttr, (arg) -> signature(provider, OSSLKeyType.ML_DSA_87, MLDSASignatureSpi.MuHandling.INTERNAL));
        provider.addAlgorithmImplementation("Signature", "ML-DSA-EXTERNAL-MU", PREFIX + "MLDSASignatureSpi$MLDSAExternalMu", mldsaSigAttr, (arg) -> signature(provider, OSSLKeyType.NONE, MLDSASignatureSpi.MuHandling.EXTERNAL_MU));
        provider.addAlgorithmImplementation("Signature", "ML-DSA-CALCULATE-MU", PREFIX + "MLDSASignatureSpi$MLDSACalculateMu", mldsaSigAttr, (arg) -> signature(provider, OSSLKeyType.NONE, MLDSASignatureSpi.MuHandling.CALCULATE_MU));

        // SPKI / signature-algorithm OID aliases (NIST CSOR id-ml-dsa-44/65/87).
        // Required so X.509 certs whose SubjectPublicKeyInfo / signature carries
        // the OID resolve to the JSL Signature, rather than falling back to the
        // JDK default.
        provider.addAlias("Signature", "ML-DSA-44", NISTObjectIdentifiers.id_ml_dsa_44);
        provider.addAlias("Signature", "ML-DSA-65", NISTObjectIdentifiers.id_ml_dsa_65);
        provider.addAlias("Signature", "ML-DSA-87", NISTObjectIdentifiers.id_ml_dsa_87);


        final Map<String, String> mldsaKfAttr = new HashMap<>();
        provider.addAlgorithmImplementation("KeyFactory", "MLDSA", PREFIX + "MLDSAKeyFactorySpi", mldsaKfAttr, (arg) -> keyFactory(provider, OSSLKeyType.NONE));
        provider.addAlias("KeyFactory", "MLDSA", "ML-DSA");
        provider.addAlgorithmImplementation("KeyFactory", "ML-DSA-44", PREFIX + "MLDSAKeyFactorySpi$MLDSA44", mldsaKfAttr, (arg) -> keyFactory(provider, OSSLKeyType.ML_DSA_44));
        provider.addAlgorithmImplementation("KeyFactory", "ML-DSA-65", PREFIX + "MLDSAKeyFactorySpi$MLDSA65", mldsaKfAttr, (arg) -> keyFactory(provider, OSSLKeyType.ML_DSA_65));
        provider.addAlgorithmImplementation("KeyFactory", "ML-DSA-87", PREFIX + "MLDSAKeyFactorySpi$MLDSA87", mldsaKfAttr, (arg) -> keyFactory(provider, OSSLKeyType.ML_DSA_87));

        // SPKI OID aliases (NIST CSOR id-ml-dsa-44/65/87) so a certificate's
        // public key can be re-derived through the JSL KeyFactory keyed on the
        // SubjectPublicKeyInfo algorithm OID (see JSLKeyX509Certificate).
        provider.addAlias("KeyFactory", "ML-DSA-44", NISTObjectIdentifiers.id_ml_dsa_44);
        provider.addAlias("KeyFactory", "ML-DSA-65", NISTObjectIdentifiers.id_ml_dsa_65);
        provider.addAlias("KeyFactory", "ML-DSA-87", NISTObjectIdentifiers.id_ml_dsa_87);


    }

    /**
     * A KeyFactory bound to {@code provider}. Every key it produces, and every
     * key it accepts, belongs to that provider INSTANCE (MT-14).
     */
    private static MLDSAKeyFactorySpiImpl keyFactory(JostleProvider provider, OSSLKeyType keyType)
    {
        return new MLDSAKeyFactorySpiImpl(NISelector.MLDSAServiceNI, NISelector.SpecNI,
                NISelector.Asn1NI, keyType, provider);
    }

    /**
     * Key factory UNFORCED, {@code forcedType} enforced by the SPI — matching
     * {@code ProvFIPSMLDSA}. A forced factory rejects a foreign
     * wrong-parameter key during import, pre-empting the SPI's more specific
     * message and covering fewer keys. One enforcement point, one message.
     */
    private static MLDSASignatureSpi signature(JostleProvider provider, OSSLKeyType forcedType,
                                               MLDSASignatureSpi.MuHandling forcedMu)
    {
        return new MLDSASignatureSpi(NISelector.MLDSAServiceNI,
                keyFactory(provider, OSSLKeyType.NONE), forcedType, forcedMu);
    }

    private static MLDSAKeyPairGeneratorImpl keyPairGenerator(JostleProvider provider, Object algorithm)
    {
        return new MLDSAKeyPairGeneratorImpl(NISelector.MLDSAServiceNI, NISelector.SpecNI,
                algorithm, provider);
    }
}
