/*
 *  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider.fips;

import org.openssl.jostle.jcajce.provider.mldsa.MLDSAKeyFactorySpiImpl;
import org.openssl.jostle.jcajce.provider.mldsa.MLDSAKeyPairGeneratorImpl;
import org.openssl.jostle.jcajce.provider.mldsa.MLDSASignatureSpi;
import org.openssl.jostle.jcajce.spec.OSSLKeyType;
import org.openssl.jostle.jcajce.spec.MLDSAParameterSpec;
import org.openssl.jostle.util.asn1.oids.NISTObjectIdentifiers;

import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * ML-DSA registrations for the FIPS provider, mirroring ProvMLDSA's surface
 * bound to the FIPS interface library.
 *
 * <p><b>Registered only when the loaded module serves the family.</b> The two
 * supported modules disagree, and it is a module-VERSION difference rather
 * than a fipsinstall configuration one - measured with real operations under
 * both the -pedantic and the default config
 * (fips-c-review/probes/pqc_op_probe.c):
 *
 * <pre>
 *   3.1.2 : keymgmt fetch = 0  -&gt; nothing registered
 *   3.5.7 : keymgmt fetch = 1  -&gt; full keygen / sign / verify, both configs
 * </pre>
 *
 * <p>Because the fetch answers it completely, this is a registration-time gate
 * rather than a use-time refusal: a caller gets {@code NoSuchAlgorithmException}
 * from {@code getInstance} and can fall through to another provider, instead of
 * an opaque failure at first use. See {@code FIPSCapabilities} for the scoping
 * rule and why no failure classifier is needed here (unlike DSA generation).
 *
 * <p>This is <b>capability</b> filtering, not <b>approval</b> filtering:
 * JSLFIPS serves what the module serves, and the compliance determination
 * belongs to the operator.
 */
class ProvFIPSMLDSA
{

    /** A KeyFactory bound to the FIPS interface library, for the Signature SPIs. */
    private static MLDSAKeyFactorySpiImpl fipsMLDSAKeyFactory()
    {
        return new MLDSAKeyFactorySpiImpl(FIPSNISelector.MLDSAServiceNI, FIPSNISelector.SpecNI,
                FIPSNISelector.Asn1NI);
    }

    private static final String PREFIX = "org.openssl.jostle.jcajce.provider.mldsa.";

    private static final Logger LOG = Logger.getLogger(ProvFIPSMLDSA.class.getName());


    public void configure(final JostleFIPSProvider provider)
    {
        if (!FIPSCapabilities.canFetchKeyMgmt("ML-DSA-65"))
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


    private void configureMLDSA(final JostleFIPSProvider provider)
    {

        final Map<String, String> mldsaKeyGenAttr = new HashMap<String, String>();

        provider.addAlgorithmImplementation("KeyPairGenerator", "MLDSA", PREFIX + "MLDSAKeyPairGenerator", mldsaKeyGenAttr, (arg) -> new MLDSAKeyPairGeneratorImpl(FIPSNISelector.MLDSAServiceNI, FIPSNISelector.SpecNI, "ML-DSA"));
        provider.addAlias("KeyPairGenerator", "MLDSA", "ML-DSA");
        provider.addAlgorithmImplementation("KeyPairGenerator", "ML-DSA-44", PREFIX + "MLDSAKeyPairGenerator$MLDSA44", mldsaKeyGenAttr, (arg) -> new MLDSAKeyPairGeneratorImpl(FIPSNISelector.MLDSAServiceNI, FIPSNISelector.SpecNI, MLDSAParameterSpec.ml_dsa_44));
        provider.addAlgorithmImplementation("KeyPairGenerator", "ML-DSA-65", PREFIX + "MLDSAKeyPairGenerator$MLDSA65", mldsaKeyGenAttr, (arg) -> new MLDSAKeyPairGeneratorImpl(FIPSNISelector.MLDSAServiceNI, FIPSNISelector.SpecNI, MLDSAParameterSpec.ml_dsa_65));
        provider.addAlgorithmImplementation("KeyPairGenerator", "ML-DSA-87", PREFIX + "MLDSAKeyPairGenerator$MLDSA87", mldsaKeyGenAttr, (arg) -> new MLDSAKeyPairGeneratorImpl(FIPSNISelector.MLDSAServiceNI, FIPSNISelector.SpecNI, MLDSAParameterSpec.ml_dsa_87));


        final Map<String, String> mldsaSigAttr = new HashMap<>();

        provider.addAlgorithmImplementation("Signature", "MLDSA", PREFIX + "MLDSASignatureSpi$MLDSA", mldsaSigAttr, (arg) -> new MLDSASignatureSpi(FIPSNISelector.MLDSAServiceNI, fipsMLDSAKeyFactory(), OSSLKeyType.NONE, MLDSASignatureSpi.MuHandling.INTERNAL));
        provider.addAlias("Signature", "MLDSA", "ML-DSA");

        provider.addAlgorithmImplementation("Signature", "ML-DSA-44", PREFIX + "MLDSASignatureSpi$MLDSA44", mldsaSigAttr, (arg) -> new MLDSASignatureSpi(FIPSNISelector.MLDSAServiceNI, fipsMLDSAKeyFactory(), OSSLKeyType.ML_DSA_44, MLDSASignatureSpi.MuHandling.INTERNAL));
        provider.addAlgorithmImplementation("Signature", "ML-DSA-65", PREFIX + "MLDSASignatureSpi$MLDSA65", mldsaSigAttr, (arg) -> new MLDSASignatureSpi(FIPSNISelector.MLDSAServiceNI, fipsMLDSAKeyFactory(), OSSLKeyType.ML_DSA_65, MLDSASignatureSpi.MuHandling.INTERNAL));
        provider.addAlgorithmImplementation("Signature", "ML-DSA-87", PREFIX + "MLDSASignatureSpi$MLDSA87", mldsaSigAttr, (arg) -> new MLDSASignatureSpi(FIPSNISelector.MLDSAServiceNI, fipsMLDSAKeyFactory(), OSSLKeyType.ML_DSA_87, MLDSASignatureSpi.MuHandling.INTERNAL));
        provider.addAlgorithmImplementation("Signature", "ML-DSA-EXTERNAL-MU", PREFIX + "MLDSASignatureSpi$MLDSAExternalMu", mldsaSigAttr, (arg) -> new MLDSASignatureSpi(FIPSNISelector.MLDSAServiceNI, fipsMLDSAKeyFactory(), OSSLKeyType.NONE, MLDSASignatureSpi.MuHandling.EXTERNAL_MU));
        provider.addAlgorithmImplementation("Signature", "ML-DSA-CALCULATE-MU", PREFIX + "MLDSASignatureSpi$MLDSACalculateMu", mldsaSigAttr, (arg) -> new MLDSASignatureSpi(FIPSNISelector.MLDSAServiceNI, fipsMLDSAKeyFactory(), OSSLKeyType.NONE, MLDSASignatureSpi.MuHandling.CALCULATE_MU));

        // SPKI / signature-algorithm OID aliases (NIST CSOR id-ml-dsa-44/65/87).
        // Required so X.509 certs whose SubjectPublicKeyInfo / signature carries
        // the OID resolve to the JSL Signature, rather than falling back to the
        // JDK default.
        provider.addAlias("Signature", "ML-DSA-44", NISTObjectIdentifiers.id_ml_dsa_44);
        provider.addAlias("Signature", "ML-DSA-65", NISTObjectIdentifiers.id_ml_dsa_65);
        provider.addAlias("Signature", "ML-DSA-87", NISTObjectIdentifiers.id_ml_dsa_87);


        final Map<String, String> mldsaKfAttr = new HashMap<>();
        provider.addAlgorithmImplementation("KeyFactory", "MLDSA", PREFIX + "MLDSAKeyFactorySpi", mldsaKfAttr, (arg) -> new MLDSAKeyFactorySpiImpl(FIPSNISelector.MLDSAServiceNI, FIPSNISelector.SpecNI, FIPSNISelector.Asn1NI));
        provider.addAlias("KeyFactory", "MLDSA", "ML-DSA");
        provider.addAlgorithmImplementation("KeyFactory", "ML-DSA-44", PREFIX + "MLDSAKeyFactorySpi$MLDSA44", mldsaKfAttr, (arg) -> new MLDSAKeyFactorySpiImpl(FIPSNISelector.MLDSAServiceNI, FIPSNISelector.SpecNI, FIPSNISelector.Asn1NI, OSSLKeyType.ML_DSA_44));
        provider.addAlgorithmImplementation("KeyFactory", "ML-DSA-65", PREFIX + "MLDSAKeyFactorySpi$MLDSA65", mldsaKfAttr, (arg) -> new MLDSAKeyFactorySpiImpl(FIPSNISelector.MLDSAServiceNI, FIPSNISelector.SpecNI, FIPSNISelector.Asn1NI, OSSLKeyType.ML_DSA_65));
        provider.addAlgorithmImplementation("KeyFactory", "ML-DSA-87", PREFIX + "MLDSAKeyFactorySpi$MLDSA87", mldsaKfAttr, (arg) -> new MLDSAKeyFactorySpiImpl(FIPSNISelector.MLDSAServiceNI, FIPSNISelector.SpecNI, FIPSNISelector.Asn1NI, OSSLKeyType.ML_DSA_87));

        // SPKI OID aliases (NIST CSOR id-ml-dsa-44/65/87) so a certificate's
        // public key can be re-derived through the JSL KeyFactory keyed on the
        // SubjectPublicKeyInfo algorithm OID (see JSLKeyX509Certificate).
        provider.addAlias("KeyFactory", "ML-DSA-44", NISTObjectIdentifiers.id_ml_dsa_44);
        provider.addAlias("KeyFactory", "ML-DSA-65", NISTObjectIdentifiers.id_ml_dsa_65);
        provider.addAlias("KeyFactory", "ML-DSA-87", NISTObjectIdentifiers.id_ml_dsa_87);


    }


}
