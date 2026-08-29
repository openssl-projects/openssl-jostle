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


import org.openssl.jostle.jcajce.provider.slhdsa.SLHDSAKeyFactorySpi;
import org.openssl.jostle.jcajce.provider.slhdsa.SLHDSAKeyPairGenerator;
import org.openssl.jostle.jcajce.provider.slhdsa.SLHDSASignatureSpi;
import org.openssl.jostle.jcajce.spec.OSSLKeyType;
import org.openssl.jostle.jcajce.spec.SLHDSAParameterSpec;
import org.openssl.jostle.util.asn1.ASN1ObjectIdentifier;
import org.openssl.jostle.util.asn1.oids.NISTObjectIdentifiers;

import java.util.HashMap;
import java.util.Map;

class ProvSLHDSA
{

    public void configure(final JostleProvider provider)
    {
        // Gate: SLH-DSA needs OpenSSL 3.5 or later. See Capabilities.
        if (!Capabilities.canFetchKeyMgmt("SLH-DSA-SHA2-128S"))
        {
            return;
        }

        configureSLHDSA(provider);
    }


    private void configureSLHDSA(final JostleProvider provider)
    {

        String[] algNames = new String[]
                {
                        "SLH-DSA-SHA2-128S",
                        "SLH-DSA-SHA2-128F",
                        "SLH-DSA-SHA2-192S",
                        "SLH-DSA-SHA2-192F",
                        "SLH-DSA-SHA2-256S",
                        "SLH-DSA-SHA2-256F",
                        "SLH-DSA-SHAKE-128S",
                        "SLH-DSA-SHAKE-128F",
                        "SLH-DSA-SHAKE-192S",
                        "SLH-DSA-SHAKE-192F",
                        "SLH-DSA-SHAKE-256S",
                        "SLH-DSA-SHAKE-256F"
                };


        final Map<String, String> slhdsaKeyGenAttr = new HashMap<String, String>();
        provider.addAlgorithmImplementation("KeyPairGenerator", "SLHDSA", SLHDSAKeyPairGenerator.class.getName(), slhdsaKeyGenAttr, (arg) -> keyPairGenerator(provider, "SLH-DSA"));
        provider.addAlias("KeyPairGenerator", "SLHDSA", "SLH-DSA");

        provider.addAlgorithmImplementation("KeyFactory", "SLHDSA", SLHDSAKeyFactorySpi.class.getName(), slhdsaKeyGenAttr, (arg) -> keyFactory(provider, OSSLKeyType.NONE));
        provider.addAlias("KeyFactory", "SLHDSA", "SLH-DSA");


        SLHDSAParameterSpec.getParameterNames().forEach(name ->
        {
            provider.addAlgorithmImplementation("KeyPairGenerator", name, SLHDSAKeyPairGenerator.class.getName(), slhdsaKeyGenAttr, (arg) -> keyPairGenerator(provider, name));
            provider.addAlgorithmImplementation("KeyFactory", name, SLHDSAKeyFactorySpi.class.getName(), slhdsaKeyGenAttr, (arg) -> keyFactory(provider, SLHDSAParameterSpec.fromName(name).getKeyType()));
        });

        final Map<String, String> slhdsaSigAttr = new HashMap<String, String>();

        provider.addAlgorithmImplementation("Signature", "SLHDSA", SLHDSASignatureSpi.class.getName(), slhdsaSigAttr, (arg) -> signature(provider, OSSLKeyType.NONE,
                        SLHDSASignatureSpi.MessageEncoding.PURE,
                        SLHDSASignatureSpi.Deterministic.NON_DETERMINISTIC));
        provider.addAlias("Signature", "SLHDSA", "SLH-DSA");

        provider.addAlgorithmImplementation("Signature", "SLH-DSA-PURE", SLHDSASignatureSpi.class.getName(), slhdsaSigAttr, (arg) -> signature(provider, OSSLKeyType.NONE,
                        SLHDSASignatureSpi.MessageEncoding.PURE,
                        SLHDSASignatureSpi.Deterministic.NON_DETERMINISTIC));
        provider.addAlgorithmImplementation("Signature", "SLH-DSA-NONE", SLHDSASignatureSpi.class.getName(), slhdsaSigAttr, (arg) -> signature(provider, OSSLKeyType.NONE,
                        SLHDSASignatureSpi.MessageEncoding.NONE,
                        SLHDSASignatureSpi.Deterministic.NON_DETERMINISTIC));

        provider.addAlgorithmImplementation("Signature", "DET-SLH-DSA-PURE", SLHDSASignatureSpi.class.getName(), slhdsaSigAttr, (arg) -> signature(provider, OSSLKeyType.NONE,
                        SLHDSASignatureSpi.MessageEncoding.PURE,
                        SLHDSASignatureSpi.Deterministic.DETERMINISTIC));
        provider.addAlgorithmImplementation("Signature", "DET-SLH-DSA-NONE", SLHDSASignatureSpi.class.getName(), slhdsaSigAttr, (arg) -> signature(provider, OSSLKeyType.NONE,
                        SLHDSASignatureSpi.MessageEncoding.NONE,
                        SLHDSASignatureSpi.Deterministic.DETERMINISTIC));


        for (String algName : algNames)
        {
            provider.addAlgorithmImplementation("Signature", algName, SLHDSASignatureSpi.class.getName(), slhdsaSigAttr, (arg) -> signature(provider, SLHDSAParameterSpec.fromName(algName).getKeyType(),
                        SLHDSASignatureSpi.MessageEncoding.PURE,
                        SLHDSASignatureSpi.Deterministic.NON_DETERMINISTIC));
        }

        // SPKI / signature-algorithm OID aliases (NIST CSOR id-slh-dsa-*, RFC 9814),
        // aligned 1:1 with algNames above. Required so an X.509 certificate whose
        // SubjectPublicKeyInfo / signature carries the OID resolves to the JSL
        // KeyFactory and Signature (see JSLKeyX509Certificate), rather than falling
        // back to the JDK default.
        ASN1ObjectIdentifier[] oids = new ASN1ObjectIdentifier[]
                {
                        NISTObjectIdentifiers.id_slh_dsa_sha2_128s,
                        NISTObjectIdentifiers.id_slh_dsa_sha2_128f,
                        NISTObjectIdentifiers.id_slh_dsa_sha2_192s,
                        NISTObjectIdentifiers.id_slh_dsa_sha2_192f,
                        NISTObjectIdentifiers.id_slh_dsa_sha2_256s,
                        NISTObjectIdentifiers.id_slh_dsa_sha2_256f,
                        NISTObjectIdentifiers.id_slh_dsa_shake_128s,
                        NISTObjectIdentifiers.id_slh_dsa_shake_128f,
                        NISTObjectIdentifiers.id_slh_dsa_shake_192s,
                        NISTObjectIdentifiers.id_slh_dsa_shake_192f,
                        NISTObjectIdentifiers.id_slh_dsa_shake_256s,
                        NISTObjectIdentifiers.id_slh_dsa_shake_256f
                };

        for (int i = 0; i < algNames.length; i++)
        {
            provider.addAlias("KeyFactory", algNames[i], oids[i]);
            provider.addAlias("Signature", algNames[i], oids[i]);
        }

    }

    /**
     * A KeyFactory bound to {@code provider}. Every key it produces, and every
     * key it accepts, belongs to that provider INSTANCE (MT-14).
     */
    private static SLHDSAKeyFactorySpi keyFactory(JostleProvider provider, OSSLKeyType keyType)
    {
        return new SLHDSAKeyFactorySpi(NISelector.SLHDSAServiceNI, NISelector.SpecNI,
                NISelector.Asn1NI, keyType, provider);
    }

    private static SLHDSASignatureSpi signature(JostleProvider provider, OSSLKeyType forcedType,
                                                SLHDSASignatureSpi.MessageEncoding encoding,
                                                SLHDSASignatureSpi.Deterministic deterministic)
    {
        return new SLHDSASignatureSpi(NISelector.SLHDSAServiceNI, NISelector.SpecNI,
                forcedType, encoding, deterministic, provider);
    }

    private static SLHDSAKeyPairGenerator keyPairGenerator(JostleProvider provider, Object algorithm)
    {
        return new SLHDSAKeyPairGenerator(NISelector.SLHDSAServiceNI, NISelector.SpecNI,
                algorithm, provider);
    }
}
