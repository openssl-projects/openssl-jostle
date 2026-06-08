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
    private static final String PREFIX = ProvSLHDSA.class.getPackage().getName() + ".slhdsa.";

    public void configure(final JostleProvider provider)
    {
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
        provider.addAlgorithmImplementation("KeyPairGenerator", "SLHDSA", PREFIX + "SLHDSAKeyPairGenerator", slhdsaKeyGenAttr, (arg) -> new SLHDSAKeyPairGenerator("SLH-DSA"));
        provider.addAlias("KeyPairGenerator", "SLHDSA", "SLH-DSA");

        provider.addAlgorithmImplementation("KeyFactory", "SLHDSA", PREFIX + "SLHDSAKeyFactory", slhdsaKeyGenAttr, (arg) -> new SLHDSAKeyFactorySpi(OSSLKeyType.NONE));
        provider.addAlias("KeyFactory", "SLHDSA", "SLH-DSA");


        SLHDSAParameterSpec.getParameterNames().forEach(name ->
        {
            provider.addAlgorithmImplementation("KeyPairGenerator", name, PREFIX + "SLHDSAKeyPairGeneratorSpi$" + name.replace("-", "_"), slhdsaKeyGenAttr, (arg) -> new SLHDSAKeyPairGenerator(name));
            provider.addAlgorithmImplementation("KeyFactory", name, PREFIX + "SLHDSAKeyFactorySpi$" + name.replace("-", "_"), slhdsaKeyGenAttr, (arg) -> new SLHDSAKeyFactorySpi(SLHDSAParameterSpec.fromName(name).getKeyType()));
        });

        final Map<String, String> slhdsaSigAttr = new HashMap<String, String>();

        provider.addAlgorithmImplementation("Signature", "SLHDSA", PREFIX + "SLHDSASignatureSpi$SLHDSA", slhdsaSigAttr, (arg) -> new SLHDSASignatureSpi());
        provider.addAlias("Signature", "SLHDSA", "SLH-DSA");

        provider.addAlgorithmImplementation("Signature", "SLH-DSA-PURE", PREFIX + "SLHDSASignatureSpi$SLHDSA_Pure", slhdsaSigAttr, (arg) -> new SLHDSASignatureSpi(SLHDSASignatureSpi.MessageEncoding.PURE, SLHDSASignatureSpi.Deterministic.NON_DETERMINISTIC));
        provider.addAlgorithmImplementation("Signature", "SLH-DSA-NONE", PREFIX + "SLHDSASignatureSpi$SLHDSA_None", slhdsaSigAttr, (arg) -> new SLHDSASignatureSpi(SLHDSASignatureSpi.MessageEncoding.NONE, SLHDSASignatureSpi.Deterministic.NON_DETERMINISTIC));

        provider.addAlgorithmImplementation("Signature", "DET-SLH-DSA-PURE", PREFIX + "SLHDSASignatureSpi$SLHDSADetPure", slhdsaSigAttr, (arg) -> new SLHDSASignatureSpi(SLHDSASignatureSpi.MessageEncoding.PURE, SLHDSASignatureSpi.Deterministic.DETERMINISTIC));
        provider.addAlgorithmImplementation("Signature", "DET-SLH-DSA-NONE", PREFIX + "SLHDSASignatureSpi$SLHDSADetNone", slhdsaSigAttr, (arg) -> new SLHDSASignatureSpi(SLHDSASignatureSpi.MessageEncoding.NONE, SLHDSASignatureSpi.Deterministic.DETERMINISTIC));


        for (String algName : algNames)
        {
            provider.addAlgorithmImplementation("Signature", algName, PREFIX + "SLHDSASignatureSpi$" + algName.replace("-", "_"), slhdsaSigAttr, (arg) -> new SLHDSASignatureSpi(SLHDSAParameterSpec.fromName(algName).getKeyType()));
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
}