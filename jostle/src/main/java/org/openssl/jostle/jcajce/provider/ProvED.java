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

import org.openssl.jostle.jcajce.provider.ed.EdDSAKeyPairGenerator;
import org.openssl.jostle.jcajce.provider.ed.EdKeyFactorySpi;
import org.openssl.jostle.jcajce.provider.ed.EdSignatureSpi;
import org.openssl.jostle.jcajce.spec.EdDSAParameterSpec;
import org.openssl.jostle.jcajce.spec.OSSLKeyType;
import org.openssl.jostle.util.asn1.oids.EdECObjectIdentifiers;

import java.util.HashMap;
import java.util.Map;

class ProvED
{

    private static final String PREFIX = ProvED.class.getPackage().getName() + ".ed.";


    public void configure(final JostleProvider provider)
    {
        configureEDDSA(provider);
    }


    private void configureEDDSA(final JostleProvider provider)
    {

        final Map<String, String> attr = new HashMap<String, String>();

        provider.addAlgorithmImplementation("KeyPairGenerator", "ED", PREFIX + "EdDSAKeyPairGenerator", attr, (arg) -> keyPairGenerator(provider, "EDDSA"));
        provider.addAlias("KeyPairGenerator", "ED", "EDDSA", "EdDSA");
        provider.addAlgorithmImplementation("KeyPairGenerator", "ED25519", PREFIX + "EdDSAKeyPairGenerator$ED25519", attr, (arg) -> keyPairGenerator(provider, EdDSAParameterSpec.ED25519));
        provider.addAlias("KeyPairGenerator", "ED25519", "Ed25519");
        provider.addAlgorithmImplementation("KeyPairGenerator", "ED448", PREFIX + "EdDSAKeyPairGenerator$ED448", attr, (arg) -> keyPairGenerator(provider, EdDSAParameterSpec.ED448));
        provider.addAlias("KeyPairGenerator", "ED448", "Ed448");

        final Map<String, String> sigAttr = new HashMap<>();

        provider.addAlgorithmImplementation("Signature", "EDDSA", PREFIX + "EdSignatureSpi", sigAttr, (arg) -> signature(provider, OSSLKeyType.NONE));
        provider.addAlias("Signature", "EDDSA", "EdDSA");

        provider.addAlgorithmImplementation("Signature", "ED25519", PREFIX + "EdSignatureSpi$ED25519", sigAttr, (arg) -> signature(provider, OSSLKeyType.ED25519));
        provider.addAlias("Signature", "ED25519", "Ed25519");
        // Curve OID alias so Signature.getInstance("1.3.101.112", ...) resolves
        // (OID-keyed callers; the latent counterpart to the KeyFactory OID gap).
        provider.addAlias("Signature", "ED25519", EdECObjectIdentifiers.id_Ed25519);
        provider.addAlgorithmImplementation("Signature", "ED25519PH", PREFIX + "EdSignatureSpi$ED25519ph", sigAttr, (arg) -> signature(provider, OSSLKeyType.Ed25519ph));
        provider.addAlias("Signature", "ED25519PH", "Ed25519ph");
        provider.addAlgorithmImplementation("Signature", "ED25519CTX", PREFIX + "EdSignatureSpi$ED25519ctx", sigAttr, (arg) -> signature(provider, OSSLKeyType.Ed25519ctx));
        provider.addAlias("Signature", "ED25519CTX", "Ed25519ctx");

        provider.addAlgorithmImplementation("Signature", "ED448", PREFIX + "EdSignatureSpi$ED448", sigAttr, (arg) -> signature(provider, OSSLKeyType.ED448));
        provider.addAlias("Signature", "ED448", "Ed448");
        provider.addAlias("Signature", "ED448", EdECObjectIdentifiers.id_Ed448);
        provider.addAlgorithmImplementation("Signature", "ED448PH", PREFIX + "EdSignatureSpi$ED448ph", sigAttr, (arg) -> signature(provider, OSSLKeyType.ED448ph));
        provider.addAlias("Signature", "ED448PH", "Ed448ph");


        final Map<String, String> kfAttr = new HashMap<>();
        provider.addAlgorithmImplementation("KeyFactory", "ED", PREFIX + "EdKeyFactorySpi", kfAttr, (arg) -> keyFactory(provider, OSSLKeyType.NONE));
        provider.addAlias("KeyFactory", "ED", "EDDSA", "EdDSA");
        provider.addAlgorithmImplementation("KeyFactory", "ED25519", PREFIX + "EdKeyFactorySpi$ED25519", kfAttr, (arg) -> keyFactory(provider, OSSLKeyType.ED25519));
        provider.addAlias("KeyFactory", "ED25519", "Ed25519");
        // Curve OID alias — fixes RFC 7250 raw-public-key verification, which
        // resolves the KeyFactory by the SPKI algorithm OID rather than by name.
        provider.addAlias("KeyFactory", "ED25519", EdECObjectIdentifiers.id_Ed25519);
        provider.addAlgorithmImplementation("KeyFactory", "ED448", PREFIX + "EdKeyFactorySpi$ED448", kfAttr, (arg) -> keyFactory(provider, OSSLKeyType.ED448));
        provider.addAlias("KeyFactory", "ED448", "Ed448");
        provider.addAlias("KeyFactory", "ED448", EdECObjectIdentifiers.id_Ed448);

    }

    /**
     * A KeyFactory bound to {@code provider}. Every key it produces, and every
     * key it accepts, belongs to that provider INSTANCE (MT-14).
     */
    private static EdKeyFactorySpi keyFactory(JostleProvider provider, OSSLKeyType fixedType)
    {
        return new EdKeyFactorySpi(NISelector.EDServiceNI, NISelector.SpecNI,
                NISelector.Asn1NI, fixedType, provider);
    }

    private static EdSignatureSpi signature(JostleProvider provider, OSSLKeyType forcedType)
    {
        return new EdSignatureSpi(NISelector.EDServiceNI,
                keyFactory(provider, OSSLKeyType.NONE), forcedType);
    }

    private static EdDSAKeyPairGenerator keyPairGenerator(JostleProvider provider, Object algorithm)
    {
        return new EdDSAKeyPairGenerator(NISelector.EDServiceNI, NISelector.SpecNI,
                NISelector.Asn1NI, algorithm, provider);
    }
}
