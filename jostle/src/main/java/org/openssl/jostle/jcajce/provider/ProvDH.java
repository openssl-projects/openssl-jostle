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

import org.openssl.jostle.jcajce.provider.dh.DHAlgorithmParameterGenerator;
import org.openssl.jostle.jcajce.provider.dh.DHAlgorithmParameters;
import org.openssl.jostle.jcajce.provider.dh.DHKeyAgreementSpi;
import org.openssl.jostle.jcajce.provider.dh.DHKeyFactorySpi;
import org.openssl.jostle.jcajce.provider.dh.DHKeyPairGenerator;
import org.openssl.jostle.jcajce.provider.dh.DHWithKDFKeyAgreementSpi;

import java.util.HashMap;
import java.util.Map;

class ProvDH
{
    private static final String PREFIX = ProvDH.class.getPackage().getName() + ".dh.";

    /**
     * PKCS#3 dhKeyAgreement OID — the algorithm identifier in X.509
     * SubjectPublicKeyInfo and PKCS#8 PrivateKeyInfo for DH keys as
     * OpenSSL emits them.
     */
    private static final String PKCS3_DH_OID = "1.2.840.113549.1.3.1";

    /**
     * X9.42 dhpublicnumber OID — the X9.42/RFC 2631 form some stacks
     * (CMS key agreement) use for DH SPKIs.
     */
    private static final String X942_DH_OID = "1.2.840.10046.2.1";

    /**
     * CMS key-agreement-with-KDF OIDs (RFC 3370 / RFC 2631). Both map to the
     * X9.42 SHA-1 KDF over the DH shared secret ({@code DHwithRFC2631KDF});
     * ESDH is ephemeral-static, SSDH static-static — the KDF is identical.
     */
    private static final String ID_ALG_ESDH = "1.2.840.113549.1.9.16.3.5";
    private static final String ID_ALG_SSDH = "1.2.840.113549.1.9.16.3.10";


    public void configure(final JostleProvider provider)
    {
        final Map<String, String> attr = new HashMap<>();
        attr.put("SupportedKeyClasses",
                "javax.crypto.interfaces.DHPublicKey|javax.crypto.interfaces.DHPrivateKey");
        attr.put("SupportedKeyFormats", "PKCS#8|X.509");

        // "DiffieHellman" is the JCA standard name; "DH" the universal
        // alias — register DH primary with DiffieHellman aliased, the
        // same orientation SunJCE uses in reverse. Lookups are
        // case-insensitive so both spellings resolve either way.
        provider.addAlgorithmImplementation("KeyPairGenerator", "DH",
                PREFIX + "DHKeyPairGenerator", attr,
                (arg) -> new DHKeyPairGenerator());
        provider.addAlias("KeyPairGenerator", "DH",
                "DiffieHellman", PKCS3_DH_OID, X942_DH_OID);

        provider.addAlgorithmImplementation("KeyFactory", "DH",
                PREFIX + "DHKeyFactorySpi", attr,
                (arg) -> new DHKeyFactorySpi());
        provider.addAlias("KeyFactory", "DH",
                "DiffieHellman", PKCS3_DH_OID, X942_DH_OID);

        // AlgorithmParameters DH — PKCS#3 DHParameter codec delegated
        // to the platform (SunJCE).
        provider.addAlgorithmImplementation("AlgorithmParameters", "DH",
                PREFIX + "DHAlgorithmParameters", new HashMap<>(),
                (arg) -> new DHAlgorithmParameters());
        provider.addAlias("AlgorithmParameters", "DH",
                "DiffieHellman", PKCS3_DH_OID);

        // AlgorithmParameterGenerator DH — native safe-prime paramgen.
        provider.addAlgorithmImplementation("AlgorithmParameterGenerator", "DH",
                PREFIX + "DHAlgorithmParameterGenerator", new HashMap<>(),
                (arg) -> new DHAlgorithmParameterGenerator());
        provider.addAlias("AlgorithmParameterGenerator", "DH", "DiffieHellman");

        provider.addAlgorithmImplementation("KeyAgreement", "DH",
                PREFIX + "DHKeyAgreementSpi", attr,
                (arg) -> new DHKeyAgreementSpi());
        provider.addAlias("KeyAgreement", "DH",
                "DiffieHellman", PKCS3_DH_OID);

        // CMS key agreement with the X9.42/RFC 2631 KDF (DHwithRFC2631KDF,
        // SHA-1). id-alg-ESDH and id-alg-SSDH both resolve here so
        // KeyAgreeRecipientInfo for finite-field DH works.
        provider.addAlgorithmImplementation("KeyAgreement", "DHWITHRFC2631KDF",
                PREFIX + "DHWithKDFKeyAgreementSpi", attr,
                (arg) -> new DHWithKDFKeyAgreementSpi("SHA-1"));
        provider.addAlias("KeyAgreement", "DHWITHRFC2631KDF",
                ID_ALG_ESDH, ID_ALG_SSDH);
    }
}
