/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider.fips;

import org.openssl.jostle.jcajce.provider.dh.DHAlgorithmParameterGenerator;
import org.openssl.jostle.jcajce.provider.dh.DHAlgorithmParameters;
import org.openssl.jostle.jcajce.provider.dh.DHKeyAgreementSpi;
import org.openssl.jostle.jcajce.provider.dh.DHKeyFactorySpi;
import org.openssl.jostle.jcajce.provider.dh.DHKeyPairGenerator;
import org.openssl.jostle.jcajce.provider.dh.DHWithKDFKeyAgreementSpi;

import java.util.HashMap;
import java.util.Map;
import org.openssl.jostle.util.asn1.oids.PKCSObjectIdentifiers;
import org.openssl.jostle.util.asn1.oids.X9ObjectIdentifiers;

/**
 * DH registrations for the FIPS provider, mirroring ProvDH's surface bound
 * to the FIPS interface library. Group/size approval is enforced by the
 * module itself (safe-prime groups per SP 800-56A).
 */
class ProvFIPSDH
{

    private static final String PKCS3_DH_OID = PKCSObjectIdentifiers.dhKeyAgreement.getId();
    private static final String X942_DH_OID = X9ObjectIdentifiers.dhpublicnumber.getId();
    private static final String ID_ALG_ESDH = PKCSObjectIdentifiers.id_alg_ESDH.getId();
    private static final String ID_ALG_SSDH = PKCSObjectIdentifiers.id_alg_SSDH.getId();

    public void configure(final JostleFIPSProvider provider)
    {
        final Map<String, String> attr = new HashMap<>();
        attr.put("SupportedKeyClasses",
                "javax.crypto.interfaces.DHPublicKey|javax.crypto.interfaces.DHPrivateKey");
        attr.put("SupportedKeyFormats", "PKCS#8|X.509");

        provider.addAlgorithmImplementation("KeyPairGenerator", "DH",
                DHKeyPairGenerator.class.getName(), attr,
                (arg) -> new DHKeyPairGenerator(
                        FIPSNISelector.DHServiceNI, FIPSNISelector.SpecNI, FIPSNISelector.Asn1NI,
                        provider));
        provider.addAlias("KeyPairGenerator", "DH",
                "DiffieHellman", PKCS3_DH_OID, X942_DH_OID);

        provider.addAlgorithmImplementation("KeyFactory", "DH",
                DHKeyFactorySpi.class.getName(), attr,
                (arg) -> keyFactory(provider));
        provider.addAlias("KeyFactory", "DH",
                "DiffieHellman", PKCS3_DH_OID, X942_DH_OID);

        provider.addAlgorithmImplementation("AlgorithmParameters", "DH",
                DHAlgorithmParameters.class.getName(), new HashMap<>(),
                (arg) -> new DHAlgorithmParameters());
        provider.addAlias("AlgorithmParameters", "DH",
                "DiffieHellman", PKCS3_DH_OID);

        provider.addAlgorithmImplementation("AlgorithmParameterGenerator", "DH",
                DHAlgorithmParameterGenerator.class.getName(), new HashMap<>(),
                (arg) -> new DHAlgorithmParameterGenerator(
                        FIPSNISelector.DHServiceNI, FIPSNISelector.SpecNI, provider));
        provider.addAlias("AlgorithmParameterGenerator", "DH", "DiffieHellman");

        provider.addAlgorithmImplementation("KeyAgreement", "DH",
                DHKeyAgreementSpi.class.getName(), attr,
                (arg) -> new DHKeyAgreementSpi(FIPSNISelector.DHServiceNI, keyFactory(provider)));
        provider.addAlias("KeyAgreement", "DH",
                "DiffieHellman", PKCS3_DH_OID);

        provider.addAlgorithmImplementation("KeyAgreement", "DHWITHRFC2631KDF",
                DHWithKDFKeyAgreementSpi.class.getName(), attr,
                (arg) -> new DHWithKDFKeyAgreementSpi(FIPSNISelector.DHServiceNI, keyFactory(provider),
                        "SHA-1", provider));
        provider.addAlias("KeyAgreement", "DHWITHRFC2631KDF",
                ID_ALG_ESDH, ID_ALG_SSDH);
    }

    /**
     * A KeyFactory bound to {@code provider}. Every key it produces, and every
     * key it accepts, belongs to that provider INSTANCE (MT-14).
     */
    private static DHKeyFactorySpi keyFactory(JostleFIPSProvider provider)
    {
        return new DHKeyFactorySpi(
                FIPSNISelector.DHServiceNI, FIPSNISelector.SpecNI, FIPSNISelector.Asn1NI, provider);
    }
}
