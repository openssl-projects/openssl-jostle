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

/**
 * DH registrations for the FIPS provider, mirroring ProvDH's surface bound
 * to the FIPS interface library. Group/size approval is enforced by the
 * module itself (safe-prime groups per SP 800-56A).
 */
class ProvFIPSDH
{
    private static final String PREFIX = "org.openssl.jostle.jcajce.provider.dh.";

    private static final String PKCS3_DH_OID = "1.2.840.113549.1.3.1";
    private static final String X942_DH_OID = "1.2.840.10046.2.1";
    private static final String ID_ALG_ESDH = "1.2.840.113549.1.9.16.3.5";
    private static final String ID_ALG_SSDH = "1.2.840.113549.1.9.16.3.10";

    public void configure(final JostleFIPSProvider provider)
    {
        final Map<String, String> attr = new HashMap<>();
        attr.put("SupportedKeyClasses",
                "javax.crypto.interfaces.DHPublicKey|javax.crypto.interfaces.DHPrivateKey");
        attr.put("SupportedKeyFormats", "PKCS#8|X.509");

        provider.addAlgorithmImplementation("KeyPairGenerator", "DH",
                PREFIX + "DHKeyPairGenerator", attr,
                (arg) -> new DHKeyPairGenerator(
                        FIPSNISelector.DHServiceNI, FIPSNISelector.SpecNI, FIPSNISelector.Asn1NI));
        provider.addAlias("KeyPairGenerator", "DH",
                "DiffieHellman", PKCS3_DH_OID, X942_DH_OID);

        provider.addAlgorithmImplementation("KeyFactory", "DH",
                PREFIX + "DHKeyFactorySpi", attr,
                (arg) -> keyFactory());
        provider.addAlias("KeyFactory", "DH",
                "DiffieHellman", PKCS3_DH_OID, X942_DH_OID);

        provider.addAlgorithmImplementation("AlgorithmParameters", "DH",
                PREFIX + "DHAlgorithmParameters", new HashMap<>(),
                (arg) -> new DHAlgorithmParameters());
        provider.addAlias("AlgorithmParameters", "DH",
                "DiffieHellman", PKCS3_DH_OID);

        provider.addAlgorithmImplementation("AlgorithmParameterGenerator", "DH",
                PREFIX + "DHAlgorithmParameterGenerator", new HashMap<>(),
                (arg) -> new DHAlgorithmParameterGenerator(FIPSNISelector.DHServiceNI));
        provider.addAlias("AlgorithmParameterGenerator", "DH", "DiffieHellman");

        provider.addAlgorithmImplementation("KeyAgreement", "DH",
                PREFIX + "DHKeyAgreementSpi", attr,
                (arg) -> new DHKeyAgreementSpi(FIPSNISelector.DHServiceNI, keyFactory()));
        provider.addAlias("KeyAgreement", "DH",
                "DiffieHellman", PKCS3_DH_OID);

        provider.addAlgorithmImplementation("KeyAgreement", "DHWITHRFC2631KDF",
                PREFIX + "DHWithKDFKeyAgreementSpi", attr,
                (arg) -> new DHWithKDFKeyAgreementSpi(FIPSNISelector.DHServiceNI, keyFactory(), "SHA-1"));
        provider.addAlias("KeyAgreement", "DHWITHRFC2631KDF",
                ID_ALG_ESDH, ID_ALG_SSDH);
    }

    private static DHKeyFactorySpi keyFactory()
    {
        return new DHKeyFactorySpi(
                FIPSNISelector.DHServiceNI, FIPSNISelector.SpecNI, FIPSNISelector.Asn1NI);
    }
}
