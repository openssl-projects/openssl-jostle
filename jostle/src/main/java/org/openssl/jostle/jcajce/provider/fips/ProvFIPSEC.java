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

import org.openssl.jostle.jcajce.provider.ec.ECAlgorithmParameters;
import org.openssl.jostle.jcajce.provider.ec.ECDHKeyAgreementSpi;
import org.openssl.jostle.jcajce.provider.ec.ECDSASignatureSpi;
import org.openssl.jostle.jcajce.provider.ec.ECKeyFactorySpi;
import org.openssl.jostle.jcajce.provider.ec.ECKeyPairGenerator;
import org.openssl.jostle.jcajce.provider.ec.ECWithKDFKeyAgreementSpi;

import java.util.HashMap;
import java.util.Map;

/**
 * EC registrations for the FIPS provider, mirroring ProvEC's surface bound
 * to the FIPS interface library. Curve approval is enforced by the module
 * itself: the FIPS lib ctx's fips=yes default properties reject key
 * generation and use on curves the module does not serve (e.g. secp256k1),
 * so no curve table is transcribed here.
 */
class ProvFIPSEC
{
    private static final String PREFIX = "org.openssl.jostle.jcajce.provider.ec.";

    public void configure(final JostleFIPSProvider provider)
    {
        final Map<String, String> attr = new HashMap<>();
        attr.put("SupportedKeyClasses",
                "java.security.interfaces.ECPublicKey|java.security.interfaces.ECPrivateKey");
        attr.put("SupportedKeyFormats", "PKCS#8|X.509");

        provider.addAlgorithmImplementation("KeyPairGenerator", "EC",
                PREFIX + "ECKeyPairGenerator", attr,
                (arg) -> new ECKeyPairGenerator(
                        FIPSNISelector.ECServiceNI, FIPSNISelector.SpecNI, FIPSNISelector.Asn1NI));
        provider.addAlias("KeyPairGenerator", "EC", "1.2.840.10045.2.1");

        provider.addAlgorithmImplementation("KeyFactory", "EC",
                PREFIX + "ECKeyFactorySpi", attr,
                (arg) -> keyFactory());
        provider.addAlias("KeyFactory", "EC", "1.2.840.10045.2.1");

        provider.addAlgorithmImplementation("AlgorithmParameters", "EC",
                PREFIX + "ECAlgorithmParameters", attr,
                (arg) -> new ECAlgorithmParameters());

        registerEcdsaSignature(provider, attr, "SHA1withECDSA", "SHA-1", "1.2.840.10045.4.1");
        registerEcdsaSignature(provider, attr, "SHA224withECDSA", "SHA-224", "1.2.840.10045.4.3.1");
        registerEcdsaSignature(provider, attr, "SHA256withECDSA", "SHA-256", "1.2.840.10045.4.3.2");
        registerEcdsaSignature(provider, attr, "SHA384withECDSA", "SHA-384", "1.2.840.10045.4.3.3");
        registerEcdsaSignature(provider, attr, "SHA512withECDSA", "SHA-512", "1.2.840.10045.4.3.4");
        registerEcdsaSignature(provider, attr, "SHA3-224withECDSA", "SHA3-224", "2.16.840.1.101.3.4.3.9");
        registerEcdsaSignature(provider, attr, "SHA3-256withECDSA", "SHA3-256", "2.16.840.1.101.3.4.3.10");
        registerEcdsaSignature(provider, attr, "SHA3-384withECDSA", "SHA3-384", "2.16.840.1.101.3.4.3.11");
        registerEcdsaSignature(provider, attr, "SHA3-512withECDSA", "SHA3-512", "2.16.840.1.101.3.4.3.12");

        // NoneWithECDSA (the raw ECDSA verification component) is a
        // non-approved service of the module per cert #4985 - not registered.

        provider.addAlgorithmImplementation("KeyAgreement", "ECDH",
                PREFIX + "ECDHKeyAgreementSpi", attr,
                (arg) -> new ECDHKeyAgreementSpi(FIPSNISelector.ECServiceNI, keyFactory()));
        registerKdfAgreement(provider, attr, "ECDHWITHSHA1KDF", "SHA-1");
        registerKdfAgreement(provider, attr, "ECDHWITHSHA224KDF", "SHA-224");
        registerKdfAgreement(provider, attr, "ECDHWITHSHA256KDF", "SHA-256");
        registerKdfAgreement(provider, attr, "ECDHWITHSHA384KDF", "SHA-384");
        registerKdfAgreement(provider, attr, "ECDHWITHSHA512KDF", "SHA-512");
    }

    private static ECKeyFactorySpi keyFactory()
    {
        return new ECKeyFactorySpi(
                FIPSNISelector.ECServiceNI, FIPSNISelector.SpecNI, FIPSNISelector.Asn1NI);
    }

    private static void registerEcdsaSignature(JostleFIPSProvider provider,
                                               Map<String, String> attr,
                                               String name,
                                               String digestName,
                                               String oid)
    {
        provider.addAlgorithmImplementation("Signature", name,
                PREFIX + "ECDSASignatureSpi$" + name.replace("-", "_"), attr,
                (arg) -> new ECDSASignatureSpi(FIPSNISelector.ECServiceNI, keyFactory(), digestName));
        provider.addAlias("Signature", name, oid);
    }

    private static void registerKdfAgreement(JostleFIPSProvider provider,
                                             Map<String, String> attr,
                                             String name,
                                             String digestName)
    {
        provider.addAlgorithmImplementation("KeyAgreement", name,
                PREFIX + "ECWithKDFKeyAgreementSpi$" + name.replace("-", "_"), attr,
                (arg) -> new ECWithKDFKeyAgreementSpi(FIPSNISelector.ECServiceNI, keyFactory(), digestName));
    }
}
