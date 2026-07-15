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

import org.openssl.jostle.jcajce.provider.dsa.DSAAlgorithmParameterGenerator;
import org.openssl.jostle.jcajce.provider.dsa.DSAAlgorithmParameters;
import org.openssl.jostle.jcajce.provider.dsa.DSAKeyFactorySpi;
import org.openssl.jostle.jcajce.provider.dsa.DSAKeyPairGenerator;
import org.openssl.jostle.jcajce.provider.dsa.DSASignatureSpi;

import java.util.HashMap;
import java.util.Map;

/**
 * DSA registrations for the FIPS provider, mirroring ProvDSA's surface bound
 * to the FIPS interface library. The 3.1.2 module still serves DSA as
 * approved (FIPS 186-4 lineage); parameter/key-size floors are enforced by
 * the module itself.
 */
class ProvFIPSDSA
{
    private static final String PREFIX = "org.openssl.jostle.jcajce.provider.dsa.";

    private static final String ID_DSA_OID = "1.2.840.10040.4.1";
    private static final String ID_DSA_WITH_SHA1_OID = "1.2.840.10040.4.3";

    public void configure(final JostleFIPSProvider provider)
    {
        final Map<String, String> attr = new HashMap<>();
        attr.put("SupportedKeyClasses",
                "java.security.interfaces.DSAPublicKey|java.security.interfaces.DSAPrivateKey");
        attr.put("SupportedKeyFormats", "PKCS#8|X.509");

        provider.addAlgorithmImplementation("KeyPairGenerator", "DSA",
                PREFIX + "DSAKeyPairGenerator", attr,
                (arg) -> new DSAKeyPairGenerator(
                        FIPSNISelector.DSAServiceNI, FIPSNISelector.SpecNI, FIPSNISelector.Asn1NI));
        provider.addAlias("KeyPairGenerator", "DSA", ID_DSA_OID);

        provider.addAlgorithmImplementation("KeyFactory", "DSA",
                PREFIX + "DSAKeyFactorySpi", attr,
                (arg) -> keyFactory());
        provider.addAlias("KeyFactory", "DSA", ID_DSA_OID);

        provider.addAlgorithmImplementation("AlgorithmParameters", "DSA",
                PREFIX + "DSAAlgorithmParameters", new HashMap<>(),
                (arg) -> new DSAAlgorithmParameters());
        provider.addAlias("AlgorithmParameters", "DSA", ID_DSA_OID);

        provider.addAlgorithmImplementation("AlgorithmParameterGenerator", "DSA",
                PREFIX + "DSAAlgorithmParameterGenerator", new HashMap<>(),
                (arg) -> new DSAAlgorithmParameterGenerator(
                        FIPSNISelector.DSAServiceNI, FIPSNISelector.SpecNI));
        provider.addAlias("AlgorithmParameterGenerator", "DSA", ID_DSA_OID);

        registerDsaSignature(provider, attr, "SHA1withDSA", "SHA-1", ID_DSA_WITH_SHA1_OID);
        registerDsaSignature(provider, attr, "SHA224withDSA", "SHA-224", "2.16.840.1.101.3.4.3.1");
        registerDsaSignature(provider, attr, "SHA256withDSA", "SHA-256", "2.16.840.1.101.3.4.3.2");
        registerDsaSignature(provider, attr, "SHA384withDSA", "SHA-384", "2.16.840.1.101.3.4.3.3");
        registerDsaSignature(provider, attr, "SHA512withDSA", "SHA-512", "2.16.840.1.101.3.4.3.4");
        registerDsaSignature(provider, attr, "SHA3-224withDSA", "SHA3-224", "2.16.840.1.101.3.4.3.5");
        registerDsaSignature(provider, attr, "SHA3-256withDSA", "SHA3-256", "2.16.840.1.101.3.4.3.6");
        registerDsaSignature(provider, attr, "SHA3-384withDSA", "SHA3-384", "2.16.840.1.101.3.4.3.7");
        registerDsaSignature(provider, attr, "SHA3-512withDSA", "SHA3-512", "2.16.840.1.101.3.4.3.8");

        provider.addAlgorithmImplementation("Signature", "NoneWithDSA",
                PREFIX + "DSASignatureSpi$None", attr,
                (arg) -> new DSASignatureSpi(FIPSNISelector.DSAServiceNI, keyFactory(), "NONE"));
    }

    private static DSAKeyFactorySpi keyFactory()
    {
        return new DSAKeyFactorySpi(
                FIPSNISelector.DSAServiceNI, FIPSNISelector.SpecNI, FIPSNISelector.Asn1NI);
    }

    private static void registerDsaSignature(JostleFIPSProvider provider,
                                             Map<String, String> attr,
                                             String name,
                                             String digestName,
                                             String oid)
    {
        provider.addAlgorithmImplementation("Signature", name,
                PREFIX + "DSASignatureSpi$" + name.replace("-", "_"), attr,
                (arg) -> new DSASignatureSpi(FIPSNISelector.DSAServiceNI, keyFactory(), digestName));
        provider.addAlias("Signature", name, oid);
    }
}
