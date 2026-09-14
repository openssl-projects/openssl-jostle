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
import org.openssl.jostle.util.asn1.oids.NISTObjectIdentifiers;
import org.openssl.jostle.util.asn1.oids.X9ObjectIdentifiers;

/**
 * DSA registrations for the FIPS provider, mirroring ProvDSA's surface bound
 * to the FIPS interface library. The 3.1.2 module still serves DSA as
 * approved (FIPS 186-4 lineage); parameter/key-size floors are enforced by
 * the module itself.
 */
class ProvFIPSDSA
{

    private static final String ID_DSA_OID = X9ObjectIdentifiers.id_dsa.getId();
    private static final String ID_DSA_WITH_SHA1_OID = X9ObjectIdentifiers.id_dsa_with_sha1.getId();

    /**
     * The FIPS 186-4 &sect;4.2 (L, N) moduli the validated modules generate.
     * Enforced at the JCE boundary so the refusal is a typed
     * InvalidParameterException rather than a module error.
     */
    private static final int[] FIPS_DSA_ACCEPTED_P_BITS = {2048, 3072};

    public void configure(final JostleFIPSProvider provider)
    {
        final Map<String, String> attr = new HashMap<>();
        attr.put("SupportedKeyClasses",
                "java.security.interfaces.DSAPublicKey|java.security.interfaces.DSAPrivateKey");
        attr.put("SupportedKeyFormats", "PKCS#8|X.509");

        provider.addAlgorithmImplementation("KeyPairGenerator", "DSA",
                DSAKeyPairGenerator.class.getName(), attr,
                (arg) -> new DSAKeyPairGenerator(
                        FIPSNISelector.DSAServiceNI, FIPSNISelector.SpecNI, FIPSNISelector.Asn1NI,
                        provider));
        provider.addAlias("KeyPairGenerator", "DSA", ID_DSA_OID);

        provider.addAlgorithmImplementation("KeyFactory", "DSA",
                DSAKeyFactorySpi.class.getName(), attr,
                (arg) -> keyFactory(provider));
        provider.addAlias("KeyFactory", "DSA", ID_DSA_OID);

        provider.addAlgorithmImplementation("AlgorithmParameters", "DSA",
                DSAAlgorithmParameters.class.getName(), new HashMap<>(),
                (arg) -> new DSAAlgorithmParameters());
        provider.addAlias("AlgorithmParameters", "DSA", ID_DSA_OID);

        provider.addAlgorithmImplementation("AlgorithmParameterGenerator", "DSA",
                DSAAlgorithmParameterGenerator.class.getName(), new HashMap<>(),
                (arg) -> new DSAAlgorithmParameterGenerator(
                        FIPSNISelector.DSAServiceNI, FIPSNISelector.SpecNI,
                        FIPS_DSA_ACCEPTED_P_BITS, provider));
        provider.addAlias("AlgorithmParameterGenerator", "DSA", ID_DSA_OID);

        registerDsaSignature(provider, attr, "SHA1withDSA", "SHA-1", ID_DSA_WITH_SHA1_OID);
        registerDsaSignature(provider, attr, "SHA224withDSA", "SHA-224", NISTObjectIdentifiers.dsa_with_sha224.getId());
        registerDsaSignature(provider, attr, "SHA256withDSA", "SHA-256", NISTObjectIdentifiers.dsa_with_sha256.getId());
        registerDsaSignature(provider, attr, "SHA384withDSA", "SHA-384", NISTObjectIdentifiers.dsa_with_sha384.getId());
        registerDsaSignature(provider, attr, "SHA512withDSA", "SHA-512", NISTObjectIdentifiers.dsa_with_sha512.getId());
        registerDsaSignature(provider, attr, "SHA3-224withDSA", "SHA3-224", NISTObjectIdentifiers.id_dsa_with_sha3_224.getId());
        registerDsaSignature(provider, attr, "SHA3-256withDSA", "SHA3-256", NISTObjectIdentifiers.id_dsa_with_sha3_256.getId());
        registerDsaSignature(provider, attr, "SHA3-384withDSA", "SHA3-384", NISTObjectIdentifiers.id_dsa_with_sha3_384.getId());
        registerDsaSignature(provider, attr, "SHA3-512withDSA", "SHA3-512", NISTObjectIdentifiers.id_dsa_with_sha3_512.getId());

        provider.addAlgorithmImplementation("Signature", "NoneWithDSA",
                DSASignatureSpi.class.getName(), attr,
                (arg) -> new DSASignatureSpi(FIPSNISelector.DSAServiceNI, keyFactory(provider), "NONE"));
    }

    /**
     * A KeyFactory bound to {@code provider}. Every key it produces, and every
     * key it accepts, belongs to that provider INSTANCE (MT-14).
     */
    private static DSAKeyFactorySpi keyFactory(JostleFIPSProvider provider)
    {
        return new DSAKeyFactorySpi(
                FIPSNISelector.DSAServiceNI, FIPSNISelector.SpecNI, FIPSNISelector.Asn1NI, provider);
    }

    private static void registerDsaSignature(JostleFIPSProvider provider,
                                             Map<String, String> attr,
                                             String name,
                                             String digestName,
                                             String oid)
    {
        provider.addAlgorithmImplementation("Signature", name,
                DSASignatureSpi.class.getName(), attr,
                (arg) -> new DSASignatureSpi(FIPSNISelector.DSAServiceNI, keyFactory(provider), digestName));
        provider.addAlias("Signature", name, oid);
    }
}
