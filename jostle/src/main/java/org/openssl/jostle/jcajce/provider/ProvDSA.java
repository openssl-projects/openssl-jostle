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

import org.openssl.jostle.jcajce.provider.dsa.DSAAlgorithmParameterGenerator;
import org.openssl.jostle.jcajce.provider.dsa.DSAAlgorithmParameters;
import org.openssl.jostle.jcajce.provider.dsa.DSAKeyFactorySpi;
import org.openssl.jostle.jcajce.provider.dsa.DSAKeyPairGenerator;
import org.openssl.jostle.jcajce.provider.dsa.DSASignatureSpi;
import org.openssl.jostle.util.asn1.oids.NISTObjectIdentifiers;

import java.util.HashMap;
import java.util.Map;

class ProvDSA
{
    private static final String PREFIX = ProvDSA.class.getPackage().getName() + ".dsa.";

    /**
     * id-dsa OID (X9.57) — used as the ASN.1 algorithm identifier in
     * X.509 SubjectPublicKeyInfo and PKCS#8 PrivateKeyInfo for DSA keys.
     */
    private static final String ID_DSA_OID = "1.2.840.10040.4.1";

    /** id-dsa-with-sha1 (X9.57). */
    private static final String ID_DSA_WITH_SHA1_OID = "1.2.840.10040.4.3";


    public void configure(final JostleProvider provider)
    {
        final Map<String, String> attr = new HashMap<>();
        attr.put("SupportedKeyClasses",
                "java.security.interfaces.DSAPublicKey|java.security.interfaces.DSAPrivateKey");
        attr.put("SupportedKeyFormats", "PKCS#8|X.509");

        provider.addAlgorithmImplementation("KeyPairGenerator", "DSA",
                PREFIX + "DSAKeyPairGenerator", attr,
                (arg) -> new DSAKeyPairGenerator());
        provider.addAlias("KeyPairGenerator", "DSA", ID_DSA_OID);

        provider.addAlgorithmImplementation("KeyFactory", "DSA",
                PREFIX + "DSAKeyFactorySpi", attr,
                (arg) -> new DSAKeyFactorySpi());
        provider.addAlias("KeyFactory", "DSA", ID_DSA_OID);

        // AlgorithmParameters DSA — Dss-Parms SEQUENCE { p, q, g } codec
        // delegated to the platform (SUN). Needed by callers that carry
        // DSA domain parameters in AlgorithmIdentifier.parameters.
        provider.addAlgorithmImplementation("AlgorithmParameters", "DSA",
                PREFIX + "DSAAlgorithmParameters", new HashMap<>(),
                (arg) -> new DSAAlgorithmParameters());
        provider.addAlias("AlgorithmParameters", "DSA", ID_DSA_OID);

        // AlgorithmParameterGenerator DSA — native FIPS 186-4 paramgen.
        provider.addAlgorithmImplementation("AlgorithmParameterGenerator", "DSA",
                PREFIX + "DSAAlgorithmParameterGenerator", new HashMap<>(),
                (arg) -> new DSAAlgorithmParameterGenerator());
        provider.addAlias("AlgorithmParameterGenerator", "DSA", ID_DSA_OID);

        // DSA Signature variants. SHA-1 is the X9.57 id-dsa-with-sha1;
        // the SHA-2 family OIDs come from NIST CSOR (RFC 5758); SHA-3
        // from NIST CSOR. The digest is fixed at SPI construction —
        // no AlgorithmParameter negotiation is needed.
        registerDsaSignature(provider, attr,
                "SHA1withDSA", DSASignatureSpi.SHA1.class,
                ID_DSA_WITH_SHA1_OID);
        registerDsaSignature(provider, attr,
                "SHA224withDSA", DSASignatureSpi.SHA224.class,
                NISTObjectIdentifiers.dsa_with_sha224.getId());
        registerDsaSignature(provider, attr,
                "SHA256withDSA", DSASignatureSpi.SHA256.class,
                NISTObjectIdentifiers.dsa_with_sha256.getId());
        registerDsaSignature(provider, attr,
                "SHA384withDSA", DSASignatureSpi.SHA384.class,
                NISTObjectIdentifiers.dsa_with_sha384.getId());
        registerDsaSignature(provider, attr,
                "SHA512withDSA", DSASignatureSpi.SHA512.class,
                NISTObjectIdentifiers.dsa_with_sha512.getId());
        registerDsaSignature(provider, attr,
                "SHA3-224withDSA", DSASignatureSpi.SHA3_224.class,
                NISTObjectIdentifiers.id_dsa_with_sha3_224.getId());
        registerDsaSignature(provider, attr,
                "SHA3-256withDSA", DSASignatureSpi.SHA3_256.class,
                NISTObjectIdentifiers.id_dsa_with_sha3_256.getId());
        registerDsaSignature(provider, attr,
                "SHA3-384withDSA", DSASignatureSpi.SHA3_384.class,
                NISTObjectIdentifiers.id_dsa_with_sha3_384.getId());
        registerDsaSignature(provider, attr,
                "SHA3-512withDSA", DSASignatureSpi.SHA3_512.class,
                NISTObjectIdentifiers.id_dsa_with_sha3_512.getId());

        // Raw DSA ("NoneWithDSA"): the caller supplies an already-computed
        // digest, so there is no per-digest OID to alias. Required by
        // externally-hashed DSA signing (BouncyCastle's TLS
        // JcaTlsDSASigner raw-signature path).
        provider.addAlgorithmImplementation("Signature", "NoneWithDSA",
                PREFIX + "DSASignatureSpi$None", attr,
                (arg) -> new DSASignatureSpi.None());
    }


    private static void registerDsaSignature(JostleProvider provider,
                                             Map<String, String> attr,
                                             String name,
                                             Class<?> spiClass,
                                             String oid)
    {
        provider.addAlgorithmImplementation("Signature", name,
                PREFIX + spiClass.getSimpleName(), attr,
                (arg) ->
                {
                    try
                    {
                        return (java.security.SignatureSpi) spiClass.getDeclaredConstructor().newInstance();
                    }
                    catch (ReflectiveOperationException e)
                    {
                        throw new IllegalStateException(
                                "unable to instantiate " + spiClass.getName(), e);
                    }
                });
        provider.addAlias("Signature", name, oid);
    }
}
