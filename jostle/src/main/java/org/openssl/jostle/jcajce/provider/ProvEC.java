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

import org.openssl.jostle.jcajce.provider.ec.ECAlgorithmParameters;
import org.openssl.jostle.jcajce.provider.ec.ECDHKeyAgreementSpi;
import org.openssl.jostle.jcajce.provider.ec.ECDSASignatureSpi;
import org.openssl.jostle.jcajce.provider.ec.ECKeyFactorySpi;
import org.openssl.jostle.jcajce.provider.ec.ECKeyPairGenerator;
import org.openssl.jostle.util.asn1.oids.NISTObjectIdentifiers;

import java.util.HashMap;
import java.util.Map;

class ProvEC
{
    private static final String PREFIX = ProvEC.class.getPackage().getName() + ".ec.";

    /**
     * id-ecPublicKey OID — used as the ASN.1 algorithm identifier in
     * X.509 SubjectPublicKeyInfo and PKCS#8 PrivateKeyInfo for any EC
     * key, regardless of curve.
     */
    private static final String EC_PUBLIC_KEY_OID = "1.2.840.10045.2.1";


    public void configure(final JostleProvider provider)
    {
        final Map<String, String> attr = new HashMap<>();
        attr.put("SupportedKeyClasses",
                "java.security.interfaces.ECPublicKey|java.security.interfaces.ECPrivateKey");
        attr.put("SupportedKeyFormats", "PKCS#8|X.509");

        provider.addAlgorithmImplementation("KeyPairGenerator", "EC",
                PREFIX + "ECKeyPairGenerator", attr,
                (arg) -> new ECKeyPairGenerator());
        provider.addAlias("KeyPairGenerator", "EC", EC_PUBLIC_KEY_OID);

        provider.addAlgorithmImplementation("KeyFactory", "EC",
                PREFIX + "ECKeyFactorySpi", attr,
                (arg) -> new ECKeyFactorySpi());
        provider.addAlias("KeyFactory", "EC", EC_PUBLIC_KEY_OID);

        // AlgorithmParameters EC — delegates curve-parameter resolution to
        // the platform (SunEC). Needed by BouncyCastle's TLS JceTlsECDomain,
        // which resolves NIST-curve domain parameters via
        // createAlgorithmParameters("EC") on the JSL-bound helper.
        provider.addAlgorithmImplementation("AlgorithmParameters", "EC",
                PREFIX + "ECAlgorithmParameters", new HashMap<>(),
                (arg) -> new ECAlgorithmParameters());
        provider.addAlias("AlgorithmParameters", "EC", EC_PUBLIC_KEY_OID);

        // ECDSA Signature variants. The signature OIDs come from
        // RFC 5758 (SHA-2) and RFC 5754 / NIST CSOR (SHA-3). The digest
        // is fixed at SPI construction time — no AlgorithmParameter
        // negotiation is needed.
        registerEcdsaSignature(provider, attr,
                "SHA1withECDSA", ECDSASignatureSpi.SHA1.class,
                "1.2.840.10045.4.1");
        registerEcdsaSignature(provider, attr,
                "SHA224withECDSA", ECDSASignatureSpi.SHA224.class,
                "1.2.840.10045.4.3.1");
        registerEcdsaSignature(provider, attr,
                "SHA256withECDSA", ECDSASignatureSpi.SHA256.class,
                "1.2.840.10045.4.3.2");
        registerEcdsaSignature(provider, attr,
                "SHA384withECDSA", ECDSASignatureSpi.SHA384.class,
                "1.2.840.10045.4.3.3");
        registerEcdsaSignature(provider, attr,
                "SHA512withECDSA", ECDSASignatureSpi.SHA512.class,
                "1.2.840.10045.4.3.4");
        registerEcdsaSignature(provider, attr,
                "SHA3-224withECDSA", ECDSASignatureSpi.SHA3_224.class,
                NISTObjectIdentifiers.id_ecdsa_with_sha3_224.getId());
        registerEcdsaSignature(provider, attr,
                "SHA3-256withECDSA", ECDSASignatureSpi.SHA3_256.class,
                NISTObjectIdentifiers.id_ecdsa_with_sha3_256.getId());
        registerEcdsaSignature(provider, attr,
                "SHA3-384withECDSA", ECDSASignatureSpi.SHA3_384.class,
                NISTObjectIdentifiers.id_ecdsa_with_sha3_384.getId());
        registerEcdsaSignature(provider, attr,
                "SHA3-512withECDSA", ECDSASignatureSpi.SHA3_512.class,
                NISTObjectIdentifiers.id_ecdsa_with_sha3_512.getId());

        // Raw ECDSA ("NoneWithECDSA"): the caller supplies an already-computed
        // digest, so there is no per-digest OID to alias. Required by TLS 1.3's
        // externally-hashed ECDSA CertificateVerify (BouncyCastle's
        // JcaTlsECDSA13Signer.generateRawSignature).
        provider.addAlgorithmImplementation("Signature", "NoneWithECDSA",
                PREFIX + "ECDSASignatureSpi$None", attr,
                (arg) -> new ECDSASignatureSpi.None());

        // ECDH KeyAgreement. The OID 1.3.132.1.12 is id-ecDH from SECG
        // (RFC 5480 §2.1.2 / SEC 1 §C.4); RFC 5480 also permits the
        // generic id-ecPublicKey OID for ECDH-with-X.509 SubjectPublicKeyInfo,
        // so we alias both for caller convenience.
        provider.addAlgorithmImplementation("KeyAgreement", "ECDH",
                PREFIX + "ECDHKeyAgreementSpi", attr,
                (arg) -> new ECDHKeyAgreementSpi());
        provider.addAlias("KeyAgreement", "ECDH", "1.3.132.1.12");
    }


    private static void registerEcdsaSignature(JostleProvider provider,
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
