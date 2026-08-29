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
import org.openssl.jostle.jcajce.provider.ec.ECWithKDFKeyAgreementSpi;
import org.openssl.jostle.jcajce.provider.ec.ECDSASignatureSpi;
import org.openssl.jostle.jcajce.provider.ec.ECKeyFactorySpi;
import org.openssl.jostle.jcajce.provider.ec.ECKeyPairGenerator;
import org.openssl.jostle.util.asn1.oids.NISTObjectIdentifiers;

import java.util.HashMap;
import java.util.Map;

class ProvEC
{

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
                ECKeyPairGenerator.class.getName(), attr,
                (arg) -> new ECKeyPairGenerator(
                        NISelector.ECServiceNI, NISelector.SpecNI, NISelector.Asn1NI, provider));
        provider.addAlias("KeyPairGenerator", "EC", EC_PUBLIC_KEY_OID);

        provider.addAlgorithmImplementation("KeyFactory", "EC",
                ECKeyFactorySpi.class.getName(), attr,
                (arg) -> keyFactory(provider));
        provider.addAlias("KeyFactory", "EC", EC_PUBLIC_KEY_OID);

        // AlgorithmParameters EC — delegates curve-parameter resolution to
        // the platform (SunEC). Needed by BouncyCastle's TLS JceTlsECDomain,
        // which resolves NIST-curve domain parameters via
        // createAlgorithmParameters("EC") on the JSL-bound helper.
        provider.addAlgorithmImplementation("AlgorithmParameters", "EC",
                ECAlgorithmParameters.class.getName(), new HashMap<>(),
                (arg) -> new ECAlgorithmParameters());
        provider.addAlias("AlgorithmParameters", "EC", EC_PUBLIC_KEY_OID);

        // ECDSA Signature variants. The signature OIDs come from
        // RFC 5758 (SHA-2) and RFC 5754 / NIST CSOR (SHA-3). The digest
        // is fixed at SPI construction time — no AlgorithmParameter
        // negotiation is needed.
        registerEcdsaSignature(provider, attr,
                "SHA1withECDSA", "SHA-1", "1.2.840.10045.4.1");
        registerEcdsaSignature(provider, attr,
                "SHA224withECDSA", "SHA-224", "1.2.840.10045.4.3.1");
        registerEcdsaSignature(provider, attr,
                "SHA256withECDSA", "SHA-256", "1.2.840.10045.4.3.2");
        registerEcdsaSignature(provider, attr,
                "SHA384withECDSA", "SHA-384", "1.2.840.10045.4.3.3");
        registerEcdsaSignature(provider, attr,
                "SHA512withECDSA", "SHA-512", "1.2.840.10045.4.3.4");
        registerEcdsaSignature(provider, attr,
                "SHA3-224withECDSA", "SHA3-224", NISTObjectIdentifiers.id_ecdsa_with_sha3_224.getId());
        registerEcdsaSignature(provider, attr,
                "SHA3-256withECDSA", "SHA3-256", NISTObjectIdentifiers.id_ecdsa_with_sha3_256.getId());
        registerEcdsaSignature(provider, attr,
                "SHA3-384withECDSA", "SHA3-384", NISTObjectIdentifiers.id_ecdsa_with_sha3_384.getId());
        registerEcdsaSignature(provider, attr,
                "SHA3-512withECDSA", "SHA3-512", NISTObjectIdentifiers.id_ecdsa_with_sha3_512.getId());

        // Raw ECDSA ("NoneWithECDSA"): the caller supplies an already-computed
        // digest, so there is no per-digest OID to alias. Required by TLS 1.3's
        // externally-hashed ECDSA CertificateVerify (BouncyCastle's
        // JcaTlsECDSA13Signer.generateRawSignature).
        provider.addAlgorithmImplementation("Signature", "NoneWithECDSA",
                ECDSASignatureSpi.class.getName(), attr,
                (arg) -> new ECDSASignatureSpi(NISelector.ECServiceNI,
                        keyFactory(provider), "NONE"));

        // ECDH KeyAgreement. The OID 1.3.132.1.12 is id-ecDH from SECG
        // (RFC 5480 §2.1.2 / SEC 1 §C.4); RFC 5480 also permits the
        // generic id-ecPublicKey OID for ECDH-with-X.509 SubjectPublicKeyInfo,
        // so we alias both for caller convenience.
        provider.addAlgorithmImplementation("KeyAgreement", "ECDH",
                ECDHKeyAgreementSpi.class.getName(), attr,
                (arg) -> new ECDHKeyAgreementSpi(NISelector.ECServiceNI, keyFactory(provider)));
        provider.addAlias("KeyAgreement", "ECDH", "1.3.132.1.12");

        // CMS EC key agreement with the X9.63 KDF (dhSinglePass-stdDH-sha*kdf-
        // scheme). One registration per digest; the scheme OID aliases onto it
        // so KeyAgreeRecipientInfo for EC recipients resolves. Cofactor
        // (dhSinglePass-cofactorDH) and MQV schemes are intentionally absent —
        // they need native cofactor/MQV agreement Jostle does not yet expose.
        final String ecKdfSpi = ECWithKDFKeyAgreementSpi.class.getName();
        provider.addAlgorithmImplementation("KeyAgreement", "ECDHWITHSHA1KDF",
                ecKdfSpi, attr,
                (arg) -> new ECWithKDFKeyAgreementSpi(NISelector.ECServiceNI,
                        keyFactory(provider), "SHA-1", JostleProvider.PROVIDER_NAME));
        provider.addAlias("KeyAgreement", "ECDHWITHSHA1KDF", "1.3.133.16.840.63.0.2");

        provider.addAlgorithmImplementation("KeyAgreement", "ECDHWITHSHA224KDF",
                ecKdfSpi, attr,
                (arg) -> new ECWithKDFKeyAgreementSpi(NISelector.ECServiceNI,
                        keyFactory(provider), "SHA-224", JostleProvider.PROVIDER_NAME));
        provider.addAlias("KeyAgreement", "ECDHWITHSHA224KDF", "1.3.132.1.11.0");

        provider.addAlgorithmImplementation("KeyAgreement", "ECDHWITHSHA256KDF",
                ecKdfSpi, attr,
                (arg) -> new ECWithKDFKeyAgreementSpi(NISelector.ECServiceNI,
                        keyFactory(provider), "SHA-256", JostleProvider.PROVIDER_NAME));
        provider.addAlias("KeyAgreement", "ECDHWITHSHA256KDF", "1.3.132.1.11.1");

        provider.addAlgorithmImplementation("KeyAgreement", "ECDHWITHSHA384KDF",
                ecKdfSpi, attr,
                (arg) -> new ECWithKDFKeyAgreementSpi(NISelector.ECServiceNI,
                        keyFactory(provider), "SHA-384", JostleProvider.PROVIDER_NAME));
        provider.addAlias("KeyAgreement", "ECDHWITHSHA384KDF", "1.3.132.1.11.2");

        provider.addAlgorithmImplementation("KeyAgreement", "ECDHWITHSHA512KDF",
                ecKdfSpi, attr,
                (arg) -> new ECWithKDFKeyAgreementSpi(NISelector.ECServiceNI,
                        keyFactory(provider), "SHA-512", JostleProvider.PROVIDER_NAME));
        provider.addAlias("KeyAgreement", "ECDHWITHSHA512KDF", "1.3.132.1.11.3");
    }


    private static void registerEcdsaSignature(JostleProvider provider,
                                               Map<String, String> attr,
                                               String name,
                                               String digestName,
                                               String oid)
    {
        provider.addAlgorithmImplementation("Signature", name,
                ECDSASignatureSpi.class.getName(), attr,
                (arg) -> new ECDSASignatureSpi(NISelector.ECServiceNI,
                        keyFactory(provider), digestName));
        provider.addAlias("Signature", name, oid);
    }

    /**
     * A KeyFactory bound to {@code provider}. Every key it produces, and every
     * key it accepts, belongs to that provider INSTANCE (MT-14).
     */
    private static ECKeyFactorySpi keyFactory(JostleProvider provider)
    {
        return new ECKeyFactorySpi(
                NISelector.ECServiceNI, NISelector.SpecNI, NISelector.Asn1NI, provider);
    }
}
