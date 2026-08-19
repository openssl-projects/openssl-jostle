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

        // NoneWithECDSA — raw ECDSA over a caller-supplied digest, both
        // directions. The module serves it, so we expose it: JSLFIPS's surface
        // is what the FIPS module implements, not a subset filtered against the
        // security policy's approved-services tables. Determining whether a
        // given use is FIPS-approved is the operator's, not this provider's.
        //
        // For the record, since it was previously restricted here: cert #4985
        // approves the SigGen Component ("Component - No, Yes"; services table
        // "SigGen (includes SigGen Component)") and lists the SigVer Component
        // as non-approved (Table 8, §4.4 Table 13). The module performs both.
        provider.addAlgorithmImplementation("Signature", "NoneWithECDSA",
                PREFIX + "ECDSASignatureSpi$None", attr,
                (arg) -> new ECDSASignatureSpi(FIPSNISelector.ECServiceNI, keyFactory(), "NONE"));

        provider.addAlgorithmImplementation("KeyAgreement", "ECDH",
                PREFIX + "ECDHKeyAgreementSpi", attr,
                (arg) -> new ECDHKeyAgreementSpi(FIPSNISelector.ECServiceNI, keyFactory()));
        // id-ecDH (SECG SEC1) — so CMS/PKIX KeyAgreeRecipientInfo can resolve
        // the EC agreement by OID, mirroring the non-FIPS ProvEC surface.
        provider.addAlias("KeyAgreement", "ECDH", "1.3.132.1.12");
        // X9.63 dhSinglePass-stdDH-sha*kdf-scheme OIDs, likewise for CMS. All
        // five PRFs are served: the module performs X963KDF with a SHA-1 PRF
        // under fips=yes (probe-confirmed), so it is exposed. Cert #4985 Table 8
        // lists that particular USAGE as non-approved — a caller-chosen PRF the
        // module does not police — which is the operator's determination to make.
        registerKdfAgreement(provider, attr, "ECDHWITHSHA1KDF", "SHA-1", "1.3.133.16.840.63.0.2");
        registerKdfAgreement(provider, attr, "ECDHWITHSHA224KDF", "SHA-224", "1.3.132.1.11.0");
        registerKdfAgreement(provider, attr, "ECDHWITHSHA256KDF", "SHA-256", "1.3.132.1.11.1");
        registerKdfAgreement(provider, attr, "ECDHWITHSHA384KDF", "SHA-384", "1.3.132.1.11.2");
        registerKdfAgreement(provider, attr, "ECDHWITHSHA512KDF", "SHA-512", "1.3.132.1.11.3");
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
                                             String digestName,
                                             String oid)
    {
        provider.addAlgorithmImplementation("KeyAgreement", name,
                PREFIX + "ECWithKDFKeyAgreementSpi$" + name.replace("-", "_"), attr,
                (arg) -> new ECWithKDFKeyAgreementSpi(FIPSNISelector.ECServiceNI, keyFactory(), digestName));
        provider.addAlias("KeyAgreement", name, oid);
    }
}
