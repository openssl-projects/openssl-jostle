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

import org.openssl.jostle.jcajce.provider.rsa.RSAKeyFactorySpi;
import org.openssl.jostle.jcajce.provider.rsa.RSAKeyPairGenerator;
import org.openssl.jostle.jcajce.provider.rsa.RSAOAEPCipherSpi;
import org.openssl.jostle.jcajce.provider.rsa.RSAPKCS1CipherSpi;
import org.openssl.jostle.jcajce.provider.rsa.RSAPSSSignatureSpi;
import org.openssl.jostle.jcajce.provider.rsa.RSASignatureSpi;

import java.util.HashMap;
import java.util.Map;

/**
 * RSA registrations for the FIPS provider, mirroring ProvRSA's surface bound
 * to the FIPS interface library. Deliberately absent: MD5withRSA (MD5 is not
 * served by the module). PKCS#1 v1.5 signatures, PSS, OAEP and PKCS#1 v1.5
 * encryption all resolve through the module's RSA implementations; the
 * module's own key-size floor (2048 bits) applies to generation.
 */
class ProvFIPSRSA
{
    private static final String PREFIX = "org.openssl.jostle.jcajce.provider.rsa.";

    public void configure(final JostleFIPSProvider provider)
    {
        final Map<String, String> attr = new HashMap<>();
        attr.put("SupportedKeyClasses",
                "java.security.interfaces.RSAPublicKey|java.security.interfaces.RSAPrivateKey");
        attr.put("SupportedKeyFormats", "PKCS#8|X.509");

        provider.addAlgorithmImplementation("KeyPairGenerator", "RSA",
                PREFIX + "RSAKeyPairGenerator", attr,
                (arg) -> new RSAKeyPairGenerator(
                        FIPSNISelector.RSAServiceNI, FIPSNISelector.SpecNI, FIPSNISelector.Asn1NI));
        provider.addAlias("KeyPairGenerator", "RSA", "1.2.840.113549.1.1.1");

        provider.addAlgorithmImplementation("KeyFactory", "RSA",
                PREFIX + "RSAKeyFactorySpi", attr,
                (arg) -> keyFactory());
        provider.addAlias("KeyFactory", "RSA", "1.2.840.113549.1.1.1");

        registerPkcs1Signature(provider, attr, "SHA1withRSA", "SHA-1", "SHA1", "1.2.840.113549.1.1.5");
        registerPkcs1Signature(provider, attr, "SHA224withRSA", "SHA-224", "SHA224", "1.2.840.113549.1.1.14");
        registerPkcs1Signature(provider, attr, "SHA256withRSA", "SHA-256", "SHA256", "1.2.840.113549.1.1.11");
        registerPkcs1Signature(provider, attr, "SHA384withRSA", "SHA-384", "SHA384", "1.2.840.113549.1.1.12");
        registerPkcs1Signature(provider, attr, "SHA512withRSA", "SHA-512", "SHA512", "1.2.840.113549.1.1.13");
        registerPkcs1Signature(provider, attr, "SHA3-224withRSA", "SHA3-224", "SHA3_224", "2.16.840.1.101.3.4.3.13");
        registerPkcs1Signature(provider, attr, "SHA3-256withRSA", "SHA3-256", "SHA3_256", "2.16.840.1.101.3.4.3.14");
        registerPkcs1Signature(provider, attr, "SHA3-384withRSA", "SHA3-384", "SHA3_384", "2.16.840.1.101.3.4.3.15");
        registerPkcs1Signature(provider, attr, "SHA3-512withRSA", "SHA3-512", "SHA3_512", "2.16.840.1.101.3.4.3.16");

        provider.addAlgorithmImplementation("Signature", "NoneWithRSA",
                PREFIX + "RSASignatureSpi$None", attr,
                (arg) -> new RSASignatureSpi(FIPSNISelector.RSAServiceNI, "NONE"));

        provider.addAlgorithmImplementation("Signature", "RSASSA-PSS",
                PREFIX + "RSAPSSSignatureSpi", attr,
                (arg) -> new RSAPSSSignatureSpi(FIPSNISelector.RSAServiceNI));
        provider.addAlias("Signature", "RSASSA-PSS", "1.2.840.113549.1.1.10");

        registerPssSignature(provider, attr, "SHA1", "SHA-1");
        registerPssSignature(provider, attr, "SHA224", "SHA-224");
        registerPssSignature(provider, attr, "SHA256", "SHA-256");
        registerPssSignature(provider, attr, "SHA384", "SHA-384");
        registerPssSignature(provider, attr, "SHA512", "SHA-512");
        registerPssSignature(provider, attr, "SHA3-224", "SHA3-224");
        registerPssSignature(provider, attr, "SHA3-256", "SHA3-256");
        registerPssSignature(provider, attr, "SHA3-384", "SHA3-384");
        registerPssSignature(provider, attr, "SHA3-512", "SHA3-512");

        Map<String, String> cipherAttr = new HashMap<>(attr);
        provider.addAlgorithmImplementation("Cipher", "RSA",
                PREFIX + "RSAOAEPCipherSpi", cipherAttr,
                (arg) -> new RSAOAEPCipherSpi(FIPSNISelector.RSAOAEPCipherNI, keyFactory()));
        provider.addAlias("Cipher", "RSA", "1.2.840.113549.1.1.1");

        Map<String, String> pkcs1Attr = new HashMap<>(attr);
        provider.addAlgorithmImplementation("Cipher", "RSA/ECB/PKCS1Padding",
                PREFIX + "RSAPKCS1CipherSpi", pkcs1Attr,
                (arg) -> new RSAPKCS1CipherSpi(FIPSNISelector.RSAPKCS1CipherNI, keyFactory()));
        provider.addAlias("Cipher", "RSA/ECB/PKCS1Padding", "RSA/None/PKCS1Padding");
    }

    private static RSAKeyFactorySpi keyFactory()
    {
        return new RSAKeyFactorySpi(
                FIPSNISelector.RSAServiceNI, FIPSNISelector.SpecNI, FIPSNISelector.Asn1NI);
    }

    private static void registerPkcs1Signature(JostleFIPSProvider provider,
                                               Map<String, String> attr,
                                               String name,
                                               String digestName,
                                               String classNameSuffix,
                                               String oid)
    {
        provider.addAlgorithmImplementation("Signature", name,
                PREFIX + classNameSuffix, attr,
                (arg) -> new RSASignatureSpi(FIPSNISelector.RSAServiceNI, digestName));
        provider.addAlias("Signature", name, oid);
    }

    private static void registerPssSignature(JostleFIPSProvider provider,
                                             Map<String, String> attr,
                                             String digestJcaName,
                                             String opensslDigest)
    {
        String mgf1Name = digestJcaName + "WITHRSAANDMGF1";
        String implName = PREFIX + "RSAPSSSignatureSpi$" + digestJcaName.replace("-", "_");
        provider.addAlgorithmImplementation("Signature", mgf1Name,
                implName, attr,
                (arg) -> new RSAPSSSignatureSpi(FIPSNISelector.RSAServiceNI, opensslDigest));
    }
}
