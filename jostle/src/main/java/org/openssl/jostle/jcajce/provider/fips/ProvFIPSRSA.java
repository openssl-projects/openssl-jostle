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
import org.openssl.jostle.jcajce.provider.rsa.RSAPSSSignatureSpi;
import org.openssl.jostle.jcajce.provider.rsa.RSASignatureSpi;

import java.util.HashMap;
import java.util.Map;

/**
 * RSA registrations for the FIPS provider, bound to the FIPS interface
 * library. PKCS#1 v1.5 signatures, PSS, and OAEP encryption resolve through the
 * module's RSA implementations; the module's own key-size floor (2048 bits)
 * applies to generation.
 * <p>
 * Deliberately absent:
 * <ol>
 *   <li>MD5withRSA — MD5 is not served by the module.</li>
 *   <li>PKCS#1 v1.5 <em>encryption</em> (Cipher {@code RSA/ECB/PKCS1Padding}).
 *       The OpenSSL FIPS Provider 3.1.2 Security Policy (CMVP cert #4985)
 *       approves RSA key transport via OAEP only (KTS-4, SP 800-56Br2);
 *       RSAES-PKCS#1-v1_5 encryption is not an approved service. It is also a
 *       Bleichenbacher padding oracle here: the 3.1.2 module does not honour
 *       the implicit-rejection param (it postdates 3.1.2), so it is left
 *       unregistered rather than exposed as a non-approved footgun. PKCS#1 v1.5
 *       remains available for SIGNATURES, which the policy does approve.</li>
 * </ol>
 */
class ProvFIPSRSA
{
    private static final String PREFIX = "org.openssl.jostle.jcajce.provider.rsa.";

    /**
     * The 3.1.2 FIPS module refuses RSA key generation below 2048 bits;
     * enforcing the same floor at the JCE boundary surfaces a typed
     * InvalidParameterException instead of a module error.
     */
    private static final int FIPS_RSA_MIN_KEY_SIZE_BITS = 2048;

    public void configure(final JostleFIPSProvider provider)
    {
        final Map<String, String> attr = new HashMap<>();
        attr.put("SupportedKeyClasses",
                "java.security.interfaces.RSAPublicKey|java.security.interfaces.RSAPrivateKey");
        attr.put("SupportedKeyFormats", "PKCS#8|X.509");

        provider.addAlgorithmImplementation("KeyPairGenerator", "RSA",
                PREFIX + "RSAKeyPairGenerator", attr,
                (arg) -> new RSAKeyPairGenerator(
                        FIPSNISelector.RSAServiceNI, FIPSNISelector.SpecNI, FIPSNISelector.Asn1NI,
                        FIPS_RSA_MIN_KEY_SIZE_BITS));
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
                (arg) -> new RSASignatureSpi(FIPSNISelector.RSAServiceNI, keyFactory(), "NONE"));

        provider.addAlgorithmImplementation("Signature", "RSASSA-PSS",
                PREFIX + "RSAPSSSignatureSpi", attr,
                (arg) -> new RSAPSSSignatureSpi(FIPSNISelector.RSAServiceNI, keyFactory()));
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

        // OAEP is the ONLY approved RSA key-transport / encryption scheme for
        // this module (KTS-4, SP 800-56Br2 — see class Javadoc). PKCS#1 v1.5
        // encryption is deliberately NOT registered: it is non-approved and the
        // 3.1.2 module does not honour implicit rejection, so it would be a
        // padding oracle. The bare "RSA" transformation therefore maps to OAEP.
        Map<String, String> cipherAttr = new HashMap<>(attr);
        provider.addAlgorithmImplementation("Cipher", "RSA",
                PREFIX + "RSAOAEPCipherSpi", cipherAttr,
                (arg) -> new RSAOAEPCipherSpi(FIPSNISelector.RSAOAEPCipherNI, keyFactory()));
        provider.addAlias("Cipher", "RSA", "1.2.840.113549.1.1.1");
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
                (arg) -> new RSASignatureSpi(FIPSNISelector.RSAServiceNI, keyFactory(), digestName));
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
                (arg) -> new RSAPSSSignatureSpi(FIPSNISelector.RSAServiceNI, keyFactory(), opensslDigest));
    }
}
