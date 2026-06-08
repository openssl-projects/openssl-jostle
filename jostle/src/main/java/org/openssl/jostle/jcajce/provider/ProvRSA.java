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

import org.openssl.jostle.jcajce.provider.rsa.*;

import java.util.HashMap;
import java.util.Map;

class ProvRSA
{
    private static final String PREFIX = ProvRSA.class.getPackage().getName() + ".rsa.";

    public void configure(final JostleProvider provider)
    {
        final Map<String, String> attr = new HashMap<>();
        attr.put("SupportedKeyClasses",
                "java.security.interfaces.RSAPublicKey|java.security.interfaces.RSAPrivateKey");
        attr.put("SupportedKeyFormats", "PKCS#8|X.509");

        // KeyPairGenerator.
        provider.addAlgorithmImplementation("KeyPairGenerator", "RSA",
                PREFIX + "RSAKeyPairGenerator", attr,
                (arg) -> new RSAKeyPairGenerator());
        provider.addAlias("KeyPairGenerator", "RSA", "1.2.840.113549.1.1.1");

        // KeyFactory.
        provider.addAlgorithmImplementation("KeyFactory", "RSA",
                PREFIX + "RSAKeyFactorySpi", attr,
                (arg) -> new RSAKeyFactorySpi());
        provider.addAlias("KeyFactory", "RSA", "1.2.840.113549.1.1.1");

        // PKCS#1 v1.5 Signature variants. MD5 is registered for legacy
        // interop only — callers should prefer SHA-2 / SHA-3 family.
        registerPkcs1Signature(provider, attr,
                "MD5withRSA", "MD5", RSASignatureSpi.MD5.class, "1.2.840.113549.1.1.4");
        registerPkcs1Signature(provider, attr,
                "SHA1withRSA", "SHA-1", RSASignatureSpi.SHA1.class, "1.2.840.113549.1.1.5");
        registerPkcs1Signature(provider, attr,
                "SHA224withRSA", "SHA-224", RSASignatureSpi.SHA224.class, "1.2.840.113549.1.1.14");
        registerPkcs1Signature(provider, attr,
                "SHA256withRSA", "SHA-256", RSASignatureSpi.SHA256.class, "1.2.840.113549.1.1.11");
        registerPkcs1Signature(provider, attr,
                "SHA384withRSA", "SHA-384", RSASignatureSpi.SHA384.class, "1.2.840.113549.1.1.12");
        registerPkcs1Signature(provider, attr,
                "SHA512withRSA", "SHA-512", RSASignatureSpi.SHA512.class, "1.2.840.113549.1.1.13");
        registerPkcs1Signature(provider, attr,
                "SHA3-224withRSA", "SHA3-224", RSASignatureSpi.SHA3_224.class, "2.16.840.1.101.3.4.3.13");
        registerPkcs1Signature(provider, attr,
                "SHA3-256withRSA", "SHA3-256", RSASignatureSpi.SHA3_256.class, "2.16.840.1.101.3.4.3.14");
        registerPkcs1Signature(provider, attr,
                "SHA3-384withRSA", "SHA3-384", RSASignatureSpi.SHA3_384.class, "2.16.840.1.101.3.4.3.15");
        registerPkcs1Signature(provider, attr,
                "SHA3-512withRSA", "SHA3-512", RSASignatureSpi.SHA3_512.class, "2.16.840.1.101.3.4.3.16");

        // RSASSA-PSS — parameters carried via PSSParameterSpec.
        provider.addAlgorithmImplementation("Signature", "RSASSA-PSS",
                PREFIX + "RSAPSSSignatureSpi", attr,
                (arg) -> new RSAPSSSignatureSpi());
        provider.addAlias("Signature", "RSASSA-PSS", "1.2.840.113549.1.1.10");

        // Per-digest RSASSA-PSS convenience names. BouncyCastle's PKIX/CMS layer
        // derives "<digest>WITHRSAANDMGF1" from an id-RSASSA-PSS AlgorithmIdentifier
        // (with "<digest>WITHRSASSA-PSS" as the fallback name) and, for default PSS
        // parameters, does NOT call setParameter — so each name must carry its own
        // digest default (with MGF1 over the same hash). Non-default parameters are
        // still applied via engineSetParameter, overriding the name's default.
        registerPssSignature(provider, attr, "SHA1", "SHA-1");
        registerPssSignature(provider, attr, "SHA224", "SHA-224");
        registerPssSignature(provider, attr, "SHA256", "SHA-256");
        registerPssSignature(provider, attr, "SHA384", "SHA-384");
        registerPssSignature(provider, attr, "SHA512", "SHA-512");
        registerPssSignature(provider, attr, "SHA3-224", "SHA3-224");
        registerPssSignature(provider, attr, "SHA3-256", "SHA3-256");
        registerPssSignature(provider, attr, "SHA3-384", "SHA3-384");
        registerPssSignature(provider, attr, "SHA3-512", "SHA3-512");

        // RSA-OAEP cipher. The provider registers only the bare "RSA"
        // primary; transformation strings like
        //   "RSA/ECB/OAEPPadding"
        //   "RSA/ECB/OAEPWith<MD>AndMGF1Padding"
        //   "RSA/None/OAEPPadding"
        // are resolved by JCE's algorithm-only fallback (Cipher.Transform
        // form 4): algo=RSA + engineSetMode("ECB") + engineSetPadding("OAEPWith…").
        //
        // We deliberately do NOT add aliases for the per-digest OAEP
        // transformations: doing so would let JCE match those names via
        // form 1 (full-transformation match), at which point setMode and
        // setPadding are skipped and the digest embedded in the alias is
        // silently ignored — every variant collapses to the SPI's default
        // (SHA-256 here). The form-4 path is what actually invokes
        // engineSetPadding, where the digest is parsed out of the name.
        Map<String, String> cipherAttr = new HashMap<>(attr);
        provider.addAlgorithmImplementation("Cipher", "RSA",
                PREFIX + "RSAOAEPCipherSpi", cipherAttr,
                (arg) -> new RSAOAEPCipherSpi());
        provider.addAlias("Cipher", "RSA", "1.2.840.113549.1.1.1");

        // RSA-PKCS#1 v1.5 cipher. Registered as a separate primary
        // ("RSA/ECB/PKCS1Padding") so the JCE name parser dispatches
        // PKCS#1 transformations to a dedicated SPI instance — our
        // RSA-OAEP SPI rejects the "PKCS1Padding" padding string.
        Map<String, String> pkcs1Attr = new HashMap<>(attr);
        provider.addAlgorithmImplementation("Cipher", "RSA/ECB/PKCS1Padding",
                PREFIX + "RSAPKCS1CipherSpi", pkcs1Attr,
                (arg) -> new RSAPKCS1CipherSpi());
        provider.addAlias("Cipher", "RSA/ECB/PKCS1Padding", "RSA/None/PKCS1Padding");
    }

    /**
     * Register a {@code <digest>WITHRSAANDMGF1} PSS Signature whose digest (and
     * MGF1 hash) default to {@code opensslDigest}, plus the equivalent
     * {@code <digest>WITHRSASSA-PSS} alias.
     */
    private static void registerPssSignature(JostleProvider provider,
                                             Map<String, String> attr,
                                             String digestJcaName,
                                             String opensslDigest)
    {
        String mgf1Name = digestJcaName + "WITHRSAANDMGF1";
        // Unique creatorMap key per digest (the map is keyed by this class-name
        // string; reusing the bare SPI name collides with the generic RSASSA-PSS
        // registration and the other per-digest entries).
        String implName = PREFIX + "RSAPSSSignatureSpi$" + digestJcaName.replace("-", "_");
        provider.addAlgorithmImplementation("Signature", mgf1Name,
                implName, attr,
                (arg) -> new RSAPSSSignatureSpi(opensslDigest));
        provider.addAlias("Signature", mgf1Name, digestJcaName + "WITHRSASSA-PSS");
    }

    private static void registerPkcs1Signature(JostleProvider provider,
                                               Map<String, String> attr,
                                               String name,
                                               String digestName,
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
