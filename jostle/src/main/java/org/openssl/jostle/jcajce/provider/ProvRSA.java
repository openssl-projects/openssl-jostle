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
import org.openssl.jostle.util.asn1.oids.NISTObjectIdentifiers;

import java.util.HashMap;
import java.util.Map;

class ProvRSA
{
    /** ISO 18033-2 {@code id-kem-rsa}, the OID CMS names in KEMRecipientInfo.kem. */
    static final String ID_KEM_RSA = "1.0.18033.2.2.4";
    /** PKCS-arc {@code id-rsa-KEM}, used when an RSA-KEM SPKI names the cipher (RFC 9690 s3.3). */
    static final String ID_RSA_KEM = "1.2.840.113549.1.9.16.3.14";

    public void configure(final JostleProvider provider)
    {
        final Map<String, String> attr = new HashMap<>();
        attr.put("SupportedKeyClasses",
                "java.security.interfaces.RSAPublicKey|java.security.interfaces.RSAPrivateKey");
        attr.put("SupportedKeyFormats", "PKCS#8|X.509");

        // KeyPairGenerator.
        provider.addAlgorithmImplementation("KeyPairGenerator", "RSA",
                RSAKeyPairGenerator.class.getName(), attr,
                (arg) -> new RSAKeyPairGenerator(
                        NISelector.RSAServiceNI, NISelector.SpecNI, NISelector.Asn1NI, provider));
        provider.addAlias("KeyPairGenerator", "RSA", "1.2.840.113549.1.1.1");

        // KeyFactory.
        provider.addAlgorithmImplementation("KeyFactory", "RSA",
                RSAKeyFactorySpi.class.getName(), attr,
                (arg) -> keyFactory(provider));
        provider.addAlias("KeyFactory", "RSA", "1.2.840.113549.1.1.1");
        // id-RSASSA-PSS SPKI. A PSS-PSS certificate's key carries OID
        // 1.2.840.113549.1.1.10, not rsaEncryption, and the JCA name for it is
        // "RSASSA-PSS". The RSA KeyFactory decodes that SPKI form correctly
        // (probe-confirmed) — only the names were missing, so a caller asking
        // by either got NoSuchAlgorithmException, and the provider-bound
        // CertificateFactory's OID-keyed key re-derivation failed loud
        // (JSLKeyX509Certificate), surfacing to TLS as bad_certificate(42).
        provider.addAlias("KeyFactory", "RSA", "1.2.840.113549.1.1.10", "RSASSA-PSS");

        // PKCS#1 v1.5 Signature variants. MD5 is registered for legacy
        // interop only — callers should prefer SHA-2 / SHA-3 family.
        registerPkcs1Signature(provider, attr,
                "MD5withRSA", "MD5", "1.2.840.113549.1.1.4");
        registerPkcs1Signature(provider, attr,
                "SHA1withRSA", "SHA-1", "1.2.840.113549.1.1.5");
        registerPkcs1Signature(provider, attr,
                "SHA224withRSA", "SHA-224", "1.2.840.113549.1.1.14");
        registerPkcs1Signature(provider, attr,
                "SHA256withRSA", "SHA-256", "1.2.840.113549.1.1.11");
        registerPkcs1Signature(provider, attr,
                "SHA384withRSA", "SHA-384", "1.2.840.113549.1.1.12");
        registerPkcs1Signature(provider, attr,
                "SHA512withRSA", "SHA-512", "1.2.840.113549.1.1.13");
        registerPkcs1Signature(provider, attr,
                "SHA3-224withRSA", "SHA3-224", NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_224.getId());
        registerPkcs1Signature(provider, attr,
                "SHA3-256withRSA", "SHA3-256", NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_256.getId());
        registerPkcs1Signature(provider, attr,
                "SHA3-384withRSA", "SHA3-384", NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_384.getId());
        registerPkcs1Signature(provider, attr,
                "SHA3-512withRSA", "SHA3-512", NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_512.getId());

        // Raw PKCS#1 v1.5 ("NoneWithRSA"): the caller has already formed the
        // bytes to sign (e.g. a DigestInfo), so there is no per-digest OID to
        // alias. Required by TLS 1.3's externally-hashed RSA CertificateVerify
        // (BouncyCastle's JcaTlsRSASigner.getRawSigner()).
        provider.addAlgorithmImplementation("Signature", "NoneWithRSA",
                RSASignatureSpi.None.class.getName(), attr,
                (arg) -> new RSASignatureSpi.None(NISelector.RSAServiceNI,
                        keyFactory(provider)));

        // RSASSA-PSS — parameters carried via PSSParameterSpec.
        provider.addAlgorithmImplementation("Signature", "RSASSA-PSS",
                RSAPSSSignatureSpi.class.getName(), attr,
                (arg) -> new RSAPSSSignatureSpi(NISelector.RSAServiceNI, keyFactory(provider)));
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
                RSAOAEPCipherSpi.class.getName(), cipherAttr,
                (arg) -> new RSAOAEPCipherSpi(NISelector.RSAOAEPCipherNI, keyFactory(provider)));
        provider.addAlias("Cipher", "RSA", "1.2.840.113549.1.1.1");

        // RSA-PKCS#1 v1.5 cipher. Registered as a separate primary
        // ("RSA/ECB/PKCS1Padding") so the JCE name parser dispatches
        // PKCS#1 transformations to a dedicated SPI instance — our
        // RSA-OAEP SPI rejects the "PKCS1Padding" padding string.
        Map<String, String> pkcs1Attr = new HashMap<>(attr);
        provider.addAlgorithmImplementation("Cipher", "RSA/ECB/PKCS1Padding",
                RSAPKCS1CipherSpi.class.getName(), pkcs1Attr,
                (arg) -> new RSAPKCS1CipherSpi(NISelector.RSAPKCS1CipherNI, keyFactory(provider)));
        provider.addAlias("Cipher", "RSA/ECB/PKCS1Padding", "RSA/None/PKCS1Padding");

        // RSA-KEM key transport (ISO 18033-2 / RFC 9690) for the CMS
        // KEMRecipientInfo path. The name and both OID aliases are BouncyCastle's,
        // deliberately: interop with BC's JceKEMRecipientInfoGenerator /
        // JceKEMEnvelopedRecipient is the entire reason this exists, and a call
        // site that resolves the cipher by either OID must reach the same SPI.
        //
        //   id-kem-rsa  1.0.18033.2.2.4                  ISO 18033-2, named in
        //                                                KEMRecipientInfo.kem
        //   id-rsa-KEM  1.2.840.113549.1.9.16.3.14       PKCS arc, used when an
        //                                                RSA-KEM SubjectPublicKeyInfo
        //                                                names the cipher directly
        //                                                (RFC 9690 s3.3)
        Map<String, String> ktsAttr = new HashMap<>(attr);
        provider.addAlgorithmImplementation("Cipher", "RSA-KTS-KEM-KWS",
                RSAKEMCipherSpi.class.getName(), ktsAttr,
                (arg) -> new RSAKEMCipherSpi(keyFactory(provider), NISelector.SpecNI));
        provider.addAlias("Cipher", "RSA-KTS-KEM-KWS",
                ID_KEM_RSA, ID_RSA_KEM);
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
        provider.addAlgorithmImplementation("Signature", mgf1Name,
                RSAPSSSignatureSpi.class.getName(), attr,
                (arg) -> new RSAPSSSignatureSpi(NISelector.RSAServiceNI,
                        keyFactory(provider), opensslDigest));
        provider.addAlias("Signature", mgf1Name, digestJcaName + "WITHRSASSA-PSS");
    }

    private static void registerPkcs1Signature(JostleProvider provider,
                                               Map<String, String> attr,
                                               String name,
                                               String digestName,
                                               String oid)
    {
        provider.addAlgorithmImplementation("Signature", name,
                RSASignatureSpi.class.getName(), attr,
                (arg) -> new RSASignatureSpi(NISelector.RSAServiceNI,
                        keyFactory(provider), digestName));
        provider.addAlias("Signature", name, oid);
    }

    /**
     * A KeyFactory bound to {@code provider}. Every key it produces, and every
     * key it accepts, belongs to that provider INSTANCE (MT-14).
     */
    private static RSAKeyFactorySpi keyFactory(JostleProvider provider)
    {
        return new RSAKeyFactorySpi(
                NISelector.RSAServiceNI, NISelector.SpecNI, NISelector.Asn1NI, provider);
    }
}
