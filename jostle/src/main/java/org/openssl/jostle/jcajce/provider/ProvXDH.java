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

import org.openssl.jostle.jcajce.provider.xec.XDHKeyAgreementSpi;
import org.openssl.jostle.jcajce.provider.xec.XDHWithCKDFKeyAgreementSpi;
import org.openssl.jostle.jcajce.provider.xec.XDHWithHKDFKeyAgreementSpi;
import org.openssl.jostle.jcajce.provider.xec.XECKeyFactorySpi;
import org.openssl.jostle.jcajce.provider.xec.XECKeyPairGenerator;
import org.openssl.jostle.jcajce.spec.OSSLKeyType;

import java.util.HashMap;
import java.util.Map;
import org.openssl.jostle.util.asn1.oids.EdECObjectIdentifiers;
import org.openssl.jostle.util.asn1.oids.PKCSObjectIdentifiers;

/**
 * Registers the XDH (X25519 / X448) KeyAgreement, KeyPairGenerator and
 * KeyFactory. Key agreement reuses the EC kex native path (the C side is
 * type-agnostic); XEC adds only key generation. OIDs are from RFC 8410.
 *
 * <p>The creatorMap key (the class-name string) must be unique per
 * registration, so the per-variant entries use a synthetic {@code $X25519}
 * / {@code $X448} / {@code $XDH} suffix — the lambda constructs the
 * instance, so the string is never reflected on.
 */
class ProvXDH
{

    private static final String X25519_OID = EdECObjectIdentifiers.id_X25519.getId();   // id-X25519, RFC 8410
    private static final String X448_OID = EdECObjectIdentifiers.id_X448.getId();     // id-X448, RFC 8410

    // RFC 8418 section 7: dhSinglePass-stdDH-hkdf-sha{256,384,512}-scheme,
    // under smime-alg 1.2.840.113549.1.9.16.3.
    private static final String HKDF_SHA256_SCHEME_OID = PKCSObjectIdentifiers.dhSinglePass_stdDH_hkdf_sha256_scheme.getId();
    private static final String HKDF_SHA384_SCHEME_OID = PKCSObjectIdentifiers.dhSinglePass_stdDH_hkdf_sha384_scheme.getId();
    private static final String HKDF_SHA512_SCHEME_OID = PKCSObjectIdentifiers.dhSinglePass_stdDH_hkdf_sha512_scheme.getId();

    public void configure(final JostleProvider provider)
    {
        final Map<String, String> attr = new HashMap<>();
        attr.put("SupportedKeyClasses", "org.openssl.jostle.jcajce.interfaces.XDHKey");
        attr.put("SupportedKeyFormats", "PKCS#8|X.509");

        // KeyPairGenerator — one instance per variant; the algorithm name
        // fixes the key type (no NamedParameterSpec needed).
        provider.addAlgorithmImplementation("KeyPairGenerator", "X25519",
                XECKeyPairGenerator.class.getName(), attr,
                (arg) -> new XECKeyPairGenerator(NISelector.XECServiceNI,
                        NISelector.SpecNI, NISelector.Asn1NI, OSSLKeyType.X25519, provider));
        provider.addAlias("KeyPairGenerator", "X25519", X25519_OID);

        provider.addAlgorithmImplementation("KeyPairGenerator", "X448",
                XECKeyPairGenerator.class.getName(), attr,
                (arg) -> new XECKeyPairGenerator(NISelector.XECServiceNI,
                        NISelector.SpecNI, NISelector.Asn1NI, OSSLKeyType.X448, provider));
        provider.addAlias("KeyPairGenerator", "X448", X448_OID);

        // KeyFactory — one SPI handles both variants (the decoded key carries
        // its type). Registered per name, under the "XDH" family, and by OID.
        provider.addAlgorithmImplementation("KeyFactory", "X25519",
                XECKeyFactorySpi.class.getName(), attr, (arg) -> keyFactory(provider));
        provider.addAlias("KeyFactory", "X25519", X25519_OID);
        provider.addAlgorithmImplementation("KeyFactory", "X448",
                XECKeyFactorySpi.class.getName(), attr, (arg) -> keyFactory(provider));
        provider.addAlias("KeyFactory", "X448", X448_OID);
        provider.addAlgorithmImplementation("KeyFactory", "XDH",
                XECKeyFactorySpi.class.getName(), attr, (arg) -> keyFactory(provider));

        // KeyAgreement — one SPI handles both variants (the key carries its type).
        provider.addAlgorithmImplementation("KeyAgreement", "X25519",
                XDHKeyAgreementSpi.class.getName(), attr,
                (arg) -> new XDHKeyAgreementSpi(NISelector.ECServiceNI, keyFactory(provider)));
        provider.addAlgorithmImplementation("KeyAgreement", "X448",
                XDHKeyAgreementSpi.class.getName(), attr,
                (arg) -> new XDHKeyAgreementSpi(NISelector.ECServiceNI, keyFactory(provider)));
        provider.addAlgorithmImplementation("KeyAgreement", "XDH",
                XDHKeyAgreementSpi.class.getName(), attr,
                (arg) -> new XDHKeyAgreementSpi(NISelector.ECServiceNI, keyFactory(provider)));

        // RFC 8418 HKDF schemes, so KeyAgreeRecipientInfo for Montgomery
        // recipients resolves. The names are BouncyCastle's spelling; one SPI
        // serves both curves, as the key carries its type. The KDF NI comes
        // from the same selector as the agreement NI so the derivation runs in
        // this provider's own lib ctx.
        final String hkdfSpi = XDHWithHKDFKeyAgreementSpi.class.getName();
        provider.addAlgorithmImplementation("KeyAgreement", "XDHwithSHA256HKDF",
                hkdfSpi, attr,
                (arg) -> new XDHWithHKDFKeyAgreementSpi(NISelector.ECServiceNI,
                        keyFactory(provider), NISelector.KdfNI, "SHA-256"));
        provider.addAlias("KeyAgreement", "XDHwithSHA256HKDF", HKDF_SHA256_SCHEME_OID);

        provider.addAlgorithmImplementation("KeyAgreement", "XDHwithSHA384HKDF",
                hkdfSpi, attr,
                (arg) -> new XDHWithHKDFKeyAgreementSpi(NISelector.ECServiceNI,
                        keyFactory(provider), NISelector.KdfNI, "SHA-384"));
        provider.addAlias("KeyAgreement", "XDHwithSHA384HKDF", HKDF_SHA384_SCHEME_OID);

        provider.addAlgorithmImplementation("KeyAgreement", "XDHwithSHA512HKDF",
                hkdfSpi, attr,
                (arg) -> new XDHWithHKDFKeyAgreementSpi(NISelector.ECServiceNI,
                        keyFactory(provider), NISelector.KdfNI, "SHA-512"));
        provider.addAlias("KeyAgreement", "XDHwithSHA512HKDF", HKDF_SHA512_SCHEME_OID);

        // RFC 6637 §7 SP 800-56C one-step KDF, curve-bound per BC's own
        // registered names (see ECWithCKDFKeyAgreementSpi and
        // XDHWithCKDFKeyAgreementSpi javadoc). No OID aliases — PGP has no
        // ASN.1 scheme-OID negotiation, bcpg resolves purely by JCA name.
        final String ckdfSpi = XDHWithCKDFKeyAgreementSpi.class.getName();
        provider.addAlgorithmImplementation("KeyAgreement", "X25519withSHA256CKDF",
                ckdfSpi, attr,
                (arg) -> new XDHWithCKDFKeyAgreementSpi(NISelector.ECServiceNI,
                        keyFactory(provider), NISelector.KdfNI, "X25519", "SHA-256"));
        provider.addAlgorithmImplementation("KeyAgreement", "X25519withSHA384CKDF",
                ckdfSpi, attr,
                (arg) -> new XDHWithCKDFKeyAgreementSpi(NISelector.ECServiceNI,
                        keyFactory(provider), NISelector.KdfNI, "X25519", "SHA-384"));
        provider.addAlgorithmImplementation("KeyAgreement", "X25519withSHA512CKDF",
                ckdfSpi, attr,
                (arg) -> new XDHWithCKDFKeyAgreementSpi(NISelector.ECServiceNI,
                        keyFactory(provider), NISelector.KdfNI, "X25519", "SHA-512"));
        provider.addAlgorithmImplementation("KeyAgreement", "X448withSHA256CKDF",
                ckdfSpi, attr,
                (arg) -> new XDHWithCKDFKeyAgreementSpi(NISelector.ECServiceNI,
                        keyFactory(provider), NISelector.KdfNI, "X448", "SHA-256"));
        provider.addAlgorithmImplementation("KeyAgreement", "X448withSHA384CKDF",
                ckdfSpi, attr,
                (arg) -> new XDHWithCKDFKeyAgreementSpi(NISelector.ECServiceNI,
                        keyFactory(provider), NISelector.KdfNI, "X448", "SHA-384"));
        provider.addAlgorithmImplementation("KeyAgreement", "X448withSHA512CKDF",
                ckdfSpi, attr,
                (arg) -> new XDHWithCKDFKeyAgreementSpi(NISelector.ECServiceNI,
                        keyFactory(provider), NISelector.KdfNI, "X448", "SHA-512"));
    }

    /**
     * A KeyFactory bound to {@code provider}. Every key it produces, and every
     * key it accepts, belongs to that provider INSTANCE (MT-14).
     */
    private static XECKeyFactorySpi keyFactory(JostleProvider provider)
    {
        return new XECKeyFactorySpi(NISelector.SpecNI, NISelector.Asn1NI, provider);
    }
}
