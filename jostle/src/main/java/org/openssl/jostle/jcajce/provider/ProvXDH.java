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
import org.openssl.jostle.jcajce.provider.xec.XECKeyFactorySpi;
import org.openssl.jostle.jcajce.provider.xec.XECKeyPairGenerator;
import org.openssl.jostle.jcajce.spec.OSSLKeyType;

import java.util.HashMap;
import java.util.Map;

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

    private static final String X25519_OID = "1.3.101.110";   // id-X25519, RFC 8410
    private static final String X448_OID = "1.3.101.111";     // id-X448, RFC 8410

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
