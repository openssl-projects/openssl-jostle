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
 * Provider wiring for X25519 / X448 — RFC 7748 Montgomery curves used
 * for key agreement (XDH).
 *
 * <p>Three JCE algorithm families are registered:
 * <ol>
 *   <li>{@code KeyPairGenerator} for "XDH" (curve-at-init), "X25519",
 *       and "X448" (curve-pinned).</li>
 *   <li>{@code KeyFactory} same triple — accepts X.509 / PKCS#8
 *       encoded forms.</li>
 *   <li>{@code KeyAgreement} same triple — XDH accepts either curve;
 *       the pinned variants reject the wrong one.</li>
 * </ol>
 *
 * <p>OIDs from RFC 8410: id-X25519 = 1.3.101.110, id-X448 = 1.3.101.111
 * — registered as aliases so bcpkix can resolve by OID.
 */
class ProvXEC
{
    private static final Map<String, String> generalAttributes = new HashMap<String, String>();

    static
    {
        generalAttributes.put("SupportedKeyClasses",
                "org.openssl.jostle.jcajce.interfaces.XECKey");
        generalAttributes.put("SupportedKeyFormats", "PKCS#8|X.509");
    }

    private static final String PREFIX = ProvXEC.class.getName();

    public void configure(final JostleProvider provider)
    {
        // ---- KeyPairGenerator ----
        provider.addAlgorithmImplementation("KeyPairGenerator", "XDH",
                PREFIX + "KpgXDH", generalAttributes,
                (arg) -> new XECKeyPairGenerator());
        provider.addAlgorithmImplementation("KeyPairGenerator", "X25519",
                PREFIX + "KpgX25519", generalAttributes,
                (arg) -> new XECKeyPairGenerator(OSSLKeyType.X25519, "X25519"));
        provider.addAlias("KeyPairGenerator", "X25519", "1.3.101.110");
        provider.addAlgorithmImplementation("KeyPairGenerator", "X448",
                PREFIX + "KpgX448", generalAttributes,
                (arg) -> new XECKeyPairGenerator(OSSLKeyType.X448, "X448"));
        provider.addAlias("KeyPairGenerator", "X448", "1.3.101.111");

        // ---- KeyFactory ----
        provider.addAlgorithmImplementation("KeyFactory", "XDH",
                PREFIX + "KfXDH", generalAttributes,
                (arg) -> new XECKeyFactorySpi());
        provider.addAlgorithmImplementation("KeyFactory", "X25519",
                PREFIX + "KfX25519", generalAttributes,
                (arg) -> new XECKeyFactorySpi(OSSLKeyType.X25519));
        provider.addAlias("KeyFactory", "X25519", "1.3.101.110");
        provider.addAlgorithmImplementation("KeyFactory", "X448",
                PREFIX + "KfX448", generalAttributes,
                (arg) -> new XECKeyFactorySpi(OSSLKeyType.X448));
        provider.addAlias("KeyFactory", "X448", "1.3.101.111");

        // ---- KeyAgreement ----
        provider.addAlgorithmImplementation("KeyAgreement", "XDH",
                PREFIX + "KaXDH", generalAttributes,
                (arg) -> new XDHKeyAgreementSpi());
        provider.addAlgorithmImplementation("KeyAgreement", "X25519",
                PREFIX + "KaX25519", generalAttributes,
                (arg) -> new XDHKeyAgreementSpi(OSSLKeyType.X25519));
        provider.addAlias("KeyAgreement", "X25519", "1.3.101.110");
        provider.addAlgorithmImplementation("KeyAgreement", "X448",
                PREFIX + "KaX448", generalAttributes,
                (arg) -> new XDHKeyAgreementSpi(OSSLKeyType.X448));
        provider.addAlias("KeyAgreement", "X448", "1.3.101.111");
    }
}
