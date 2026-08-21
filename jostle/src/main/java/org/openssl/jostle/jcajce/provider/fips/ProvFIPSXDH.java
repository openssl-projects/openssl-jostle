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

import org.openssl.jostle.jcajce.provider.xec.XDHKeyAgreementSpi;
import org.openssl.jostle.jcajce.provider.xec.XECKeyFactorySpi;
import org.openssl.jostle.jcajce.provider.xec.XECKeyPairGenerator;
import org.openssl.jostle.jcajce.spec.OSSLKeyType;

import java.util.HashMap;
import java.util.Map;

/**
 * XDH (X25519 / X448) registrations for the FIPS provider, mirroring ProvXDH's
 * surface bound to the FIPS interface library.
 *
 * <p><b>Registered only when the loaded module serves them.</b> The two
 * supported modules disagree, measured through the keymgmt fetch under the
 * FIPS lib ctx's {@code fips=yes} default properties:
 *
 * <pre>
 *   3.1.2 : fetch X25519 = 1  -> keygen and agreement both work; registered
 *   3.5.7 : fetch X25519 = 0  -> inner_evp_generic_fetch: unsupported
 *                                "Non-default"; nothing registered
 * </pre>
 *
 * <p>This is the cheap, startup-decidable half of the capability split (see
 * {@link FIPSCapabilities}): a fetch answers it outright, so the services are
 * simply not registered rather than registered-then-refusing. A caller gets
 * {@code NoSuchAlgorithmException} from {@code getInstance} and can fall
 * through to another provider, instead of an opaque failure at first use.
 *
 * <p>The gate is <b>capability</b>, not <b>approval</b>. Cert #4985's security
 * policy lists X25519/X448 key agreement as a non-approved service (Table 8,
 * and §4.4 Table 13 "Key Exchange — Perform key agreement primitives on behalf
 * of the calling process") — but that is a compliance determination about a
 * particular use and it belongs to the operator, not to this provider. When
 * the module implements XDH, JSLFIPS exposes it. See
 * {@code JostleFIPSProvider.setup} for why filtering on approval was
 * abandoned: the module does not enforce its own validated envelope, 3.1.2
 * offers no runtime approved-mode indicator, and a hand-maintained subset
 * removed working algorithms from callers when it drifted.
 */
class ProvFIPSXDH
{
    private static final String PREFIX = "org.openssl.jostle.jcajce.provider.xec.";

    private static final String X25519_OID = "1.3.101.110";   // id-X25519, RFC 8410
    private static final String X448_OID = "1.3.101.111";     // id-X448, RFC 8410

    public void configure(final JostleFIPSProvider provider)
    {
        // Both curves stand or fall together: they come from the same keymgmt
        // family and no supported module has ever served one without the
        // other. Probing each separately would imply a split that does not
        // exist; probing X25519 and gating both states the real contract.
        if (!FIPSCapabilities.canFetchKeyMgmt("X25519"))
        {
            return;
        }

        final Map<String, String> attr = new HashMap<>();
        attr.put("SupportedKeyClasses", "org.openssl.jostle.jcajce.interfaces.XDHKey");
        attr.put("SupportedKeyFormats", "PKCS#8|X.509");

        provider.addAlgorithmImplementation("KeyPairGenerator", "X25519",
                PREFIX + "XECKeyPairGenerator$X25519", attr,
                (arg) -> new XECKeyPairGenerator(FIPSNISelector.XECServiceNI, FIPSNISelector.SpecNI,
                        FIPSNISelector.Asn1NI, OSSLKeyType.X25519));
        provider.addAlias("KeyPairGenerator", "X25519", X25519_OID);

        provider.addAlgorithmImplementation("KeyPairGenerator", "X448",
                PREFIX + "XECKeyPairGenerator$X448", attr,
                (arg) -> new XECKeyPairGenerator(FIPSNISelector.XECServiceNI, FIPSNISelector.SpecNI,
                        FIPSNISelector.Asn1NI, OSSLKeyType.X448));
        provider.addAlias("KeyPairGenerator", "X448", X448_OID);

        provider.addAlgorithmImplementation("KeyFactory", "X25519",
                PREFIX + "XECKeyFactorySpi$X25519", attr, (arg) -> keyFactory());
        provider.addAlias("KeyFactory", "X25519", X25519_OID);
        provider.addAlgorithmImplementation("KeyFactory", "X448",
                PREFIX + "XECKeyFactorySpi$X448", attr, (arg) -> keyFactory());
        provider.addAlias("KeyFactory", "X448", X448_OID);
        provider.addAlgorithmImplementation("KeyFactory", "XDH",
                PREFIX + "XECKeyFactorySpi$XDH", attr, (arg) -> keyFactory());

        provider.addAlgorithmImplementation("KeyAgreement", "X25519",
                PREFIX + "XDHKeyAgreementSpi$X25519", attr,
                (arg) -> new XDHKeyAgreementSpi(FIPSNISelector.ECServiceNI, keyFactory()));
        provider.addAlgorithmImplementation("KeyAgreement", "X448",
                PREFIX + "XDHKeyAgreementSpi$X448", attr,
                (arg) -> new XDHKeyAgreementSpi(FIPSNISelector.ECServiceNI, keyFactory()));
        provider.addAlgorithmImplementation("KeyAgreement", "XDH",
                PREFIX + "XDHKeyAgreementSpi$XDH", attr,
                (arg) -> new XDHKeyAgreementSpi(FIPSNISelector.ECServiceNI, keyFactory()));
    }

    private static XECKeyFactorySpi keyFactory()
    {
        return new XECKeyFactorySpi(FIPSNISelector.SpecNI, FIPSNISelector.Asn1NI);
    }
}
