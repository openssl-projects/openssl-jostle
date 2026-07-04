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

import org.openssl.jostle.jcajce.spec.OSSLKeyType;
import org.openssl.jostle.jcajce.provider.xec.XDHKeyAgreementSpi;
import org.openssl.jostle.jcajce.provider.xec.XECKeyFactorySpi;
import org.openssl.jostle.jcajce.provider.xec.XECKeyPairGenerator;

import java.util.HashMap;
import java.util.Map;

/**
 * XDH (X25519/X448) registrations for the FIPS provider, mirroring
 * ProvXDH's surface bound to the FIPS interface library. X25519/X448 key
 * agreement is approved (SP 800-186 / SP 800-56A rev3 alignment in the
 * module); the module gates use through the fips=yes lib ctx.
 */
class ProvFIPSXDH
{
    private static final String PREFIX = "org.openssl.jostle.jcajce.provider.xec.";

    private static final String X25519_OID = "1.3.101.110";
    private static final String X448_OID = "1.3.101.111";

    public void configure(final JostleFIPSProvider provider)
    {
        final Map<String, String> attr = new HashMap<>();
        attr.put("SupportedKeyClasses",
                "java.security.interfaces.XECPublicKey|java.security.interfaces.XECPrivateKey");
        attr.put("SupportedKeyFormats", "PKCS#8|X.509");

        provider.addAlgorithmImplementation("KeyPairGenerator", "X25519",
                PREFIX + "XECKeyPairGenerator$X25519", attr,
                (arg) -> new XECKeyPairGenerator(
                        FIPSNISelector.XECServiceNI, FIPSNISelector.SpecNI, FIPSNISelector.Asn1NI, OSSLKeyType.X25519));
        provider.addAlias("KeyPairGenerator", "X25519", X25519_OID);
        provider.addAlgorithmImplementation("KeyPairGenerator", "X448",
                PREFIX + "XECKeyPairGenerator$X448", attr,
                (arg) -> new XECKeyPairGenerator(
                        FIPSNISelector.XECServiceNI, FIPSNISelector.SpecNI, FIPSNISelector.Asn1NI, OSSLKeyType.X448));
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
                PREFIX + "XDHKeyAgreementSpi$X25519", attr, (arg) -> agreement());
        provider.addAlgorithmImplementation("KeyAgreement", "X448",
                PREFIX + "XDHKeyAgreementSpi$X448", attr, (arg) -> agreement());
        provider.addAlgorithmImplementation("KeyAgreement", "XDH",
                PREFIX + "XDHKeyAgreementSpi$XDH", attr, (arg) -> agreement());
    }

    private static XECKeyFactorySpi keyFactory()
    {
        return new XECKeyFactorySpi(FIPSNISelector.SpecNI, FIPSNISelector.Asn1NI);
    }

    private static XDHKeyAgreementSpi agreement()
    {
        return new XDHKeyAgreementSpi(FIPSNISelector.ECServiceNI, keyFactory());
    }
}
