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

import org.openssl.jostle.jcajce.provider.ed.EdDSAKeyPairGenerator;
import org.openssl.jostle.jcajce.provider.ed.EdKeyFactorySpi;
import org.openssl.jostle.jcajce.provider.ed.EdSignatureSpi;
import org.openssl.jostle.jcajce.spec.EdDSAParameterSpec;
import org.openssl.jostle.jcajce.spec.OSSLKeyType;
import org.openssl.jostle.util.asn1.oids.EdECObjectIdentifiers;

import java.util.HashMap;
import java.util.Map;

/**
 * EdDSA (Ed25519 / Ed448) registrations for the FIPS provider, mirroring
 * ProvED's surface bound to the FIPS interface library.
 *
 * <p><b>Registered only when the loaded module serves them</b>, and — unlike
 * every other gated family here — <b>per name</b>. The two supported modules
 * disagree, and 3.5.7 disagrees with itself across the family. Measured
 * through the FIPS lib ctx's {@code fips=yes} default properties by
 * {@code fips-c-review/probes/ed_gate_probe.c}:
 *
 * <pre>
 *   3.1.2            : keymgmt ED25519/ED448 REFUSED ("unsupported"), and
 *                      every EVP_SIGNATURE name REFUSED -> nothing registered
 *   3.5.7 default    : keymgmt ok; EVP_SIGNATURE ED25519 ok, ED25519PH ok,
 *                      ED448 ok, ED448PH ok, ED25519CTX REFUSED
 *   3.5.7 -pedantic  : byte-identical to default; no cnf switch gates Ed
 * </pre>
 *
 * <p>This is the exact inverse of {@link ProvFIPSXDH}'s direction — X25519 is
 * served on 3.1.2 and refused on 3.5.7 — so a reader looking for the usual
 * "newer module, fewer algorithms" pattern will not find it here.
 *
 * <p><b>Why ED25519CTX is gated separately.</b> The keymgmt fetch answers only
 * "is there an Ed25519 key type?", which is true on 3.5.7. But
 * {@code EdSignatureSpi} drives {@code EVP_DigestSignInit_ex} with
 * {@code instance="Ed25519ctx"} for that forced type <i>unconditionally</i>,
 * whether or not the caller supplied a context — and 3.5.7's module refuses
 * that instance with "invalid eddsa instance for attempted operation". A
 * registration would resolve through {@code getInstance} and then fail at
 * every {@code init}: the "registration is not usability" trap. The
 * signature-fetch probe distinguishes the case exactly, and keeps doing so if
 * a later module adds ctx — nothing here is transcribed.
 *
 * <p>The gate is <b>capability</b>, not <b>approval</b>. Cert #4985's security
 * policy (the 3.1.2 module) lists Ed25519 and Ed448 in Table 8 as
 * non-approved, not-allowed algorithms — but that module does not implement
 * them at all, so the question never arises there. For a 3.5.x module the
 * approval position comes from its own certificate, which is not yet
 * available; FIPS 186-5 §7.8 standardises EdDSA, so it is expected to be an
 * approved signature algorithm, but this provider asserts nothing. As
 * everywhere else in JSLFIPS, what the module implements is what gets served,
 * and whether a particular use is approved is the operator's determination.
 * See {@code JostleFIPSProvider.setup} for why filtering on approval was
 * abandoned.
 */
class ProvFIPSED
{
    private static final String PREFIX = "org.openssl.jostle.jcajce.provider.ed.";

    public void configure(final JostleFIPSProvider provider)
    {
        // Both curves come from the same keymgmt family and no supported
        // module has served one without the other, so one keymgmt probe gates
        // the family. The per-NAME signature probes below then decide which
        // Signature services are usable.
        if (!FIPSCapabilities.canFetchKeyMgmt("ED25519"))
        {
            return;
        }

        final boolean ed25519 = FIPSCapabilities.canFetchSignature("ED25519");
        final boolean ed25519ph = FIPSCapabilities.canFetchSignature("ED25519PH");
        final boolean ed25519ctx = FIPSCapabilities.canFetchSignature("ED25519CTX");
        final boolean ed448 = FIPSCapabilities.canFetchSignature("ED448");
        final boolean ed448ph = FIPSCapabilities.canFetchSignature("ED448PH");

        final Map<String, String> attr = new HashMap<String, String>();

        provider.addAlgorithmImplementation("KeyPairGenerator", "ED",
                PREFIX + "EdDSAKeyPairGenerator", attr, (arg) -> keyPairGenerator(provider, "EDDSA"));
        provider.addAlias("KeyPairGenerator", "ED", "EDDSA", "EdDSA");
        provider.addAlgorithmImplementation("KeyPairGenerator", "ED25519",
                PREFIX + "EdDSAKeyPairGenerator$ED25519", attr,
                (arg) -> keyPairGenerator(provider, EdDSAParameterSpec.ED25519));
        provider.addAlias("KeyPairGenerator", "ED25519", "Ed25519");
        provider.addAlgorithmImplementation("KeyPairGenerator", "ED448",
                PREFIX + "EdDSAKeyPairGenerator$ED448", attr,
                (arg) -> keyPairGenerator(provider, EdDSAParameterSpec.ED448));
        provider.addAlias("KeyPairGenerator", "ED448", "Ed448");

        final Map<String, String> sigAttr = new HashMap<String, String>();

        // The generic "EDDSA" signature takes its instance from the key's own
        // type ("Ed25519" / "Ed448" — the pure forms), so it is usable exactly
        // when at least one pure form is.
        if (ed25519 || ed448)
        {
            provider.addAlgorithmImplementation("Signature", "EDDSA",
                    PREFIX + "EdSignatureSpi", sigAttr, (arg) -> signature(provider, OSSLKeyType.NONE));
            provider.addAlias("Signature", "EDDSA", "EdDSA");
        }

        if (ed25519)
        {
            provider.addAlgorithmImplementation("Signature", "ED25519",
                    PREFIX + "EdSignatureSpi$ED25519", sigAttr, (arg) -> signature(provider, OSSLKeyType.ED25519));
            provider.addAlias("Signature", "ED25519", "Ed25519");
            provider.addAlias("Signature", "ED25519", EdECObjectIdentifiers.id_Ed25519);
        }
        if (ed25519ph)
        {
            provider.addAlgorithmImplementation("Signature", "ED25519PH",
                    PREFIX + "EdSignatureSpi$ED25519ph", sigAttr, (arg) -> signature(provider, OSSLKeyType.Ed25519ph));
            provider.addAlias("Signature", "ED25519PH", "Ed25519ph");
        }
        if (ed25519ctx)
        {
            provider.addAlgorithmImplementation("Signature", "ED25519CTX",
                    PREFIX + "EdSignatureSpi$ED25519ctx", sigAttr, (arg) -> signature(provider, OSSLKeyType.Ed25519ctx));
            provider.addAlias("Signature", "ED25519CTX", "Ed25519ctx");
        }
        if (ed448)
        {
            provider.addAlgorithmImplementation("Signature", "ED448",
                    PREFIX + "EdSignatureSpi$ED448", sigAttr, (arg) -> signature(provider, OSSLKeyType.ED448));
            provider.addAlias("Signature", "ED448", "Ed448");
            provider.addAlias("Signature", "ED448", EdECObjectIdentifiers.id_Ed448);
        }
        if (ed448ph)
        {
            provider.addAlgorithmImplementation("Signature", "ED448PH",
                    PREFIX + "EdSignatureSpi$ED448ph", sigAttr, (arg) -> signature(provider, OSSLKeyType.ED448ph));
            provider.addAlias("Signature", "ED448PH", "Ed448ph");
        }

        final Map<String, String> kfAttr = new HashMap<String, String>();
        provider.addAlgorithmImplementation("KeyFactory", "ED",
                PREFIX + "EdKeyFactorySpi", kfAttr, (arg) -> keyFactory(provider, OSSLKeyType.NONE));
        provider.addAlias("KeyFactory", "ED", "EDDSA", "EdDSA");
        provider.addAlgorithmImplementation("KeyFactory", "ED25519",
                PREFIX + "EdKeyFactorySpi$ED25519", kfAttr, (arg) -> keyFactory(provider, OSSLKeyType.ED25519));
        provider.addAlias("KeyFactory", "ED25519", "Ed25519");
        provider.addAlias("KeyFactory", "ED25519", EdECObjectIdentifiers.id_Ed25519);
        provider.addAlgorithmImplementation("KeyFactory", "ED448",
                PREFIX + "EdKeyFactorySpi$ED448", kfAttr, (arg) -> keyFactory(provider, OSSLKeyType.ED448));
        provider.addAlias("KeyFactory", "ED448", "Ed448");
        provider.addAlias("KeyFactory", "ED448", EdECObjectIdentifiers.id_Ed448);
    }

    /**
     * A KeyFactory bound to {@code provider}. Every key it produces, and every
     * key it accepts, belongs to that provider INSTANCE (MT-14).
     */
    private static EdKeyFactorySpi keyFactory(JostleFIPSProvider provider, OSSLKeyType fixedType)
    {
        return new EdKeyFactorySpi(FIPSNISelector.EDServiceNI, FIPSNISelector.SpecNI,
                FIPSNISelector.Asn1NI, fixedType, provider);
    }

    private static EdSignatureSpi signature(JostleFIPSProvider provider, OSSLKeyType forcedType)
    {
        return new EdSignatureSpi(FIPSNISelector.EDServiceNI,
                keyFactory(provider, OSSLKeyType.NONE), forcedType);
    }

    private static EdDSAKeyPairGenerator keyPairGenerator(JostleFIPSProvider provider, Object algorithm)
    {
        return new EdDSAKeyPairGenerator(FIPSNISelector.EDServiceNI, FIPSNISelector.SpecNI,
                FIPSNISelector.Asn1NI, algorithm, provider);
    }
}
