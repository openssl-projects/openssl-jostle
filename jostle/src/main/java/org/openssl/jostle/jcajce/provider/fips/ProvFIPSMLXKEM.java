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

import org.openssl.jostle.jcajce.provider.mlxkem.MLXKEMKeyFactorySpi;
import org.openssl.jostle.jcajce.provider.mlxkem.MLXKEMKeyGenerator;
import org.openssl.jostle.jcajce.provider.mlxkem.MLXKEMKeyPairGenerator;
import org.openssl.jostle.jcajce.spec.MLXKEMParameterSpec;

import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Hybrid KEM registrations for the FIPS provider, mirroring ProvMLXKEM's
 * surface bound to the FIPS interface library.
 *
 * <p><b>Gated PER VARIANT, not per family.</b> Unlike ML-KEM, the four groups
 * do not arrive and depart together - measured through the FIPS lib ctx
 * ({@code fips-c-review/probes/hybrid_kem_probe.c}):
 *
 * <pre>
 *                        3.1.2    3.5.8
 *   X25519MLKEM768       no       yes
 *   X448MLKEM1024        no       NO
 *   SecP256r1MLKEM768    no       yes
 *   SecP384r1MLKEM1024   no       yes
 * </pre>
 *
 * <p>Those two are the supported modules: 3.1.2 is the CMVP-validated one
 * (cert #4985) and 3.5.8 is the OpenSSL LTS. A 3.5.7 install, measured while
 * it was still a supported target, served all four - which is the evidence
 * that the property is per variant rather than per family, and the reason the
 * gate is written this way even though no supported module currently serves
 * all four.
 *
 * <p>{@code X448MLKEM1024} is not a retraction on cryptographic grounds as far
 * as the source shows: {@code providers/fips/fipsprov.c} marks it
 * {@code FIPS_UNAPPROVED_PROPERTIES} while the other three carry
 * {@code FIPS_DEFAULT_PROPERTIES}, and the {@code CHANGES.md} entry that
 * introduced hybrid support names exactly the other three - so it was never in
 * the documented approved set, and 3.5.7 exposing it under {@code fips=yes}
 * looks like the anomaly. No NIST rationale is quotable from the tree; treat
 * the reason as unknown until the 3.5.x security policy publishes.
 *
 * <p>A family-level gate keyed on any one name is therefore wrong on 3.5.8 in
 * one direction or the other. The keymgmt fetch is a COMPLETE answer for a
 * given group: on 3.5.8, X448MLKEM1024 answers no to the KEM fetch, the
 * keymgmt fetch, keygen init and keygen alike - it is wholly absent rather
 * than present-but-refusing, so no failure classifier is needed.
 *
 * <p>This is <b>capability</b> filtering, not <b>approval</b> filtering:
 * JSLFIPS serves what the module serves, and the compliance determination
 * belongs to the operator.
 *
 * <h2>Approval status: PENDING, and deliberately not asserted</h2>
 *
 * No claim is made here in either direction, for two reasons that can be
 * checked rather than taken on trust:
 *
 * <ol>
 * <li>The 3.1.2 security policy (CMVP cert #4985) says nothing about these
 *     groups because that module does not implement them - and it lists
 *     X25519 and X448 as non-approved wholesale in its Table 8, so reasoning
 *     from it about a construction that uses one as a component would be
 *     reasoning from the wrong document.</li>
 * <li>The 3.5.x security policy is not published at the time of writing, so
 *     the treatment of a hybrid (approved ML-KEM component plus an ECDH
 *     component allowed under an implementation guidance) cannot be quoted.
 *     Quote it here when it lands; do not infer it.</li>
 * </ol>
 *
 * <p>What IS known and worth recording: the module's own
 * {@code FIPS_DEFAULT_PROPERTIES} / {@code FIPS_UNAPPROVED_PROPERTIES} split
 * in {@code providers/fips/fipsprov.c} is what moves a group in and out of a
 * {@code fips=yes} lookup, and 3.5.8 moved {@code X448MLKEM1024} to the
 * unapproved side. That is the module stating a position through its own
 * property table, which the gate above already honours - it is not this
 * provider making a determination.
 */
class ProvFIPSMLXKEM
{
    private static final String PREFIX = "org.openssl.jostle.jcajce.provider.mlxkem.";

    private static final Logger LOG = Logger.getLogger(ProvFIPSMLXKEM.class.getName());

    public void configure(final JostleFIPSProvider provider)
    {
        // Fail soft: see ProvFIPSMLKEM for why registration failures must not
        // escape a provider static initializer.
        try
        {
            configureMLXKEM(provider);
        }
        catch (Throwable t)
        {
            LOG.log(Level.WARNING, "hybrid KEM provider registration failed; the hybrid groups will be unavailable", t);
        }
    }

    private void configureMLXKEM(final JostleFIPSProvider provider)
    {
        final Map<String, String> attr = new HashMap<String, String>();

        for (final MLXKEMParameterSpec spec : MLXKEMParameterSpec.all())
        {
            String name = spec.getName();

            if (!FIPSCapabilities.canFetchKeyMgmt(name))
            {
                continue;
            }

            provider.addAlgorithmImplementation("KeyPairGenerator", name,
                    PREFIX + "MLXKEMKeyPairGenerator$" + name, attr,
                    (arg) -> new MLXKEMKeyPairGenerator(
                            FIPSNISelector.MLXKEMServiceNI, FIPSNISelector.SpecNI, spec));

            provider.addAlgorithmImplementation("KeyGenerator", name,
                    PREFIX + "MLXKEMKeyGenerator$" + name, attr,
                    (arg) -> new MLXKEMKeyGenerator(
                            FIPSNISelector.MLXKEMServiceNI, FIPSNISelector.SpecNI, spec));

            provider.addAlgorithmImplementation("KeyFactory", name,
                    PREFIX + "MLXKEMKeyFactorySpi$" + name, attr,
                    (arg) -> new MLXKEMKeyFactorySpi(
                            FIPSNISelector.MLXKEMServiceNI, FIPSNISelector.SpecNI, spec));
        }
    }
}
