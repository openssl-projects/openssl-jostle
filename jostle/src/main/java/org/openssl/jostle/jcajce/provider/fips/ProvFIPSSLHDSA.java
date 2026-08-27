/*
 *  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider.fips;


import org.openssl.jostle.jcajce.provider.slhdsa.SLHDSAKeyFactorySpi;
import org.openssl.jostle.jcajce.provider.slhdsa.SLHDSAKeyPairGenerator;
import org.openssl.jostle.jcajce.provider.slhdsa.SLHDSASignatureSpi;
import org.openssl.jostle.jcajce.spec.OSSLKeyType;
import org.openssl.jostle.jcajce.spec.SLHDSAParameterSpec;
import org.openssl.jostle.util.asn1.ASN1ObjectIdentifier;
import org.openssl.jostle.util.asn1.oids.NISTObjectIdentifiers;

import java.util.HashMap;
import java.util.Map;

/**
 * SLH-DSA registrations for the FIPS provider, mirroring ProvSLHDSA's surface
 * bound to the FIPS interface library.
 *
 * <p><b>Registered only when the loaded module serves the family.</b> The two
 * supported modules disagree, and it is a module-VERSION difference rather
 * than a fipsinstall configuration one - measured with real operations under
 * both the -pedantic and the default config
 * (fips-c-review/probes/pqc_op_probe.c):
 *
 * <pre>
 *   3.1.2 : keymgmt fetch = 0  -&gt; nothing registered
 *   3.5.7 : keymgmt fetch = 1  -&gt; full keygen / sign / verify, both configs
 * </pre>
 *
 * <p>Because the fetch answers it completely, this is a registration-time gate
 * rather than a use-time refusal: a caller gets {@code NoSuchAlgorithmException}
 * from {@code getInstance} and can fall through to another provider, instead of
 * an opaque failure at first use. See {@code FIPSCapabilities} for the scoping
 * rule and why no failure classifier is needed here (unlike DSA generation).
 *
 * <p>This is <b>capability</b> filtering, not <b>approval</b> filtering:
 * JSLFIPS serves what the module serves, and the compliance determination
 * belongs to the operator.
 */
class ProvFIPSSLHDSA
{
    private static final String PREFIX = "org.openssl.jostle.jcajce.provider.slhdsa.";

    public void configure(final JostleFIPSProvider provider)
    {
        if (!FIPSCapabilities.canFetchKeyMgmt("SLH-DSA-SHA2-128S"))
        {
            return;
        }
        configureSLHDSA(provider);
    }


    private void configureSLHDSA(final JostleFIPSProvider provider)
    {

        String[] algNames = new String[]
                {
                        "SLH-DSA-SHA2-128S",
                        "SLH-DSA-SHA2-128F",
                        "SLH-DSA-SHA2-192S",
                        "SLH-DSA-SHA2-192F",
                        "SLH-DSA-SHA2-256S",
                        "SLH-DSA-SHA2-256F",
                        "SLH-DSA-SHAKE-128S",
                        "SLH-DSA-SHAKE-128F",
                        "SLH-DSA-SHAKE-192S",
                        "SLH-DSA-SHAKE-192F",
                        "SLH-DSA-SHAKE-256S",
                        "SLH-DSA-SHAKE-256F"
                };


        final Map<String, String> slhdsaKeyGenAttr = new HashMap<String, String>();
        provider.addAlgorithmImplementation("KeyPairGenerator", "SLHDSA", PREFIX + "SLHDSAKeyPairGenerator", slhdsaKeyGenAttr, (arg) -> new SLHDSAKeyPairGenerator(FIPSNISelector.SLHDSAServiceNI, FIPSNISelector.SpecNI, "SLH-DSA", provider));
        provider.addAlias("KeyPairGenerator", "SLHDSA", "SLH-DSA");

        provider.addAlgorithmImplementation("KeyFactory", "SLHDSA", PREFIX + "SLHDSAKeyFactory", slhdsaKeyGenAttr, (arg) -> new SLHDSAKeyFactorySpi(FIPSNISelector.SLHDSAServiceNI, FIPSNISelector.SpecNI, FIPSNISelector.Asn1NI, OSSLKeyType.NONE, provider));
        provider.addAlias("KeyFactory", "SLHDSA", "SLH-DSA");


        SLHDSAParameterSpec.getParameterNames().forEach(name ->
        {
            provider.addAlgorithmImplementation("KeyPairGenerator", name, PREFIX + "SLHDSAKeyPairGeneratorSpi$" + name.replace("-", "_"), slhdsaKeyGenAttr, (arg) -> new SLHDSAKeyPairGenerator(FIPSNISelector.SLHDSAServiceNI, FIPSNISelector.SpecNI, name, provider));
            provider.addAlgorithmImplementation("KeyFactory", name, PREFIX + "SLHDSAKeyFactorySpi$" + name.replace("-", "_"), slhdsaKeyGenAttr, (arg) -> new SLHDSAKeyFactorySpi(FIPSNISelector.SLHDSAServiceNI, FIPSNISelector.SpecNI, FIPSNISelector.Asn1NI, SLHDSAParameterSpec.fromName(name).getKeyType(), provider));
        });

        final Map<String, String> slhdsaSigAttr = new HashMap<String, String>();

        provider.addAlgorithmImplementation("Signature", "SLHDSA", PREFIX + "SLHDSASignatureSpi$SLHDSA", slhdsaSigAttr, (arg) -> new SLHDSASignatureSpi(FIPSNISelector.SLHDSAServiceNI, FIPSNISelector.SpecNI, OSSLKeyType.NONE, SLHDSASignatureSpi.MessageEncoding.PURE, SLHDSASignatureSpi.Deterministic.NON_DETERMINISTIC, provider));
        provider.addAlias("Signature", "SLHDSA", "SLH-DSA");

        provider.addAlgorithmImplementation("Signature", "SLH-DSA-PURE", PREFIX + "SLHDSASignatureSpi$SLHDSA_Pure", slhdsaSigAttr, (arg) -> new SLHDSASignatureSpi(FIPSNISelector.SLHDSAServiceNI, FIPSNISelector.SpecNI, OSSLKeyType.NONE, SLHDSASignatureSpi.MessageEncoding.PURE, SLHDSASignatureSpi.Deterministic.NON_DETERMINISTIC, provider));
        provider.addAlgorithmImplementation("Signature", "SLH-DSA-NONE", PREFIX + "SLHDSASignatureSpi$SLHDSA_None", slhdsaSigAttr, (arg) -> new SLHDSASignatureSpi(FIPSNISelector.SLHDSAServiceNI, FIPSNISelector.SpecNI, OSSLKeyType.NONE, SLHDSASignatureSpi.MessageEncoding.NONE, SLHDSASignatureSpi.Deterministic.NON_DETERMINISTIC, provider));

        provider.addAlgorithmImplementation("Signature", "DET-SLH-DSA-PURE", PREFIX + "SLHDSASignatureSpi$SLHDSADetPure", slhdsaSigAttr, (arg) -> new SLHDSASignatureSpi(FIPSNISelector.SLHDSAServiceNI, FIPSNISelector.SpecNI, OSSLKeyType.NONE, SLHDSASignatureSpi.MessageEncoding.PURE, SLHDSASignatureSpi.Deterministic.DETERMINISTIC, provider));
        provider.addAlgorithmImplementation("Signature", "DET-SLH-DSA-NONE", PREFIX + "SLHDSASignatureSpi$SLHDSADetNone", slhdsaSigAttr, (arg) -> new SLHDSASignatureSpi(FIPSNISelector.SLHDSAServiceNI, FIPSNISelector.SpecNI, OSSLKeyType.NONE, SLHDSASignatureSpi.MessageEncoding.NONE, SLHDSASignatureSpi.Deterministic.DETERMINISTIC, provider));


        for (String algName : algNames)
        {
            provider.addAlgorithmImplementation("Signature", algName, PREFIX + "SLHDSASignatureSpi$" + algName.replace("-", "_"), slhdsaSigAttr, (arg) -> new SLHDSASignatureSpi(FIPSNISelector.SLHDSAServiceNI, FIPSNISelector.SpecNI, SLHDSAParameterSpec.fromName(algName).getKeyType(), SLHDSASignatureSpi.MessageEncoding.PURE, SLHDSASignatureSpi.Deterministic.NON_DETERMINISTIC, provider));
        }

        // SPKI / signature-algorithm OID aliases (NIST CSOR id-slh-dsa-*, RFC 9814),
        // aligned 1:1 with algNames above. Required so an X.509 certificate whose
        // SubjectPublicKeyInfo / signature carries the OID resolves to the JSL
        // KeyFactory and Signature (see JSLKeyX509Certificate), rather than falling
        // back to the JDK default.
        ASN1ObjectIdentifier[] oids = new ASN1ObjectIdentifier[]
                {
                        NISTObjectIdentifiers.id_slh_dsa_sha2_128s,
                        NISTObjectIdentifiers.id_slh_dsa_sha2_128f,
                        NISTObjectIdentifiers.id_slh_dsa_sha2_192s,
                        NISTObjectIdentifiers.id_slh_dsa_sha2_192f,
                        NISTObjectIdentifiers.id_slh_dsa_sha2_256s,
                        NISTObjectIdentifiers.id_slh_dsa_sha2_256f,
                        NISTObjectIdentifiers.id_slh_dsa_shake_128s,
                        NISTObjectIdentifiers.id_slh_dsa_shake_128f,
                        NISTObjectIdentifiers.id_slh_dsa_shake_192s,
                        NISTObjectIdentifiers.id_slh_dsa_shake_192f,
                        NISTObjectIdentifiers.id_slh_dsa_shake_256s,
                        NISTObjectIdentifiers.id_slh_dsa_shake_256f
                };

        for (int i = 0; i < algNames.length; i++)
        {
            provider.addAlias("KeyFactory", algNames[i], oids[i]);
            provider.addAlias("Signature", algNames[i], oids[i]);
        }

    }
}