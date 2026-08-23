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

import org.openssl.jostle.jcajce.provider.mlkem.MLKEMKeyFactorySpi;
import org.openssl.jostle.jcajce.provider.mlkem.MLKEMKeyGenerator;
import org.openssl.jostle.jcajce.provider.mlkem.MLKEMKTSCipherSpi;
import org.openssl.jostle.jcajce.provider.mlkem.MLKEMKeyPairGenerator;
import org.openssl.jostle.jcajce.spec.MLKEMParameterSpec;
import org.openssl.jostle.jcajce.spec.OSSLKeyType;
import org.openssl.jostle.util.asn1.oids.NISTObjectIdentifiers;

import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * ML-KEM registrations for the FIPS provider, mirroring ProvMLKEM's surface
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
 *   3.5.7 : keymgmt fetch = 1  -&gt; full keygen / encapsulate / decapsulate, both configs
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
class ProvFIPSMLKEM
{

    private static final String PREFIX = "org.openssl.jostle.jcajce.provider.mlkem.";

    private static final Logger LOG = Logger.getLogger(ProvFIPSMLKEM.class.getName());


    public void configure(final JostleFIPSProvider provider)
    {
        if (!FIPSCapabilities.canFetchKeyMgmt("ML-KEM-768"))
        {
            return;
        }
        // Fail soft: a failure registering the ML-KEM algorithms must not abort
        // JostleProvider's static initialization, which would take the whole
        // provider down with an ExceptionInInitializerError (never retried for
        // the life of the JVM). Log it and let the other Prov* classes register.
        try
        {
            configureMLKEM(provider);
        }
        catch (Throwable t)
        {
            LOG.log(Level.WARNING, "ML-KEM provider registration failed; ML-KEM algorithms will be unavailable", t);
        }
    }


    private void configureMLKEM(final JostleFIPSProvider provider)
    {

        final Map<String, String> MLKEMKeyGenAttr = new HashMap<String, String>();

        provider.addAlgorithmImplementation("KeyPairGenerator", "MLKEM", PREFIX + "MLKEMKeyPairGenerator", MLKEMKeyGenAttr, (arg) -> new MLKEMKeyPairGenerator(FIPSNISelector.MLKEMServiceNI, FIPSNISelector.SpecNI, "ML-KEM"));
        provider.addAlias("KeyPairGenerator", "MLKEM", "ML-KEM");
        provider.addAlgorithmImplementation("KeyPairGenerator", "ML-KEM-512", PREFIX + "MLKEMKeyPairGenerator$MLKEM512", MLKEMKeyGenAttr, (arg) -> new MLKEMKeyPairGenerator(FIPSNISelector.MLKEMServiceNI, FIPSNISelector.SpecNI, "ML-KEM-512"));
        provider.addAlgorithmImplementation("KeyPairGenerator", "ML-KEM-768", PREFIX + "MLKEMKeyPairGenerator$MLKEM768", MLKEMKeyGenAttr, (arg) -> new MLKEMKeyPairGenerator(FIPSNISelector.MLKEMServiceNI, FIPSNISelector.SpecNI, "ML-KEM-768"));
        provider.addAlgorithmImplementation("KeyPairGenerator", "ML-KEM-1024", PREFIX + "MLKEMKeyPairGenerator$MLKEM1024", MLKEMKeyGenAttr, (arg) -> new MLKEMKeyPairGenerator(FIPSNISelector.MLKEMServiceNI, FIPSNISelector.SpecNI, "ML-KEM-1024"));


        final Map<String, String> mlkemCipherAttr = new HashMap<>();

        provider.addAlgorithmImplementation("KeyGenerator", "MLKEM", PREFIX + "Base", mlkemCipherAttr, (arg) -> new MLKEMKeyGenerator());
        provider.addAlias("KeyGenerator", "MLKEM", "ML-KEM");

        provider.addAlgorithmImplementation("KeyGenerator", "ML-KEM-512", PREFIX + "MLKEM512", mlkemCipherAttr, (arg) -> new MLKEMKeyGenerator(MLKEMParameterSpec.ml_kem_512));
        provider.addAlgorithmImplementation("KeyGenerator", "ML-KEM-768", PREFIX + "MLKEM768", mlkemCipherAttr, (arg) -> new MLKEMKeyGenerator(MLKEMParameterSpec.ml_kem_768));
        provider.addAlgorithmImplementation("KeyGenerator", "ML-KEM-1024", PREFIX + "MLKEM1024", mlkemCipherAttr, (arg) -> new MLKEMKeyGenerator(MLKEMParameterSpec.ml_kem_1024));

        final Map<String, String> MLKEMKfAttr = new HashMap<>();
        provider.addAlgorithmImplementation("KeyFactory", "MLKEM", PREFIX + "MLKEMKeyFactorySpi", MLKEMKfAttr, (arg) -> new MLKEMKeyFactorySpi(FIPSNISelector.MLKEMServiceNI, FIPSNISelector.SpecNI, FIPSNISelector.Asn1NI));
        provider.addAlias("KeyFactory", "MLKEM", "ML-KEM");
        provider.addAlgorithmImplementation("KeyFactory", "ML-KEM-512", PREFIX + "MLKEMKeyFactorySpi$MLKEM512", MLKEMKfAttr, (arg) -> new MLKEMKeyFactorySpi(FIPSNISelector.MLKEMServiceNI, FIPSNISelector.SpecNI, FIPSNISelector.Asn1NI, OSSLKeyType.ML_KEM_512));
        provider.addAlgorithmImplementation("KeyFactory", "ML-KEM-768", PREFIX + "MLKEMKeyFactorySpi$MLKEM768", MLKEMKfAttr, (arg) -> new MLKEMKeyFactorySpi(FIPSNISelector.MLKEMServiceNI, FIPSNISelector.SpecNI, FIPSNISelector.Asn1NI, OSSLKeyType.ML_KEM_768));
        provider.addAlgorithmImplementation("KeyFactory", "ML-KEM-1024", PREFIX + "MLKEMKeyFactorySpi$MLKEM1024", MLKEMKfAttr, (arg) -> new MLKEMKeyFactorySpi(FIPSNISelector.MLKEMServiceNI, FIPSNISelector.SpecNI, FIPSNISelector.Asn1NI, OSSLKeyType.ML_KEM_1024));

        // SPKI OID aliases (NIST CSOR id-alg-ml-kem-*, RFC 9814; note the .4.4
        // "kems" arc, not the .4.3 "sigAlgs" arc) so a certificate's public key
        // can be re-derived through the JSL KeyFactory keyed on the
        // SubjectPublicKeyInfo algorithm OID (see JSLKeyX509Certificate).
        provider.addAlias("KeyFactory", "ML-KEM-512", NISTObjectIdentifiers.id_alg_ml_kem_512);
        provider.addAlias("KeyFactory", "ML-KEM-768", NISTObjectIdentifiers.id_alg_ml_kem_768);
        provider.addAlias("KeyFactory", "ML-KEM-1024", NISTObjectIdentifiers.id_alg_ml_kem_1024);

        // KTS (key-transport) Cipher for the CMS KEMRecipientInfo path (RFC 9629).
        // BC's JceCMSKEMKeyWrapper/Unwrapper resolve it via Cipher.getInstance(<ml-kem-oid>),
        // so it is registered under the SPKI/KEM OIDs (the .4.4 "kems" arc). The single
        // SPI handles all three parameter sets (the key carries its variant).
        final Map<String, String> mlkemCtsAttr = new HashMap<>();
        provider.addAlgorithmImplementation("Cipher", "ML-KEM", PREFIX + "MLKEMKTSCipherSpi", mlkemCtsAttr, (arg) -> new MLKEMKTSCipherSpi(new MLKEMKeyFactorySpi(FIPSNISelector.MLKEMServiceNI, FIPSNISelector.SpecNI, FIPSNISelector.Asn1NI), FIPSNISelector.SpecNI));
        provider.addAlias("Cipher", "ML-KEM", "MLKEM");
        provider.addAlias("Cipher", "ML-KEM",
            NISTObjectIdentifiers.id_alg_ml_kem_512,
            NISTObjectIdentifiers.id_alg_ml_kem_768,
            NISTObjectIdentifiers.id_alg_ml_kem_1024);

    }


}
