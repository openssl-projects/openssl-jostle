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

import org.openssl.jostle.jcajce.provider.mlxkem.MLXKEMKeyFactorySpi;
import org.openssl.jostle.jcajce.provider.mlxkem.MLXKEMKeyGenerator;
import org.openssl.jostle.jcajce.provider.mlxkem.MLXKEMKeyPairGenerator;
import org.openssl.jostle.jcajce.spec.MLXKEMParameterSpec;

import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * The four TLS hybrid KEM groups (draft-ietf-tls-ecdhe-mlkem).
 *
 * <p>Gated per variant, like {@code ProvFIPSMLXKEM}: the four groups are not
 * all-or-nothing, so a single representative name cannot decide them. Both
 * mainline installs on hand serve all four (measured 2026-08-28), but a
 * distributor's older libcrypto may not.
 *
 * <p>No OID aliases and no Cipher: these groups have no ASN.1 encoding, so
 * there is nothing for a certificate or a CMS recipient-info to key on.
 */
class ProvMLXKEM
{
    private static final String PREFIX = ProvMLXKEM.class.getPackage().getName() + ".mlxkem.";

    private static final Logger LOG = Logger.getLogger(ProvMLXKEM.class.getName());

    public void configure(final JostleProvider provider)
    {
        // Fail soft: a failure here must not abort JostleProvider's static
        // initialization, which would take the whole provider down with an
        // ExceptionInInitializerError (never retried for the life of the JVM).
        try
        {
            configureMLXKEM(provider);
        }
        catch (Throwable t)
        {
            LOG.log(Level.WARNING, "hybrid KEM provider registration failed; the hybrid groups will be unavailable", t);
        }
    }

    private void configureMLXKEM(final JostleProvider provider)
    {
        final Map<String, String> attr = new HashMap<String, String>();

        for (final MLXKEMParameterSpec spec : MLXKEMParameterSpec.all())
        {
            String name = spec.getName();

            if (!Capabilities.canFetchKeyMgmt(name))
            {
                continue;
            }

            provider.addAlgorithmImplementation("KeyPairGenerator", name,
                    PREFIX + "MLXKEMKeyPairGenerator$" + name, attr,
                    (arg) -> new MLXKEMKeyPairGenerator(
                            NISelector.MLXKEMServiceNI, NISelector.SpecNI, spec, provider));

            provider.addAlgorithmImplementation("KeyGenerator", name,
                    PREFIX + "MLXKEMKeyGenerator$" + name, attr,
                    (arg) -> new MLXKEMKeyGenerator(
                            NISelector.MLXKEMServiceNI, NISelector.SpecNI, spec, provider));

            provider.addAlgorithmImplementation("KeyFactory", name,
                    PREFIX + "MLXKEMKeyFactorySpi$" + name, attr,
                    (arg) -> new MLXKEMKeyFactorySpi(
                            NISelector.MLXKEMServiceNI, NISelector.SpecNI, spec, provider));
        }
    }
}
