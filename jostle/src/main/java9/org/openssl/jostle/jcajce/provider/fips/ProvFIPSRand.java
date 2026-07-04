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

import org.openssl.jostle.jcajce.provider.rand.RandAlgorithm;
import org.openssl.jostle.jcajce.provider.rand.RandServiceSPI;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandomParameters;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * Java 9+ override of the FIPS SecureRandom registrations: accepts
 * SecureRandomParameters as the construction parameter, mirroring ProvRand's
 * multi-release split. Public surface must stay identical to the Java 8
 * baseline (multi-release ABI rule).
 */
class ProvFIPSRand
{
    private static final String PREFIX = "org.openssl.jostle.jcajce.provider.rand.";

    public void configure(final JostleFIPSProvider provider)
    {
        final Map<String, String> attr = new HashMap<String, String>();
        attr.put("ThreadSafe", "true");

        for (RandAlgorithm algorithm : RandAlgorithm.values())
        {
            if (isFipsApproved(algorithm))
            {
                addRand(provider, algorithm, attr);
            }
        }
        provider.addAlias("SecureRandom", RandAlgorithm.DRBG.getJcaName(), "DEFAULT");
    }

    //
    // FIPS 140-3 IG D.R limits DRBG digests to a fixed set (see the FIPS
    // provider's ossl_drbg_verify_digest): SHA-1, non-truncated SHA-2 (256,
    // 512) and non-truncated SHA-3 (256, 512). The truncated digests
    // (SHA-224, SHA-384, SHA-512/224, SHA-512/256) are not allowed for DRBGs,
    // so the HASH-/HMAC-DRBG variants over them are not registered here - a
    // fetch would fail the module's digest check anyway. CTR-DRBG variants
    // are keyed by cipher, not digest, and are unaffected.
    //
    private static final Set<String> APPROVED_DRBG_DIGESTS = new HashSet<String>(Arrays.asList(
            "SHA1", "SHA2-256", "SHA2-512", "SHA3-256", "SHA3-512"));

    private static boolean isFipsApproved(RandAlgorithm algorithm)
    {
        String mechanism = algorithm.getMechanism();
        if ("HASH-DRBG".equals(mechanism) || "HMAC-DRBG".equals(mechanism))
        {
            return APPROVED_DRBG_DIGESTS.contains(algorithm.getVariant());
        }
        return true;
    }

    private static void addRand(final JostleFIPSProvider provider, RandAlgorithm algorithm, Map<String, String> attr)
    {
        String name = algorithm.getJcaName();
        String clName = name.replace("-", "_").replace("/", "_");
        provider.addAlgorithmImplementation("SecureRandom", name,
                PREFIX + "RandServiceSPI$" + clName, attr,
                (arg) -> createInstance(algorithm, arg));
    }

    private static RandServiceSPI createInstance(RandAlgorithm algorithm, Object arg)
            throws NoSuchAlgorithmException
    {
        if (arg == null)
        {
            return new RandServiceSPI(FIPSNISelector.RandServiceNI, algorithm);
        }

        if (arg instanceof SecureRandomParameters)
        {
            return new RandServiceSPI(FIPSNISelector.RandServiceNI, algorithm, (SecureRandomParameters) arg);
        }

        throw new NoSuchAlgorithmException("SecureRandom parameters must implement SecureRandomParameters");
    }
}
