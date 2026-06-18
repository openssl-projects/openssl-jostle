/*
 *
 *   Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *   Licensed under the Apache License 2.0 (the "License"). You may not use
 *   this file except in compliance with the License.  You can obtain a copy
 *   in the file LICENSE in the source distribution or at
 *   https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider.rand;

import java.security.Security;

/**
 * Resolves the JDK {@code securerandom.drbg.config} security property into the
 * OpenSSL DRBG mechanism / variant / derivation-function selection used by the
 * {@code DRBG} (and {@code DEFAULT}) SecureRandom service.
 * <p>
 * The property grammar (aspects comma-separated, any order, each at most once)
 * is {@code mech_name, algorithm_name, strength, capability, df}. Only the
 * mechanism, algorithm (digest/cipher) and derivation-function aspects are
 * applied here — these are the selections the standard JCA API otherwise cannot
 * carry. The strength and capability aspects are validated for correctness but
 * NOT applied: per-instance strength and capability continue to flow through
 * {@code DrbgParameters} and the algorithm's variant-derived strength ceiling.
 * </p>
 * <p>
 * Supported algorithms follow the JDK grammar: {@code SHA-224}, {@code SHA-256},
 * {@code SHA-384}, {@code SHA-512} for Hash/HMAC and {@code AES-128},
 * {@code AES-192}, {@code AES-256} for CTR. (SHA-1 is intentionally absent from
 * the property grammar; it remains reachable via the {@code HASH-DRBG-SHA1} /
 * {@code HMAC-DRBG-SHA1} named services.)
 * </p>
 */
final class DrbgConfig
{
    private final String mechanism;
    private final String variant;
    private final boolean useDerivationFunction;

    private DrbgConfig(String mechanism, String variant, boolean useDerivationFunction)
    {
        this.mechanism = mechanism;
        this.variant = variant;
        this.useDerivationFunction = useDerivationFunction;
    }

    String getMechanism()
    {
        return mechanism;
    }

    String getVariant()
    {
        return variant;
    }

    boolean usesDerivationFunction()
    {
        return useDerivationFunction;
    }

    /**
     * Reads and resolves the {@code securerandom.drbg.config} security property.
     *
     * @return the resolved configuration, or {@code null} when the property is
     * unset or empty (in which case the algorithm's built-in defaults apply)
     * @throws IllegalArgumentException if the property is malformed
     */
    static DrbgConfig fromSecurityProperty()
    {
        String cfg = Security.getProperty("securerandom.drbg.config");
        if (cfg == null || cfg.trim().isEmpty())
        {
            return null;
        }

        return parse(cfg);
    }

    static DrbgConfig parse(String config)
    {
        String mech = null;
        String alg = null;
        Boolean useDf = null;

        for (String raw : config.split(","))
        {
            String token = raw.trim();
            if (token.isEmpty())
            {
                continue;
            }

            if (isMechanism(token))
            {
                if (mech != null)
                {
                    throw new IllegalArgumentException("duplicate DRBG mechanism in securerandom.drbg.config");
                }
                mech = token;
            }
            else if (variantNameOrNull(token) != null)
            {
                if (alg != null)
                {
                    throw new IllegalArgumentException("duplicate DRBG algorithm in securerandom.drbg.config");
                }
                alg = token;
            }
            else if (token.equals("use_df") || token.equals("no_df"))
            {
                if (useDf != null)
                {
                    throw new IllegalArgumentException("duplicate derivation-function flag in securerandom.drbg.config");
                }
                useDf = token.equals("use_df");
            }
            else if (isStrength(token) || isCapability(token))
            {
                // Validated but not applied: strength and capability flow
                // through DrbgParameters and the variant strength ceiling.
                continue;
            }
            else
            {
                throw new IllegalArgumentException("invalid securerandom.drbg.config aspect: " + token);
            }
        }

        if (mech == null)
        {
            mech = "Hash_DRBG";
        }

        boolean ctr = mech.equals("CTR_DRBG");

        if (alg == null)
        {
            alg = ctr ? "AES-256" : "SHA-256";
        }

        if (ctr != alg.startsWith("AES-"))
        {
            throw new IllegalArgumentException(
                    "DRBG algorithm " + alg + " is not valid for mechanism " + mech);
        }

        return new DrbgConfig(mechanismName(mech), variantNameOrNull(alg),
                useDf == null || useDf);
    }

    private static boolean isMechanism(String token)
    {
        return token.equals("Hash_DRBG") || token.equals("HMAC_DRBG") || token.equals("CTR_DRBG");
    }

    private static boolean isStrength(String token)
    {
        return token.equals("112") || token.equals("128") || token.equals("192") || token.equals("256");
    }

    private static boolean isCapability(String token)
    {
        return token.equals("pr_and_reseed") || token.equals("reseed_only") || token.equals("none");
    }

    private static String mechanismName(String mech)
    {
        switch (mech)
        {
        case "Hash_DRBG":
            return "HASH-DRBG";
        case "HMAC_DRBG":
            return "HMAC-DRBG";
        case "CTR_DRBG":
            return "CTR-DRBG";
        default:
            throw new IllegalArgumentException("unknown DRBG mechanism: " + mech);
        }
    }

    private static String variantNameOrNull(String alg)
    {
        switch (alg)
        {
        case "SHA-224":
            return "SHA2-224";
        case "SHA-256":
            return "SHA2-256";
        case "SHA-384":
            return "SHA2-384";
        case "SHA-512":
            return "SHA2-512";
        case "AES-128":
            return "AES-128-CTR";
        case "AES-192":
            return "AES-192-CTR";
        case "AES-256":
            return "AES-256-CTR";
        default:
            return null;
        }
    }
}
