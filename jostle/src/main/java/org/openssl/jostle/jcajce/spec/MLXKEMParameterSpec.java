/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.spec;

import org.openssl.jostle.util.Strings;

import java.security.spec.AlgorithmParameterSpec;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * Parameter set for the four TLS hybrid KEMs
 * (draft-ietf-tls-ecdhe-mlkem): an ML-KEM component and an ECDH component
 * whose shared secrets are CONCATENATED rather than combined by a KDF.
 *
 * <p>The names are IANA TLS group names, spelled as OpenSSL spells them.
 * There are no OIDs and no ASN.1 encoding for these keys, so unlike
 * {@link MLKEMParameterSpec} there is no OID alias to look them up by.
 */
public class MLXKEMParameterSpec implements AlgorithmParameterSpec
{
    public static final MLXKEMParameterSpec x25519_mlkem768 =
            new MLXKEMParameterSpec("X25519MLKEM768", OSSLKeyType.X25519MLKEM768, 192, 32, 32);
    public static final MLXKEMParameterSpec x448_mlkem1024 =
            new MLXKEMParameterSpec("X448MLKEM1024", OSSLKeyType.X448MLKEM1024, 256, 32, 56);
    public static final MLXKEMParameterSpec secp256r1_mlkem768 =
            new MLXKEMParameterSpec("SecP256r1MLKEM768", OSSLKeyType.SecP256r1MLKEM768, 192, 32, 32);
    public static final MLXKEMParameterSpec secp384r1_mlkem1024 =
            new MLXKEMParameterSpec("SecP384r1MLKEM1024", OSSLKeyType.SecP384r1MLKEM1024, 256, 32, 48);

    private static final Set<MLXKEMParameterSpec> parameterSpecs =
            Collections.unmodifiableSet(new HashSet<MLXKEMParameterSpec>()
            {
                {
                    add(x25519_mlkem768);
                    add(x448_mlkem1024);
                    add(secp256r1_mlkem768);
                    add(secp384r1_mlkem1024);
                }
            });

    private static final Map<OSSLKeyType, MLXKEMParameterSpec> typeToSpec =
            Collections.unmodifiableMap(new HashMap<OSSLKeyType, MLXKEMParameterSpec>()
            {
                {
                    parameterSpecs.forEach(spec -> put(spec.getKeyType(), spec));
                }
            });

    private static final Map<String, MLXKEMParameterSpec> parameters = new HashMap<String, MLXKEMParameterSpec>();

    static
    {
        parameterSpecs.forEach(spec -> parameters.put(Strings.toLowerCase(spec.getName()), spec));
    }

    private final String name;
    private final OSSLKeyType keyType;
    private final int requiredStrengthBits;
    private final int mlkemSecretBytes;
    private final int ecdhSecretBytes;

    private MLXKEMParameterSpec(String name, OSSLKeyType keyType, int requiredStrengthBits,
                                int mlkemSecretBytes, int ecdhSecretBytes)
    {
        this.name = name;
        this.keyType = keyType;
        this.requiredStrengthBits = requiredStrengthBits;
        this.mlkemSecretBytes = mlkemSecretBytes;
        this.ecdhSecretBytes = ecdhSecretBytes;
    }

    public String getName()
    {
        return name;
    }

    public OSSLKeyType getKeyType()
    {
        return keyType;
    }

    /**
     * Strength of the ML-KEM component: 192 for the 768-bearing variants, 256
     * for the 1024-bearing ones, matching what OpenSSL reports as the key's
     * {@code security_bits}. Drives the SPI's default-DRBG selection, exactly
     * as {@link MLKEMParameterSpec#getRequiredStrengthBits} does — a
     * 128-bit DRBG trips the C-side RAND gate on these.
     */
    public int getRequiredStrengthBits()
    {
        return requiredStrengthBits;
    }

    /**
     * Length of the ML-KEM half of the shared secret. Always 32.
     */
    public int getMlkemSecretBytes()
    {
        return mlkemSecretBytes;
    }

    /**
     * Length of the ECDH half of the shared secret: 32 for X25519 and P-256,
     * 56 for X448, <b>48</b> for P-384.
     *
     * <p>Note the asymmetry — the two 1024-bearing variants do NOT match.
     * X448MLKEM1024's secret is 88 bytes and SecP384r1MLKEM1024's is 80,
     * because P-384's shared secret is 48 bytes where X448's is 56. Measured
     * ({@code fips-c-review/probes/hybrid_kem_probe.c}); assuming symmetry here
     * is a mistake that has already been made once.
     */
    public int getEcdhSecretBytes()
    {
        return ecdhSecretBytes;
    }

    /**
     * Total shared-secret length: the two components concatenated.
     */
    public int getSharedSecretBytes()
    {
        return mlkemSecretBytes + ecdhSecretBytes;
    }

    /**
     * Does the ML-KEM component come FIRST in the concatenated secret and
     * ciphertext?
     *
     * <p>True for the X25519/X448 pair, false for the SecP pair — OpenSSL's
     * {@code hybrid_vtable} gives {@code ml_kem_slot} 0 and 1 respectively
     * ({@code providers/implementations/keymgmt/mlx_kmgmt.c}). Ordering is a
     * per-variant fact, not a family one, and getting it wrong is exactly what
     * an agreement test composing a reference must catch.
     */
    public boolean isMlkemFirst()
    {
        return keyType == OSSLKeyType.X25519MLKEM768 || keyType == OSSLKeyType.X448MLKEM1024;
    }

    public static MLXKEMParameterSpec fromName(String name)
    {
        if (name == null)
        {
            throw new NullPointerException("name cannot be null");
        }

        MLXKEMParameterSpec parameterSpec = parameters.get(Strings.toLowerCase(name));

        if (parameterSpec == null)
        {
            throw new IllegalArgumentException("unknown parameter name: " + name);
        }
        return parameterSpec;
    }

    public static MLXKEMParameterSpec getSpecForOSSLType(OSSLKeyType type)
    {
        return typeToSpec.get(type);
    }

    public static Set<MLXKEMParameterSpec> all()
    {
        return parameterSpecs;
    }

    @Override
    public String toString()
    {
        return name;
    }
}
