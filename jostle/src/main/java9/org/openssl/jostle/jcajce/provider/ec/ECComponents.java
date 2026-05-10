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

package org.openssl.jostle.jcajce.provider.ec;

import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.jcajce.spec.PKEYKeySpec;

import java.lang.ref.Reference;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;

/**
 * Shared helper that fetches EC components from the native EVP_PKEY.
 *
 * <p>Java 9+ override of the Java 8 baseline. Uses
 * {@link Reference#reachabilityFence} to keep the underlying
 * {@code PKEYKeySpec} reachable across the two-step native calls
 * (query length, then fetch), replacing the {@code synchronized(spec)}
 * idiom in the baseline.
 */
final class ECComponents
{
    private ECComponents() {}

    /** Fetch the curve name as a UTF-8 string. */
    static String getCurveName(PKEYKeySpec spec)
    {
        try
        {
            int len = NISelector.ECServiceNI.getComponent(
                    spec.getReference(), ECServiceNI.COMP_CURVE_NAME, null);
            byte[] raw = new byte[len];
            int written = NISelector.ECServiceNI.getComponent(
                    spec.getReference(), ECServiceNI.COMP_CURVE_NAME, raw);
            if (written != raw.length)
            {
                byte[] trimmed = new byte[written];
                System.arraycopy(raw, 0, trimmed, 0, written);
                raw = trimmed;
            }
            return new String(raw, StandardCharsets.UTF_8);
        }
        finally
        {
            Reference.reachabilityFence(spec);
        }
    }

    /** Fetch a BIGNUM-valued component (X, Y, or private scalar). */
    static BigInteger getBigInteger(PKEYKeySpec spec, int component)
    {
        try
        {
            int len = NISelector.ECServiceNI.getComponent(
                    spec.getReference(), component, null);
            byte[] raw = new byte[len];
            int written = NISelector.ECServiceNI.getComponent(
                    spec.getReference(), component, raw);
            if (written != raw.length)
            {
                byte[] trimmed = new byte[written];
                System.arraycopy(raw, 0, trimmed, 0, written);
                raw = trimmed;
            }
            // Big-endian unsigned magnitude — positive sign forces
            // BigInteger to interpret without two's-complement wrapping.
            return new BigInteger(1, raw);
        }
        finally
        {
            Reference.reachabilityFence(spec);
        }
    }

    /**
     * Resolve the JCE-standard {@link ECParameterSpec} for the given
     * OpenSSL curve name. Delegates to the JDK's built-in
     * AlgorithmParameters("EC") (SunEC), which knows the standard
     * NIST and SECG curve parameters.
     *
     * <p>The same curve has multiple valid names (e.g. "P-256" /
     * "secp256r1" / "prime256v1"). OpenSSL canonicalises differently
     * from SunEC — when fetched back, a curve generated as "P-256"
     * may report itself as "prime256v1". We try each known alias in
     * turn so the lookup succeeds regardless of which provider's
     * canonical form OpenSSL gave us.
     */
    static ECParameterSpec resolveParams(String curveName)
    {
        Throwable firstFailure = null;
        for (String candidate : aliasesFor(curveName))
        {
            try
            {
                AlgorithmParameters ap = AlgorithmParameters.getInstance("EC");
                ap.init(new ECGenParameterSpec(candidate));
                return ap.getParameterSpec(ECParameterSpec.class);
            }
            catch (Throwable t)
            {
                if (firstFailure == null) firstFailure = t;
            }
        }
        throw new IllegalStateException(
                "unable to resolve ECParameterSpec for curve " + curveName,
                firstFailure);
    }

    /**
     * Reverse-resolve an arbitrary {@link ECParameterSpec} back to an
     * OpenSSL curve name. Iterates over a fixed list of OpenSSL-supported
     * curves, materialises each as an {@link ECParameterSpec} via
     * {@link #resolveParams}, and returns the first whose components
     * match. Returns {@code null} if no candidate matches.
     */
    static String findCurveName(ECParameterSpec params)
    {
        if (params == null) return null;
        for (String candidate : KNOWN_CURVES)
        {
            if (!NISelector.ECServiceNI.curveSupported(candidate)) continue;
            try
            {
                ECParameterSpec known = resolveParams(candidate);
                if (paramsEqual(params, known)) return candidate;
            }
            catch (RuntimeException ignored)
            {
                // resolveParams failed for this curve — keep trying.
            }
        }
        return null;
    }

    /**
     * Compare two {@link ECParameterSpec} instances field-by-field.
     */
    private static boolean paramsEqual(ECParameterSpec a, ECParameterSpec b)
    {
        if (a == b) return true;
        if (a == null || b == null) return false;
        if (a.getCofactor() != b.getCofactor()) return false;
        if (!a.getOrder().equals(b.getOrder())) return false;
        if (a.getCurve().getField().getFieldSize()
                != b.getCurve().getField().getFieldSize()) return false;
        if (!a.getCurve().getA().equals(b.getCurve().getA())) return false;
        if (!a.getCurve().getB().equals(b.getCurve().getB())) return false;
        if (!a.getGenerator().getAffineX().equals(b.getGenerator().getAffineX())) return false;
        if (!a.getGenerator().getAffineY().equals(b.getGenerator().getAffineY())) return false;
        return true;
    }

    private static final String[] KNOWN_CURVES = {
            "P-256", "P-384", "P-521", "secp256k1", "P-224"
    };

    private static String[] aliasesFor(String curveName)
    {
        switch (curveName)
        {
            case "P-256":
            case "prime256v1":
            case "secp256r1":
                return new String[]{"secp256r1", "P-256", "prime256v1",
                        "1.2.840.10045.3.1.7"};
            case "P-384":
            case "secp384r1":
                return new String[]{"secp384r1", "P-384", "1.3.132.0.34"};
            case "P-521":
            case "secp521r1":
                return new String[]{"secp521r1", "P-521", "1.3.132.0.35"};
            case "secp256k1":
                return new String[]{"secp256k1", "1.3.132.0.10"};
            case "P-224":
            case "secp224r1":
                return new String[]{"secp224r1", "P-224", "1.3.132.0.33"};
            default:
                return new String[]{curveName};
        }
    }
}
