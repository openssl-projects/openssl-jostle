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

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;

/**
 * Shared helper that fetches EC components from the native EVP_PKEY.
 * Mirrors {@code RSAComponents}: synchronizes on the spec to keep the
 * underlying EVP_PKEY reachable across the two-call protocol (query
 * length, then fetch).
 */
final class ECComponents
{
    private ECComponents() {}

    /** Fetch the curve name as a UTF-8 string. */
    static String getCurveName(PKEYKeySpec spec)
    {
        synchronized (spec)
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
    }

    /** Fetch a BIGNUM-valued component (X, Y, or private scalar). */
    static BigInteger getBigInteger(PKEYKeySpec spec, int component)
    {
        synchronized (spec)
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
    }

    /**
     * Resolve the JCE-standard {@link ECParameterSpec} for the given
     * OpenSSL curve name. Delegates to the JDK's built-in
     * AlgorithmParameters("EC") (SunEC), which knows the standard
     * NIST and SECG curve parameters.
     *
     * <p>Returning a proper {@link ECParameterSpec} (instead of null)
     * is what makes Jostle's EC keys interoperable with foreign EC
     * code that introspects via {@code getParams().getCurve()} etc.
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
        // Try the name as-given first, then aliases. SunEC accepts
        // "secp256r1" and "1.2.840.10045.3.1.7" but not "prime256v1"
        // or "P-256" (older JDKs); enumerate enough aliases so that
        // at least one resolves on every reasonable JDK + curve combo.
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
     * match. Returns {@code null} if no candidate matches — the caller
     * surfaces this as an {@code InvalidKeySpecException}.
     *
     * <p>Used by the {@link ECKeyFactorySpi} to translate
     * {@link java.security.spec.ECPrivateKeySpec} (which carries an
     * {@code ECParameterSpec}, not a curve name) into a name OpenSSL
     * accepts via {@code OSSL_PKEY_PARAM_GROUP_NAME}.
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
                // resolveParams failed for this curve — keep trying
                // others. The candidate list is curated so this is
                // unusual but possible on a stripped-down JDK.
            }
        }
        return null;
    }

    /**
     * Compare two {@link ECParameterSpec} instances field-by-field.
     * {@code ECParameterSpec} doesn't override {@code equals}, so this
     * is a content-based comparison over the curve, generator, order,
     * and cofactor — sufficient to distinguish all curves Jostle exposes.
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

    /**
     * Curated list of curve names tried by {@link #findCurveName}. The
     * order matches {@code STANDARD_CURVES} in {@code ECTest} and
     * covers the common NIST and SECG curves; uncommon ones won't
     * resolve via this path but will still work via the encoded-form
     * KeyFactory paths.
     */
    private static final String[] KNOWN_CURVES = {
            "P-256", "P-384", "P-521", "secp256k1", "P-224"
    };

    /**
     * Return the input plus all known aliases for a given curve name.
     * Order: input first (most likely to be the SunEC-preferred form
     * if the caller chose well), then known equivalents.
     */
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
