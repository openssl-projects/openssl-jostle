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
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

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
                if (firstFailure == null)
                {
                    firstFailure = t;
                }
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
        if (params == null)
        {
            return null;
        }
        for (String candidate : KNOWN_CURVES)
        {
            if (!NISelector.ECServiceNI.curveSupported(candidate))
            {
                continue;
            }
            try
            {
                ECParameterSpec known = resolveParams(candidate);
                if (paramsEqual(params, known))
                {
                    return candidate;
                }
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
     * Canonicalise a caller-supplied curve name to one the loaded
     * OpenSSL build accepts via {@code OSSL_PKEY_PARAM_GROUP_NAME}.
     *
     * <p>OpenSSL does not recognise every standard name for a curve:
     * P-256 is registered under {@code prime256v1}/{@code P-256} but NOT
     * the SECG {@code secp256r1} nor the X9.62 OID
     * {@code 1.2.840.10045.3.1.7}, even though those are the names TLS
     * (and SECG) callers use. This method maps any accepted alias of a
     * curve to a name OpenSSL does recognise.
     *
     * <p>Strategy: if OpenSSL already accepts the name as-given, return
     * it unchanged (the common case, and the only behaviour for names
     * not in the alias table). Otherwise locate the alias family the
     * name belongs to — matching against every form, including the OID —
     * and return the first member OpenSSL accepts. Returns {@code null}
     * if no form of the curve is supported by the loaded build, which
     * the caller surfaces as {@link java.security.InvalidAlgorithmParameterException}.
     */
    static String toOpenSSLCurveName(String requested)
    {
        if (requested == null)
        {
            return null;
        }
        if (NISelector.ECServiceNI.curveSupported(requested))
        {
            return requested;
        }
        for (String[] family : CURVE_ALIASES.values())
        {
            boolean member = false;
            for (String alias : family)
            {
                if (alias.equals(requested))
                {
                    member = true;
                    break;
                }
            }
            if (!member)
            {
                continue;
            }
            for (String candidate : family)
            {
                if (NISelector.ECServiceNI.curveSupported(candidate))
                {
                    return candidate;
                }
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
        if (a == b)
        {
            return true;
        }
        if (a == null || b == null)
        {
            return false;
        }
        if (a.getCofactor() != b.getCofactor())
        {
            return false;
        }
        if (!a.getOrder().equals(b.getOrder()))
        {
            return false;
        }
        if (a.getCurve().getField().getFieldSize()
                != b.getCurve().getField().getFieldSize())
        {
            return false;
        }
        if (!a.getCurve().getA().equals(b.getCurve().getA()))
        {
            return false;
        }
        if (!a.getCurve().getB().equals(b.getCurve().getB()))
        {
            return false;
        }
        if (!a.getGenerator().getAffineX().equals(b.getGenerator().getAffineX()))
        {
            return false;
        }
        if (!a.getGenerator().getAffineY().equals(b.getGenerator().getAffineY()))
        {
            return false;
        }
        return true;
    }

    /**
     * Curated list of curve names tried by {@link #findCurveName}.
     * Covers NIST P-curves, the common SECG curves (including the
     * Koblitz secp256k1), and the NIST binary-field K/B curves (the
     * sectXXXkN/rN families that BC also exposes via short {@code K-NNN}
     * / {@code B-NNN} aliases). Uncommon curves (Brainpool, X9.62
     * binary, Oakley/IPSec) won't reverse-resolve via this path but
     * still work via the encoded-form KeyFactory paths.
     */
    private static final String[] KNOWN_CURVES = {
            "P-256", "P-384", "P-521", "secp256k1", "P-224",
            // NIST K-curves (binary field, Koblitz)
            "sect163k1", "sect233k1", "sect283k1", "sect409k1", "sect571k1",
            // NIST B-curves (binary field, random — note B-163 is r2)
            "sect163r2", "sect233r1", "sect283r1", "sect409r1", "sect571r1"
    };

    /**
     * Return the input plus all known aliases for a given curve name.
     * Order in the returned array: SECG canonical name first (this is
     * the form SunEC's {@code AlgorithmParameters("EC")} accepts on
     * JDK 9+), then BC-style short name, then OID. If the input
     * doesn't match a known family, returns just the input wrapped
     * in a single-element array.
     *
     * <p>The lookup table is built once at class init. Each accepted
     * input name is registered as a separate map key with its own
     * (deliberately duplicated) alias array — keeps each row of the
     * static block self-contained for review and dodges the
     * {@code switch}-with-fallthrough hazards a manual editor might
     * introduce when adding a new family.
     */
    static String[] aliasesFor(String curveName)
    {
        String[] aliases = CURVE_ALIASES.get(curveName);
        return aliases != null ? aliases : new String[]{curveName};
    }

    private static final Map<String, String[]> CURVE_ALIASES;

    static
    {
        Map<String, String[]> m = new HashMap<>();

        // NIST P-256 / SECG secp256r1 / X9.62 prime256v1
        m.put("P-256",       new String[]{"secp256r1", "P-256", "prime256v1", "1.2.840.10045.3.1.7"});
        m.put("prime256v1",  new String[]{"secp256r1", "P-256", "prime256v1", "1.2.840.10045.3.1.7"});
        m.put("secp256r1",   new String[]{"secp256r1", "P-256", "prime256v1", "1.2.840.10045.3.1.7"});

        // NIST P-384 / SECG secp384r1
        m.put("P-384",       new String[]{"secp384r1", "P-384", "1.3.132.0.34"});
        m.put("secp384r1",   new String[]{"secp384r1", "P-384", "1.3.132.0.34"});

        // NIST P-521 / SECG secp521r1
        m.put("P-521",       new String[]{"secp521r1", "P-521", "1.3.132.0.35"});
        m.put("secp521r1",   new String[]{"secp521r1", "P-521", "1.3.132.0.35"});

        // NIST P-224 / SECG secp224r1
        m.put("P-224",       new String[]{"secp224r1", "P-224", "1.3.132.0.33"});
        m.put("secp224r1",   new String[]{"secp224r1", "P-224", "1.3.132.0.33"});

        // SECG secp256k1 (Koblitz prime — Bitcoin)
        m.put("secp256k1",   new String[]{"secp256k1", "1.3.132.0.10"});

        // NIST K-curves (binary field, Koblitz). BC accepts the short
        // K-NNN names; SunEC needs the SECG sectNNNk1 form, so the
        // SECG name is listed first in the alias array.
        m.put("K-163",       new String[]{"sect163k1", "K-163", "1.3.132.0.1"});
        m.put("sect163k1",   new String[]{"sect163k1", "K-163", "1.3.132.0.1"});
        m.put("K-233",       new String[]{"sect233k1", "K-233", "1.3.132.0.26"});
        m.put("sect233k1",   new String[]{"sect233k1", "K-233", "1.3.132.0.26"});
        m.put("K-283",       new String[]{"sect283k1", "K-283", "1.3.132.0.16"});
        m.put("sect283k1",   new String[]{"sect283k1", "K-283", "1.3.132.0.16"});
        m.put("K-409",       new String[]{"sect409k1", "K-409", "1.3.132.0.36"});
        m.put("sect409k1",   new String[]{"sect409k1", "K-409", "1.3.132.0.36"});
        m.put("K-571",       new String[]{"sect571k1", "K-571", "1.3.132.0.38"});
        m.put("sect571k1",   new String[]{"sect571k1", "K-571", "1.3.132.0.38"});

        // NIST B-curves (binary field, random). B-163 maps to sect163r2
        // — NOT r1; sect163r1 was withdrawn before NIST adopted the
        // family. The other B-NNN curves all map to sectNNNr1.
        m.put("B-163",       new String[]{"sect163r2", "B-163", "1.3.132.0.15"});
        m.put("sect163r2",   new String[]{"sect163r2", "B-163", "1.3.132.0.15"});
        m.put("B-233",       new String[]{"sect233r1", "B-233", "1.3.132.0.27"});
        m.put("sect233r1",   new String[]{"sect233r1", "B-233", "1.3.132.0.27"});
        m.put("B-283",       new String[]{"sect283r1", "B-283", "1.3.132.0.17"});
        m.put("sect283r1",   new String[]{"sect283r1", "B-283", "1.3.132.0.17"});
        m.put("B-409",       new String[]{"sect409r1", "B-409", "1.3.132.0.37"});
        m.put("sect409r1",   new String[]{"sect409r1", "B-409", "1.3.132.0.37"});
        m.put("B-571",       new String[]{"sect571r1", "B-571", "1.3.132.0.39"});
        m.put("sect571r1",   new String[]{"sect571r1", "B-571", "1.3.132.0.39"});

        CURVE_ALIASES = Collections.unmodifiableMap(m);
    }
}
