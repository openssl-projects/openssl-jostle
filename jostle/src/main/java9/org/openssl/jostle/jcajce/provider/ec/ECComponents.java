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

import org.openssl.jostle.jcajce.spec.PKEYKeySpec;

import java.lang.ref.Reference;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.spec.ECField;
import java.security.spec.ECFieldF2m;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Shared helper for EC components, in two halves.
 *
 * <p>Java 9+ override of the Java 8 baseline. The KEY half fetches components
 * from a native EVP_PKEY and uses {@link Reference#reachabilityFence} to keep
 * the underlying {@code PKEYKeySpec} reachable across the two-step native
 * calls (query length, then fetch), replacing the {@code synchronized(spec)}
 * idiom in the baseline.
 *
 * <p>The CURVE half reads OpenSSL's builtin curve table by name, in both
 * directions. It replaces a hardcoded 16-entry candidate list and a 47-entry
 * alias map, both of which were a second source of truth for values OpenSSL
 * owns — see the query-and-cache rule in {@code java-spi.md}. Two spellings
 * survive as {@link #SECG_SUBSTITUTIONS} because OpenSSL genuinely does not
 * know them.
 */
final class ECComponents
{
    private ECComponents() {}

    /** Fetch the curve name as a UTF-8 string. */
    static String getCurveName(ECServiceNI ecServiceNI, PKEYKeySpec spec)
    {
        try
        {
            int len = ecServiceNI.getComponent(
                    spec.getReference(), ECServiceNI.COMP_CURVE_NAME, null);
            byte[] raw = new byte[len];
            int written = ecServiceNI.getComponent(
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
    static BigInteger getBigInteger(ECServiceNI ecServiceNI, PKEYKeySpec spec, int component)
    {
        try
        {
            int len = ecServiceNI.getComponent(
                    spec.getReference(), component, null);
            byte[] raw = new byte[len];
            int written = ecServiceNI.getComponent(
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
     * Resolve the JCE-standard {@link ECParameterSpec} for an OpenSSL curve
     * name, from OpenSSL's own builtin curve table.
     *
     * <p>Returning a proper {@link ECParameterSpec} (instead of null) is what
     * makes Jostle's EC keys interoperable with foreign EC code that
     * introspects via {@code getParams().getCurve()} etc.
     *
     * <p>Answers for every curve the loaded build knows — 82 in OpenSSL 3.5.x,
     * of which 42 are binary-field.
     *
     * @throws IllegalStateException if the name is not a curve this build knows.
     */
    static ECParameterSpec resolveParams(ECServiceNI ecServiceNI, String curveName)
    {
        if (curveName == null)
        {
            throw new IllegalStateException("curve name is null");
        }
        ECParameterSpec cached = PARAM_CACHE.get(curveName);
        if (cached != null)
        {
            return cached;
        }

        // Field type and degree first: both are small fixed-width answers, and
        // the degree is what bounds every remaining allocation.
        byte[] rawFieldType = curveComponent(ecServiceNI, curveName,
                ECServiceNI.CURVE_COMP_FIELD_TYPE, FIELD_TYPE_MAX_BYTES);
        if (rawFieldType == null || rawFieldType.length != 1)
        {
            throw new IllegalStateException(
                    "unable to resolve ECParameterSpec for curve " + curveName);
        }
        int degree = smallValue(curveComponent(ecServiceNI, curveName,
                ECServiceNI.CURVE_COMP_DEGREE, DEGREE_MAX_BYTES), curveName, "degree");
        if (degree <= 0 || degree > ECServiceNI.MAX_FIELD_BITS)
        {
            throw new IllegalStateException("curve " + curveName
                    + " reports a field degree outside 1.." + ECServiceNI.MAX_FIELD_BITS);
        }

        // Every field-valued component is a residue mod a `degree`-bit modulus,
        // so it cannot need more than ceil(degree/8) bytes. The order n is the
        // one that can exceed the field: Hasse bounds it by p + 1 + 2*sqrt(p),
        // which needs at most one further byte.
        int fieldMaxBytes = (degree + 7) / 8 + 1;

        BigInteger p = magnitude(curveComponent(ecServiceNI, curveName,
                ECServiceNI.CURVE_COMP_P, fieldMaxBytes));
        BigInteger a = magnitude(curveComponent(ecServiceNI, curveName,
                ECServiceNI.CURVE_COMP_A, fieldMaxBytes));
        BigInteger b = magnitude(curveComponent(ecServiceNI, curveName,
                ECServiceNI.CURVE_COMP_B, fieldMaxBytes));
        BigInteger gx = magnitude(curveComponent(ecServiceNI, curveName,
                ECServiceNI.CURVE_COMP_GX, fieldMaxBytes));
        BigInteger gy = magnitude(curveComponent(ecServiceNI, curveName,
                ECServiceNI.CURVE_COMP_GY, fieldMaxBytes));
        BigInteger order = magnitude(curveComponent(ecServiceNI, curveName,
                ECServiceNI.CURVE_COMP_ORDER, fieldMaxBytes));
        int cofactor = smallValue(curveComponent(ecServiceNI, curveName,
                ECServiceNI.CURVE_COMP_COFACTOR, COFACTOR_MAX_BYTES),
                curveName, "cofactor");

        if (p == null || a == null || b == null || gx == null || gy == null
                || order == null)
        {
            throw new IllegalStateException(
                    "unable to resolve ECParameterSpec for curve " + curveName);
        }

        ECField field;
        if (rawFieldType[0] == (byte) ECServiceNI.FIELD_TYPE_PRIME)
        {
            field = new ECFieldFp(p);
        }
        else
        {
            // The reduction-polynomial constructor derives the mid-terms
            // itself, so nothing about the polynomial is transcribed here and
            // the mid-term array matches what any JDK-built spec carries.
            field = new ECFieldF2m(degree, p);
        }

        ECParameterSpec spec = new ECParameterSpec(
                new EllipticCurve(field, a, b), new ECPoint(gx, gy), order, cofactor);

        // Key by the name as asked: aliases of one curve are separate keys
        // holding equal specs, which costs a few entries and saves resolving
        // the canonical name on every hit.
        PARAM_CACHE.putIfAbsent(curveName, spec);
        return spec;
    }

    /**
     * Reverse-resolve an {@link ECParameterSpec} to an OpenSSL curve name the
     * loaded provider will also OPERATE on, or {@code null}.
     *
     * <p>Used by {@link ECKeyFactorySpi} and {@link ECKeyPairGenerator}, both of
     * which feed the result straight into {@code OSSL_PKEY_PARAM_GROUP_NAME}.
     * The {@code curveSupported} gate is therefore part of the contract here:
     * OpenSSL's curve TABLE is not provider-gated, so under a FIPS lib ctx the
     * lookup happily names secp256k1 while the module refuses to use it.
     * {@link #curveNameForEncoding} is the ungated form, for callers that only
     * describe a curve rather than operate on it.
     */
    static String findCurveName(ECServiceNI ecServiceNI, ECParameterSpec params)
    {
        String name = curveNameForEncoding(ecServiceNI, params);
        if (name == null || !ecServiceNI.curveSupported(name))
        {
            return null;
        }
        return name;
    }

    /**
     * Reverse-resolve an {@link ECParameterSpec} to an OpenSSL curve name
     * without asking whether the provider can operate on that curve, or
     * {@code null} when the values name no builtin curve.
     *
     * <p>Encoding domain parameters describes a curve; it is not an operation
     * on it. So {@link ECAlgorithmParameters} can name a curve JSLFIPS would
     * refuse to generate a key on, deliberately.
     */
    static String curveNameForEncoding(ECServiceNI ecServiceNI, ECParameterSpec params)
    {
        if (params == null)
        {
            return null;
        }
        ECField field = params.getCurve().getField();
        BigInteger modulus;
        int fieldType;
        if (field instanceof ECFieldFp)
        {
            fieldType = ECServiceNI.FIELD_TYPE_PRIME;
            modulus = ((ECFieldFp) field).getP();
        }
        else if (field instanceof ECFieldF2m)
        {
            fieldType = ECServiceNI.FIELD_TYPE_BINARY;
            modulus = ((ECFieldF2m) field).getReductionPolynomial();
        }
        else
        {
            // A third ECField implementation is not something this provider
            // can describe to OpenSSL.
            return null;
        }
        if (modulus == null)
        {
            return null;
        }

        byte[] p = unsignedBytes(modulus);
        byte[] a = unsignedBytes(params.getCurve().getA());
        byte[] b = unsignedBytes(params.getCurve().getB());
        byte[] gx = unsignedBytes(params.getGenerator().getAffineX());
        byte[] gy = unsignedBytes(params.getGenerator().getAffineY());
        byte[] order = unsignedBytes(params.getOrder());
        byte[] cofactor = unsignedBytes(BigInteger.valueOf(params.getCofactor()));
        if (p == null || a == null || b == null || gx == null || gy == null
                || order == null || cofactor == null)
        {
            return null;
        }

        int len = ecServiceNI.findCurveName(fieldType, p, a, b, gx, gy, order,
                cofactor, null);
        if (len < 0)
        {
            return null;
        }
        // Bound stated at the allocation: a curve name is an OpenSSL short
        // name, capped at MAX_CURVE_NAME_BYTES by the C side.
        if (len > ECServiceNI.MAX_CURVE_NAME_BYTES)
        {
            throw new IllegalStateException(
                    "curve name longer than " + ECServiceNI.MAX_CURVE_NAME_BYTES + " bytes");
        }
        byte[] out = new byte[len];
        int written = ecServiceNI.findCurveName(fieldType, p, a, b, gx, gy,
                order, cofactor, out);
        if (written != len)
        {
            throw new IllegalStateException("curve name length changed between calls: "
                    + len + " then " + written);
        }
        return new String(out, StandardCharsets.UTF_8);
    }

    /**
     * Canonicalise a caller-supplied curve name to one the loaded OpenSSL build
     * accepts via {@code OSSL_PKEY_PARAM_GROUP_NAME}, or {@code null} if no
     * form of the curve is supported.
     *
     * <p>That parameter accepts short and NIST names but NOT dotted OIDs, so
     * the canonicalisation is load-bearing rather than cosmetic: a caller
     * passing {@code 1.2.840.10045.3.1.7} would otherwise be refused a curve
     * the build has.
     */
    static String toOpenSSLCurveName(ECServiceNI ecServiceNI, String requested)
    {
        if (requested == null)
        {
            return null;
        }
        String canonical = canonicalCurveName(ecServiceNI, requested);
        if (canonical != null && ecServiceNI.curveSupported(canonical))
        {
            return canonical;
        }
        return null;
    }

    /**
     * The OpenSSL short name for any spelling OpenSSL resolves, or {@code null}.
     * Applies the two SECG substitutions below before giving up.
     */
    static String canonicalCurveName(ECServiceNI ecServiceNI, String requested)
    {
        if (requested == null)
        {
            return null;
        }
        String cached = NAME_CACHE.get(requested);
        if (cached != null)
        {
            return cached;
        }
        String resolved = rawCanonicalName(ecServiceNI, requested);
        if (resolved == null)
        {
            String substitute = openSSLSpellingOf(requested);
            if (substitute != null)
            {
                resolved = rawCanonicalName(ecServiceNI, substitute);
            }
        }
        if (resolved != null)
        {
            NAME_CACHE.putIfAbsent(requested, resolved);
        }
        return resolved;
    }

    private static String rawCanonicalName(ECServiceNI ecServiceNI, String requested)
    {
        byte[] raw = curveComponent(ecServiceNI, requested,
                ECServiceNI.CURVE_COMP_NAME, ECServiceNI.MAX_CURVE_NAME_BYTES);
        if (raw == null || raw.length == 0)
        {
            return null;
        }
        return new String(raw, StandardCharsets.UTF_8);
    }

    /**
     * The dotted-decimal OID of a curve, or {@code null} when the curve has
     * none. Two builtin curves (Oakley-EC2N-3 / -4) genuinely have no OID, so
     * "none" is an answer rather than a failure.
     */
    static String curveOid(ECServiceNI ecServiceNI, String curveName)
    {
        byte[] raw = curveComponent(ecServiceNI, curveName,
                ECServiceNI.CURVE_COMP_OID, ECServiceNI.MAX_CURVE_OID_BYTES);
        if (raw == null || raw.length == 0)
        {
            return null;
        }
        return new String(raw, StandardCharsets.UTF_8);
    }

    /**
     * The name a JCE caller expects back for an OpenSSL curve name — the
     * inverse of {@link #openSSLSpellingOf}, so
     * {@code getParameterSpec(ECGenParameterSpec.class)} answers
     * {@code "secp256r1"} exactly as the platform provider does.
     */
    static String jceSpellingOf(String openSSLName)
    {
        for (int i = 0; i < SECG_SUBSTITUTIONS.length; i++)
        {
            if (SECG_SUBSTITUTIONS[i][1].equals(openSSLName))
            {
                return SECG_SUBSTITUTIONS[i][0];
            }
        }
        return openSSLName;
    }

    private static String openSSLSpellingOf(String requested)
    {
        for (int i = 0; i < SECG_SUBSTITUTIONS.length; i++)
        {
            if (SECG_SUBSTITUTIONS[i][0].equals(requested))
            {
                return SECG_SUBSTITUTIONS[i][1];
            }
        }
        return null;
    }

    /**
     * The only curve spellings OpenSSL does not resolve for itself. Measured
     * across SEC 2 against {@code OBJ_txt2nid} and {@code EC_curve_nist2nid}:
     * these two SECG names are absent because OpenSSL registers both curves
     * under their X9.62 names instead. Every other SECG, NIST and OID spelling
     * resolves natively — see {@code ECCurveTableTest}, which fails
     * if OpenSSL ever learns them and this table stops being needed.
     */
    private static final String[][] SECG_SUBSTITUTIONS = {
            {"secp192r1", "prime192v1"},
            {"secp256r1", "prime256v1"},
    };

    /** Field type is one byte; degree is a bit count below 2^16. */
    private static final int FIELD_TYPE_MAX_BYTES = 1;
    private static final int DEGREE_MAX_BYTES = 4;

    /**
     * A cofactor must fit an {@code int} to reach {@link ECParameterSpec} at
     * all, so four bytes is the structural bound rather than a chosen one.
     */
    private static final int COFACTOR_MAX_BYTES = 4;

    /**
     * Memoised curve descriptions, keyed by the name as asked. Fixed table
     * values, so a concurrent double-probe is benign. Only names that RESOLVE
     * are cached, so the key space is bounded by the curve table's alias set —
     * a caller asking for unknown names cannot grow either map. A plain map
     * rather than {@code NativeLengthCache} because there is no guard logic to
     * share — the reason that class exists — and the values are objects, not
     * lengths.
     */
    private static final ConcurrentHashMap<String, ECParameterSpec> PARAM_CACHE =
            new ConcurrentHashMap<String, ECParameterSpec>();

    private static final ConcurrentHashMap<String, String> NAME_CACHE =
            new ConcurrentHashMap<String, String>();

    /**
     * Fetch one curve-table component through the two-call protocol, or
     * {@code null} when the name is not a curve this build knows.
     *
     * <p>{@code maxBytes} is checked against the length the FIRST call reports,
     * BEFORE the allocation, so a native answer outside the bound is refused
     * rather than sized. The second call's length must then equal the first:
     * these are fixed table values for a fixed name, so an answer that shrinks
     * between two calls is evidence of a defect, not a shorter result. That is
     * deliberately stricter than {@link #getBigInteger} above, which trims,
     * because a KEY's components are fetched from live state that a concurrent
     * caller could legitimately have replaced.
     */
    private static byte[] curveComponent(ECServiceNI ecServiceNI, String curveName,
                                         int component, int maxBytes)
    {
        int len = ecServiceNI.getCurveComponent(curveName, component, null);
        if (len < 0)
        {
            return null;
        }
        if (len > maxBytes)
        {
            throw new IllegalStateException("curve " + curveName + " component "
                    + component + " is " + len + " bytes, above the " + maxBytes
                    + "-byte bound");
        }
        byte[] out = new byte[len];
        int written = ecServiceNI.getCurveComponent(curveName, component, out);
        if (written != len)
        {
            throw new IllegalStateException("curve " + curveName + " component "
                    + component + " changed length between calls: " + len
                    + " then " + written);
        }
        return out;
    }

    /** Big-endian unsigned magnitude to BigInteger; empty means zero. */
    private static BigInteger magnitude(byte[] raw)
    {
        return raw == null ? null : new BigInteger(1, raw);
    }

    /** A component that must fit a non-negative int. */
    private static int smallValue(byte[] raw, String curveName, String what)
    {
        BigInteger v = magnitude(raw);
        if (v == null || v.bitLength() > 31)
        {
            throw new IllegalStateException(
                    "curve " + curveName + " has an out-of-range " + what);
        }
        return v.intValue();
    }

    /**
     * BigInteger to big-endian unsigned magnitude, dropping the sign byte
     * {@code toByteArray} adds. Returns {@code null} for a negative value,
     * which no domain parameter can legitimately be.
     */
    private static byte[] unsignedBytes(BigInteger v)
    {
        if (v == null || v.signum() < 0)
        {
            return null;
        }
        byte[] raw = v.toByteArray();
        if (raw.length > 1 && raw[0] == 0)
        {
            byte[] trimmed = new byte[raw.length - 1];
            System.arraycopy(raw, 1, trimmed, 0, trimmed.length);
            return trimmed;
        }
        // BigInteger.ZERO encodes as a single 0x00; the native side reads an
        // empty array as zero, and both forms decode identically.
        return raw;
    }
}
