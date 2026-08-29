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

import org.openssl.jostle.jcajce.provider.DefaultServiceNI;
import org.openssl.jostle.jcajce.provider.ErrorCode;
import org.openssl.jostle.rand.RandSource;

/**
 * Native interface for EC keypair operations. Component selectors are
 * stable integer identifiers passed across the JNI/FFI boundary; they
 * are mirrored from {@code interface/nonfips/util/ec.h}.
 */
public interface ECServiceNI extends DefaultServiceNI
{
    // Component selectors. MUST match EC_COMP_* in ec.h.
    int COMP_CURVE_NAME = 0;
    int COMP_PUBLIC_X = 1;
    int COMP_PUBLIC_Y = 2;
    int COMP_PRIVATE_VALUE = 3;

    // Curve-table component selectors. MUST match EC_CURVE_COMP_* in ec.h.
    // These index the CURVE TABLE by name; COMP_* above index a KEY.
    int CURVE_COMP_FIELD_TYPE = 0;
    int CURVE_COMP_DEGREE = 1;
    int CURVE_COMP_P = 2;
    int CURVE_COMP_A = 3;
    int CURVE_COMP_B = 4;
    int CURVE_COMP_GX = 5;
    int CURVE_COMP_GY = 6;
    int CURVE_COMP_ORDER = 7;
    int CURVE_COMP_COFACTOR = 8;
    int CURVE_COMP_OID = 9;
    int CURVE_COMP_NAME = 10;

    // Values of CURVE_COMP_FIELD_TYPE. MUST match EC_FIELD_TYPE_* in ec.h.
    int FIELD_TYPE_PRIME = 1;
    int FIELD_TYPE_BINARY = 2;

    /**
     * Hard structural cap on the field degree, mirroring EC_CURVE_MAX_FIELD_BITS
     * in ec.h. Every per-component allocation bound derives from the degree,
     * so this is the one constant the length-to-allocation chain rests on.
     * The largest curve any current OpenSSL build ships is sect571r1 at 571
     * bits.
     */
    int MAX_FIELD_BITS = 4096;

    /** Caps on the two text components, mirroring ec.h. */
    int MAX_CURVE_NAME_BYTES = 64;
    int MAX_CURVE_OID_BYTES = 128;


    /** 1 if OpenSSL recognises the curve name, 0 otherwise. */
    int ni_curveSupported(String curveName);

    long ni_generateKeyPair(String curveName, int[] err, RandSource rndSource);

    /**
     * Construct an EC key_spec for the given curve from its private
     * scalar (big-endian, unsigned magnitude). OpenSSL re-derives the
     * public point with a point-blinded scalar mul, so a non-NULL
     * RandSource is required.
     */
    long ni_makePrivateFromComponents(String curveName, byte[] scalarBE,
                                      int[] err, RandSource rndSource);

    int ni_getComponent(long specRef, int component, byte[] out);

    /**
     * Fetch one component of a NAMED CURVE from OpenSSL's builtin table.
     * {@code curveName} may be any spelling OpenSSL resolves — short name,
     * long name, dotted OID, or a NIST name such as {@code "P-256"}.
     *
     * <p>Two-call protocol: {@code out == null} returns the required byte
     * length, a second call with a large enough buffer writes it. A
     * zero-length result is SUCCESS and means the value is zero — secp256k1
     * has {@code a == 0}, so this is a real case, not a theoretical one.
     */
    int ni_getCurveComponent(String curveName, int component, byte[] out);

    /**
     * Reverse direction: name the builtin curve these explicit domain
     * parameters describe. Numeric inputs are big-endian unsigned magnitude
     * and must all be non-null; a zero-length array legitimately denotes
     * zero. Two-call protocol as above.
     */
    int ni_findCurveName(int fieldType, byte[] p, byte[] a, byte[] b,
                         byte[] gx, byte[] gy, byte[] order, byte[] cofactor,
                         byte[] out);


    // ---------------------------------------------------------------
    // Sign / verify session
    // ---------------------------------------------------------------

    long ni_allocateSigner(int[] err);

    void ni_disposeSigner(long reference);

    int ni_initSign(long ref, long keyRef, String digestName, RandSource rndSource);

    int ni_initVerify(long ref, long keyRef, String digestName);

    int ni_update(long ref, byte[] input, int inOff, int inLen);

    int ni_sign(long ref, byte[] sig, int outOff, RandSource rndSource);

    /**
     * EC verify takes a {@link RandSource} because OpenSSL's EC
     * implementation uses RAND internally for point-blinding (a
     * side-channel mitigation). Even though verification is logically a
     * public-key operation, the upcall must be in place before
     * {@code EVP_DigestVerifyFinal} runs.
     */
    int ni_verify(long ref, byte[] sig, int sigLen, RandSource rndSource);


    // ---------------------------------------------------------------
    // Key agreement (ECDH) session
    // ---------------------------------------------------------------

    long ni_allocateKex(int[] err);

    void ni_disposeKex(long reference);

    int ni_kexInit(long ref, long keyRef, RandSource rndSource);

    /**
     * Bind the peer public key to a kex ctx. {@link RandSource} is
     * required because OpenSSL's binary-field curve handling does an
     * internal point-blinded scalar mul (via {@code EVP_PKEY_public_check}
     * inside {@code EVP_PKEY_derive_set_peer}) that consumes RAND.
     */
    int ni_kexSetPeer(long ref, long peerRef, RandSource rndSource);

    int ni_kexDerive(long ref, byte[] out, int outOff, RandSource rndSource);


    // ---------------------------------------------------------------
    // Default error-handling wrappers.
    // ---------------------------------------------------------------

    /**
     * Probe whether OpenSSL recognises the given curve name. Used by
     * the SPI to pre-validate user-supplied curve names so unknown
     * curves surface as InvalidAlgorithmParameterException with a
     * clear message rather than a generic OpenSSLException from the
     * keygen path.
     */
    default boolean curveSupported(String curveName)
    {
        return ni_curveSupported(curveName) == 1;
    }

    default long generateKeyPair(String curveName, RandSource rndSource)
    {
        int[] err = new int[1];
        long r = ni_generateKeyPair(curveName, err, rndSource);
        handleErrors(err[0]);
        return r;
    }

    default long makePrivateFromComponents(String curveName, byte[] scalarBE,
                                           RandSource rndSource)
    {
        int[] err = new int[1];
        long r = ni_makePrivateFromComponents(curveName, scalarBE, err, rndSource);
        handleErrors(err[0]);
        return r;
    }

    default int getComponent(long specRef, int component, byte[] out)
    {
        return (int) handleErrors(ni_getComponent(specRef, component, out));
    }

    /**
     * Returns the byte count, or {@code JO_CURVE_NOT_SUPPORTED} when the name
     * is not a curve this build knows. That one code is returned rather than
     * thrown because "no such curve" is an ordinary answer the caller phrases
     * for itself; every other negative code still throws.
     */
    default int getCurveComponent(String curveName, int component, byte[] out)
    {
        int code = ni_getCurveComponent(curveName, component, out);
        if (code == ErrorCode.JO_CURVE_NOT_SUPPORTED.getCode())
        {
            return code;
        }
        return (int) handleErrors(code);
    }

    /**
     * Returns the byte count, or {@code JO_CURVE_NO_MATCH} when the values
     * describe no named curve. Suppressed for the same reason as above — the
     * KeyFactory and the KeyPairGenerator each phrase that outcome
     * differently, so neither wants an exception thrown from here.
     */
    default int findCurveName(int fieldType, byte[] p, byte[] a, byte[] b,
                              byte[] gx, byte[] gy, byte[] order,
                              byte[] cofactor, byte[] out)
    {
        int code = ni_findCurveName(fieldType, p, a, b, gx, gy, order,
                                    cofactor, out);
        if (code == ErrorCode.JO_CURVE_NO_MATCH.getCode())
        {
            return code;
        }
        return (int) handleErrors(code);
    }


    // ---- signing-session wrappers, mirror RSAServiceNI ----

    default long allocateSigner()
    {
        int[] err = new int[1];
        long ref = ni_allocateSigner(err);
        handleErrors(err[0]);
        return ref;
    }

    default void disposeSigner(long reference)
    {
        ni_disposeSigner(reference);
    }

    default void initSign(long ref, long keyRef, String digestName, RandSource rndSource)
    {
        handleErrors(ni_initSign(ref, keyRef, digestName, rndSource));
    }

    default void initVerify(long ref, long keyRef, String digestName)
    {
        handleErrors(ni_initVerify(ref, keyRef, digestName));
    }

    default void update(long ref, byte[] input, int inOff, int inLen)
    {
        handleErrors(ni_update(ref, input, inOff, inLen));
    }

    default int sign(long ref, byte[] sig, int outOff, RandSource rndSource)
    {
        return (int) handleErrors(ni_sign(ref, sig, outOff, rndSource));
    }

    /**
     * Returns 0 on successful verification, -1 on invalid signature
     * (mirrors RSAServiceNI.verify — JO_FAIL is suppressed by the
     * default error handler so the caller can distinguish "sig was
     * structurally invalid" from "sig didn't verify").
     */
    default int verify(long ref, byte[] sig, int sigLen, RandSource rndSource)
    {
        long code = ni_verify(ref, sig, sigLen, rndSource);
        if (code != ErrorCode.JO_FAIL.getCode())
        {
            return (int) handleErrors(code);
        }
        return (int) code;
    }


    // ---- ECDH wrappers ----

    default long allocateKex()
    {
        int[] err = new int[1];
        long ref = ni_allocateKex(err);
        handleErrors(err[0]);
        return ref;
    }

    default void disposeKex(long reference)
    {
        ni_disposeKex(reference);
    }

    default void kexInit(long ref, long keyRef, RandSource rndSource)
    {
        handleErrors(ni_kexInit(ref, keyRef, rndSource));
    }

    default void kexSetPeer(long ref, long peerRef, RandSource rndSource)
    {
        handleErrors(ni_kexSetPeer(ref, peerRef, rndSource));
    }

    default int kexDerive(long ref, byte[] out, int outOff, RandSource rndSource)
    {
        return (int) handleErrors(ni_kexDerive(ref, out, outOff, rndSource));
    }


    default long handleErrors(long code)
    {
        if (code >= 0)
        {
            return code;
        }

        ErrorCode errorCode = ErrorCode.forCode(code);
        switch (errorCode)
        {
            case JO_INCORRECT_KEY_TYPE:
                throw new IllegalArgumentException("invalid key type for EC");
            case JO_CURVE_NO_MATCH:
                // Only reached by a direct NI caller: the findCurveName
                // wrapper above returns this code rather than throwing.
                throw new IllegalArgumentException(
                        "explicit parameters match no named curve");
            default:
        }

        return baseErrorHandler(code);
    }
}
