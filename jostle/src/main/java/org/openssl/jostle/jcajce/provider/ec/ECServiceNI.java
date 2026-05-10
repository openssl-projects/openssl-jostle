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
 * are mirrored from {@code interface/util/ec.h}.
 */
public interface ECServiceNI extends DefaultServiceNI
{
    // Component selectors. MUST match EC_COMP_* in ec.h.
    int COMP_CURVE_NAME = 0;
    int COMP_PUBLIC_X = 1;
    int COMP_PUBLIC_Y = 2;
    int COMP_PRIVATE_VALUE = 3;


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
            default:
        }

        return baseErrorHandler(code);
    }
}
