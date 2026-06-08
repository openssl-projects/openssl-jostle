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

package org.openssl.jostle.jcajce.provider.rsa;

import org.openssl.jostle.jcajce.provider.DefaultServiceNI;
import org.openssl.jostle.jcajce.provider.ErrorCode;
import org.openssl.jostle.rand.RandSource;

/**
 * Native interface for RSA signing operations. Padding-mode and component
 * selectors are stable integer identifiers passed across the JNI/FFI
 * boundary; they are mirrored from {@code interface/util/rsa.h}.
 *
 * <p>The signing API expects the caller to manage two distinct native
 * references: a {@code key_spec*} for the key (allocated via
 * {@code SpecNI.allocate()} and populated by one of the {@code decode*}
 * methods or via keypair generation) and an {@code rsa_ctx*} for the
 * signing session (allocated via {@link #allocateSigner()}).
 */
public interface RSAServiceNI extends DefaultServiceNI
{
    // Padding modes. MUST match RSA_PADDING_* in rsa.h.
    int PADDING_PKCS1 = 1;
    int PADDING_PSS = 2;
    // Raw PKCS#1 v1.5 ("NoneWithRSA"): caller supplies the already-formed
    // bytes (e.g. a DigestInfo); no digest is computed in the engine.
    int PADDING_PKCS1_NONE = 3;

    // Component selectors. MUST match RSA_COMP_* in rsa.h.
    int COMP_MODULUS = 0;
    int COMP_PUBLIC_EXPONENT = 1;
    int COMP_PRIVATE_EXPONENT = 2;
    int COMP_PRIME_P = 3;
    int COMP_PRIME_Q = 4;
    int COMP_EXPONENT_P = 5;
    int COMP_EXPONENT_Q = 6;
    int COMP_CRT_COEFFICIENT = 7;


    long ni_allocateSigner(int[] err);

    void ni_disposeSigner(long reference);

    long ni_generateKeyPair(int bits, byte[] pubExp, int[] err, RandSource rndSource);

    int ni_decodePublicComponents(long specRef, byte[] n, byte[] e);

    int ni_decodePrivateComponents(long specRef, byte[] n, byte[] e, byte[] d);

    int ni_decodePrivateComponentsCrt(long specRef,
                                      byte[] n, byte[] e, byte[] d,
                                      byte[] p, byte[] q,
                                      byte[] dp, byte[] dq, byte[] qinv);

    int ni_getComponent(long specRef, int component, byte[] out);

    int ni_initSign(long ref, long keyRef, String digestName,
                    int paddingMode, String mgf1MdName, int saltLen,
                    RandSource rndSource);

    int ni_initVerify(long ref, long keyRef, String digestName,
                      int paddingMode, String mgf1MdName, int saltLen);

    int ni_update(long ref, byte[] input, int inOff, int inLen);

    int ni_sign(long ref, byte[] sig, int outOff, RandSource rndSource);

    int ni_verify(long ref, byte[] sig, int sigLen);


    // ---------------------------------------------------------------
    // Default error-handling wrappers (mirror EDServiceNI pattern).
    // ---------------------------------------------------------------

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

    default long generateKeyPair(int bits, byte[] pubExp, RandSource rndSource)
    {
        int[] err = new int[1];
        long r = ni_generateKeyPair(bits, pubExp, err, rndSource);
        handleErrors(err[0]);
        return r;
    }

    default int decodePublicComponents(long specRef, byte[] n, byte[] e)
    {
        return (int) handleErrors(ni_decodePublicComponents(specRef, n, e));
    }

    default int decodePrivateComponents(long specRef, byte[] n, byte[] e, byte[] d)
    {
        return (int) handleErrors(ni_decodePrivateComponents(specRef, n, e, d));
    }

    default int decodePrivateComponentsCrt(long specRef,
                                           byte[] n, byte[] e, byte[] d,
                                           byte[] p, byte[] q,
                                           byte[] dp, byte[] dq, byte[] qinv)
    {
        return (int) handleErrors(
                ni_decodePrivateComponentsCrt(specRef, n, e, d, p, q, dp, dq, qinv));
    }

    /**
     * Fetches a single RSA component as a big-endian byte array.
     *
     * <p>Returns the required byte length when {@code out == null}, or
     * the number of bytes written. A negative return signals "component
     * unavailable" (e.g. CRT components on a key constructed without
     * them); callers building a {@code RSAPrivateCrtKey} should map that
     * to {@code null} per the JCA contract rather than propagating the
     * exception, by calling {@link #ni_getComponent} directly.
     */
    default int getComponent(long specRef, int component, byte[] out)
    {
        return (int) handleErrors(ni_getComponent(specRef, component, out));
    }

    default void initSign(long ref, long keyRef, String digestName,
                          int paddingMode, String mgf1MdName, int saltLen,
                          RandSource rndSource)
    {
        handleErrors(ni_initSign(ref, keyRef, digestName,
                paddingMode, mgf1MdName, saltLen, rndSource));
    }

    default void initVerify(long ref, long keyRef, String digestName,
                            int paddingMode, String mgf1MdName, int saltLen)
    {
        handleErrors(ni_initVerify(ref, keyRef, digestName,
                paddingMode, mgf1MdName, saltLen));
    }

    default int update(long ref, byte[] input, int inOff, int inLen)
    {
        return (int) handleErrors(ni_update(ref, input, inOff, inLen));
    }

    default int sign(long ref, byte[] sig, int outOff, RandSource rndSource)
    {
        return (int) handleErrors(ni_sign(ref, sig, outOff, rndSource));
    }

    /**
     * Verify follows the EdDSA convention: {@link ErrorCode#JO_FAIL} is
     * a legitimate "signature didn't verify" return and is not thrown.
     */
    default int verify(long ref, byte[] sig, int sigLen)
    {
        long code = ni_verify(ref, sig, sigLen);
        if (code != ErrorCode.JO_FAIL.getCode())
        {
            return (int) handleErrors(code);
        }
        return (int) code;
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
                throw new IllegalArgumentException("invalid key type for RSA");
            case JO_RSA_PUB_EXP_IS_NULL:
                throw new NullPointerException("public exponent is null");
            case JO_RSA_MODULUS_IS_NULL:
                throw new NullPointerException("modulus is null");
            case JO_RSA_PRIV_EXP_IS_NULL:
                throw new NullPointerException("private exponent is null");
            case JO_RSA_PRIME_P_IS_NULL:
                throw new NullPointerException("prime P is null");
            case JO_RSA_PRIME_Q_IS_NULL:
                throw new NullPointerException("prime Q is null");
            case JO_RSA_PRIME_EXP_P_IS_NULL:
                throw new NullPointerException("prime exponent P is null");
            case JO_RSA_PRIME_EXP_Q_IS_NULL:
                throw new NullPointerException("prime exponent Q is null");
            case JO_RSA_CRT_COEFFICIENT_IS_NULL:
                throw new NullPointerException("CRT coefficient is null");
            default:
        }

        return baseErrorHandler(code);
    }
}
