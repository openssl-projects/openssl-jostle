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

package org.openssl.jostle.jcajce.provider.dsa;

import org.openssl.jostle.jcajce.provider.DefaultServiceNI;
import org.openssl.jostle.jcajce.provider.ErrorCode;
import org.openssl.jostle.jcajce.provider.ProviderCapabilityException;
import org.openssl.jostle.rand.RandSource;

import java.math.BigInteger;
import java.security.ProviderException;

/**
 * Native interface for DSA operations. Component selectors are stable
 * integer identifiers passed across the JNI/FFM boundary; they are
 * mirrored from {@code interface/nonfips/util/dsa.h}.
 */
public interface DSAServiceNI extends DefaultServiceNI
{
    // Component selectors. MUST match DSA_COMP_* in dsa.h.
    int COMP_P = 0;
    int COMP_Q = 1;
    int COMP_G = 2;
    int COMP_PUBLIC_VALUE = 3;
    int COMP_PRIVATE_VALUE = 4;

    /** The refusal when the provider verifies with a key but will not sign with it; %d is p's size in bits. */
    String SIGN_KEY_REFUSED_FORMAT =
            "the loaded provider does not sign DSA with this key (p of %d bits); verification remains available";


    /**
     * Generate DSA domain parameters (p, q, g) per FIPS 186-4 and
     * return a parameters-only key spec reference.
     */
    long ni_generateParameters(int pBits, int qBits, int[] err, RandSource rndSource);

    /**
     * Construct a parameters-only DSA key spec from explicit (p, q, g)
     * big-endian unsigned magnitudes.
     */
    long ni_makeParamsFromComponents(byte[] p, byte[] q, byte[] g, int[] err);

    /**
     * Generate a DSA keypair from an established domain-parameter spec
     * (produced by {@link #ni_generateParameters} or
     * {@link #ni_makeParamsFromComponents}).
     */
    long ni_generateKeyPair(long paramsRef, int[] err, RandSource rndSource);

    /**
     * Construct a DSA private key from explicit (p, q, g, x). The
     * public value y = g^x mod p is computed on the native side.
     */
    long ni_makePrivateFromComponents(byte[] p, byte[] q, byte[] g, byte[] x,
                                      int[] err, RandSource rndSource);

    /**
     * Construct a DSA public key from explicit (p, q, g, y).
     */
    long ni_makePublicFromComponents(byte[] p, byte[] q, byte[] g, byte[] y,
                                     int[] err);

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
     * DSA verify takes a {@link RandSource} for parity with the EC
     * surface — the native side binds the entropy upcall before
     * {@code EVP_DigestVerifyFinal} so any RAND consumption on the
     * verify path resolves to fresh Java entropy.
     */
    int ni_verify(long ref, byte[] sig, int sigLen, RandSource rndSource);


    // ---------------------------------------------------------------
    // Default error-handling wrappers.
    // ---------------------------------------------------------------

    default long generateParameters(int pBits, int qBits, RandSource rndSource)
    {
        int[] err = new int[1];
        long r = ni_generateParameters(pBits, qBits, err, rndSource);
        if (err[0] == ErrorCode.JO_DSA_PARAMGEN_SIZE_MISMATCH.getCode())
        {
            throw new ProviderException(String.format(
                    "DSA parameter generation did not honour the requested sizes: p of %d bits, q of %d bits",
                    pBits, qBits));
        }
        handleErrors(err[0]);
        return r;
    }

    default long makeParamsFromComponents(byte[] p, byte[] q, byte[] g)
    {
        int[] err = new int[1];
        long r = ni_makeParamsFromComponents(p, q, g, err);
        handleErrors(err[0]);
        return r;
    }

    default long generateKeyPair(long paramsRef, RandSource rndSource)
    {
        int[] err = new int[1];
        long r = ni_generateKeyPair(paramsRef, err, rndSource);
        handleErrors(err[0]);
        return r;
    }

    default long makePrivateFromComponents(byte[] p, byte[] q, byte[] g,
                                           byte[] x, RandSource rndSource)
    {
        int[] err = new int[1];
        long r = ni_makePrivateFromComponents(p, q, g, x, err, rndSource);
        handleErrors(err[0]);
        return r;
    }

    default long makePublicFromComponents(byte[] p, byte[] q, byte[] g,
                                          byte[] y)
    {
        int[] err = new int[1];
        long r = ni_makePublicFromComponents(p, q, g, y, err);
        handleErrors(err[0]);
        return r;
    }

    default int getComponent(long specRef, int component, byte[] out)
    {
        return (int) handleErrors(ni_getComponent(specRef, component, out));
    }


    // ---- signing-session wrappers, mirror ECServiceNI ----

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
        int code = ni_initSign(ref, keyRef, digestName, rndSource);
        if (code == ErrorCode.JO_DSA_SIGN_UNAVAILABLE.getCode())
        {
            throw new ProviderCapabilityException(String.format(SIGN_KEY_REFUSED_FORMAT, pBits(keyRef)));
        }
        if (code == ErrorCode.JO_DSA_DIGEST_NOT_SUPPORTED.getCode())
        {
            throw new ProviderCapabilityException("the loaded provider does not sign DSA with " + digestName);
        }
        handleErrors(code);
    }

    /** The bit length of p in the key; the caller keeps the key reachable. */
    default int pBits(long keyRef)
    {
        byte[] p = new byte[getComponent(keyRef, COMP_P, null)];
        getComponent(keyRef, COMP_P, p);
        return new BigInteger(1, p).bitLength();
    }

    default void initVerify(long ref, long keyRef, String digestName)
    {
        int code = ni_initVerify(ref, keyRef, digestName);
        if (code == ErrorCode.JO_DSA_DIGEST_NOT_SUPPORTED.getCode())
        {
            throw new ProviderCapabilityException("the loaded provider does not verify DSA with " + digestName);
        }
        handleErrors(code);
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
     * (mirrors ECServiceNI.verify — JO_FAIL is suppressed by the
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
                throw new IllegalArgumentException("invalid key type for DSA");
            case JO_DSA_BITS_OUT_OF_RANGE:
                throw new IllegalArgumentException("DSA parameter bit size out of range");
            case JO_DSA_PUBLIC_VALUE_INVALID:
                throw new IllegalArgumentException("DSA y is outside its range or outside the subgroup of order q");
            case JO_DSA_PRIVATE_VALUE_INVALID:
                throw new IllegalArgumentException("DSA x is outside its range: [1, q-1]");
            default:
        }

        return baseErrorHandler(code);
    }
}
