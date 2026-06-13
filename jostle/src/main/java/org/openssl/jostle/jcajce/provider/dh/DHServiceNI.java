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

package org.openssl.jostle.jcajce.provider.dh;

import org.openssl.jostle.jcajce.provider.DefaultServiceNI;
import org.openssl.jostle.jcajce.provider.ErrorCode;
import org.openssl.jostle.rand.RandSource;

/**
 * Native interface for finite-field Diffie-Hellman operations.
 * Component selectors are stable integer identifiers passed across the
 * JNI/FFI boundary; they are mirrored from {@code interface/util/dh.h}.
 */
public interface DHServiceNI extends DefaultServiceNI
{
    // Component selectors. MUST match DH_COMP_* in dh.h.
    int COMP_P = 0;
    int COMP_Q = 1;
    int COMP_G = 2;
    int COMP_PUBLIC_VALUE = 3;
    int COMP_PRIVATE_VALUE = 4;


    /** 1 if OpenSSL recognises the DH group name, 0 otherwise. */
    int ni_groupSupported(String groupName);

    /**
     * Generate a DH keypair on a named group (RFC 7919
     * {@code ffdhe2048..ffdhe8192}, RFC 3526 {@code modp_*}).
     */
    long ni_generateKeyPairByGroup(String groupName, int[] err, RandSource rndSource);

    /**
     * Generate PKCS#3-style safe-prime domain parameters of the given
     * modulus length. Slow at 2048 bits and above — prefer the named
     * groups.
     */
    long ni_generateParameters(int pBits, int[] err, RandSource rndSource);

    /**
     * Construct a parameters-only DH key spec from explicit (p, g)
     * big-endian unsigned magnitudes.
     */
    long ni_makeParamsFromComponents(byte[] p, byte[] g, int[] err);

    /**
     * Generate a DH keypair from an established domain-parameter spec.
     */
    long ni_generateKeyPair(long paramsRef, int[] err, RandSource rndSource);

    /**
     * Construct a DH private key from explicit (p, g, x). The public
     * value y = g^x mod p is computed on the native side.
     */
    long ni_makePrivateFromComponents(byte[] p, byte[] g, byte[] x,
                                      int[] err, RandSource rndSource);

    /**
     * Construct a DH public key from explicit (p, g, y).
     */
    long ni_makePublicFromComponents(byte[] p, byte[] g, byte[] y,
                                     int[] err);

    int ni_getComponent(long specRef, int component, byte[] out);


    // ---------------------------------------------------------------
    // Key agreement session
    // ---------------------------------------------------------------

    long ni_allocateKex(int[] err);

    void ni_disposeKex(long reference);

    int ni_kexInit(long ref, long keyRef, RandSource rndSource);

    int ni_kexSetPeer(long ref, long peerRef, RandSource rndSource);

    /**
     * Derive the shared secret. The output is left-padded to the prime
     * length (the native side sets the OpenSSL {@code pad} exchange
     * parameter — see {@code dh_kex_init} in {@code interface/util/dh.c}).
     */
    int ni_kexDerive(long ref, byte[] out, int outOff, RandSource rndSource);


    // ---------------------------------------------------------------
    // Default error-handling wrappers.
    // ---------------------------------------------------------------

    /**
     * Probe whether OpenSSL recognises the given DH group name. Used by
     * the SPI to pre-validate group names so unknown groups surface as
     * a typed exception rather than a generic OpenSSLException from the
     * keygen path.
     */
    default boolean groupSupported(String groupName)
    {
        return ni_groupSupported(groupName) == 1;
    }

    default long generateKeyPairByGroup(String groupName, RandSource rndSource)
    {
        int[] err = new int[1];
        long r = ni_generateKeyPairByGroup(groupName, err, rndSource);
        handleErrors(err[0]);
        return r;
    }

    default long generateParameters(int pBits, RandSource rndSource)
    {
        int[] err = new int[1];
        long r = ni_generateParameters(pBits, err, rndSource);
        handleErrors(err[0]);
        return r;
    }

    default long makeParamsFromComponents(byte[] p, byte[] g)
    {
        int[] err = new int[1];
        long r = ni_makeParamsFromComponents(p, g, err);
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

    default long makePrivateFromComponents(byte[] p, byte[] g, byte[] x,
                                           RandSource rndSource)
    {
        int[] err = new int[1];
        long r = ni_makePrivateFromComponents(p, g, x, err, rndSource);
        handleErrors(err[0]);
        return r;
    }

    default long makePublicFromComponents(byte[] p, byte[] g, byte[] y)
    {
        int[] err = new int[1];
        long r = ni_makePublicFromComponents(p, g, y, err);
        handleErrors(err[0]);
        return r;
    }

    default int getComponent(long specRef, int component, byte[] out)
    {
        return (int) handleErrors(ni_getComponent(specRef, component, out));
    }


    // ---- key-agreement wrappers, mirror ECServiceNI ----

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
                throw new IllegalArgumentException("invalid key type for DH");
            case JO_DH_BITS_OUT_OF_RANGE:
                throw new IllegalArgumentException("DH parameter bit size out of range");
            default:
        }

        return baseErrorHandler(code);
    }
}
