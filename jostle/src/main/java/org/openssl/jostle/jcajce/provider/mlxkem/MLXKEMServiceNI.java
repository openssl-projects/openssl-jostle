/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider.mlxkem;

import org.openssl.jostle.jcajce.provider.DefaultServiceNI;
import org.openssl.jostle.jcajce.provider.ErrorCode;
import org.openssl.jostle.rand.RandSource;

/**
 * Native interface for the four TLS hybrid KEMs
 * (draft-ietf-tls-ecdhe-mlkem): X25519MLKEM768, X448MLKEM1024,
 * SecP256r1MLKEM768, SecP384r1MLKEM1024.
 *
 * <p>Narrower than {@code MLKEMServiceNI} in two ways, both forced by what the
 * provider exposes rather than by choice:
 *
 * <ol>
 * <li><b>No seed.</b> Hybrids have no {@code ML_KEM_SEED} equivalent, so
 *     keygen takes no seed and there is no {@code getSeed}.</li>
 * <li><b>No encoding.</b> There is no ASN.1 codec for a hybrid key in any
 *     provider — {@code i2d_PUBKEY} and {@code i2d_PrivateKey} both return -1,
 *     and {@code encoders.inc} registers nothing for them. What these getters
 *     return is the RAW material: the TLS wire share for the public half, the
 *     raw private bytes for the other. Decoding goes back through
 *     {@code EVP_PKEY_fromdata}, not a decoder.</li>
 * </ol>
 *
 * <p>Encapsulation and decapsulation are NOT here. They go through the shared
 * {@code SpecNI} encap/decap, which is generic over the key and needs no
 * kem-op name for these.
 */
public interface MLXKEMServiceNI extends DefaultServiceNI
{
    long ni_generateKeyPair(int type, int[] err, RandSource randSource);

    int ni_getPublicKey(long ref, byte[] output);

    int ni_getPrivateKey(long ref, byte[] output);

    int ni_decode_publicKey(long specRef, int keyType, byte[] input, int inputOffset, int inputLen);

    int ni_decode_privateKey(long specRef, int keyType, byte[] input, int inputOffset, int inputLen);

    /**
     * Generate a hybrid keypair.
     *
     * @param type one of the {@code KS_*} hybrid constants
     * @return the native key-spec reference
     */
    default long generateKeyPair(int type, RandSource randSource)
    {
        int[] err = new int[1];
        long ref = ni_generateKeyPair(type, err, randSource);
        handleErrors(err[0]);
        return ref;
    }

    /**
     * The public wire share. Pass a null output to learn the length.
     */
    default int getPublicKey(long ref, byte[] output)
    {
        return (int) handleErrors(ni_getPublicKey(ref, output));
    }

    /**
     * The raw private half. Pass a null output to learn the length.
     *
     * <p>Throws {@link UnsupportedOperationException} on the SecP variants,
     * whose private material the provider will not release — see
     * {@link #handleErrors}.
     *
     * <p><b>The length query is not an availability check.</b> The SecP
     * keymgmt reports how big the private param WOULD be and then refuses the
     * fetch, so a null-output call answers on all four groups while a real
     * fetch answers on two. Probe by fetching. No JCE surface reaches this —
     * no hybrid key class offers a private getter, precisely because the
     * behaviour is split — so the two-step is a raw-NI contract that only
     * {@code MLXKEMLimitTest} exercises.
     */
    default int getPrivateKey(long ref, byte[] output)
    {
        return (int) handleErrors(ni_getPrivateKey(ref, output));
    }

    default int decode_publicKey(long specRef, int keyType, byte[] input, int inputOffset, int inputLen)
    {
        return (int) handleErrors(ni_decode_publicKey(specRef, keyType, input, inputOffset, inputLen));
    }

    default int decode_privateKey(long specRef, int keyType, byte[] input, int inputOffset, int inputLen)
    {
        return (int) handleErrors(ni_decode_privateKey(specRef, keyType, input, inputOffset, inputLen));
    }

    default long handleErrors(long code)
    {
        if (code >= 0)
        {
            return code;
        }

        ErrorCode errorCode = ErrorCode.forCode(code);
        if (errorCode == ErrorCode.JO_INCORRECT_KEY_TYPE || errorCode == ErrorCode.JO_INVALID_KEY_TYPE)
        {
            throw new IllegalArgumentException("invalid key type for a hybrid ML-KEM");
        }
        if (errorCode == ErrorCode.JO_HYBRID_PRIVATE_EXPORT_UNSUPPORTED)
        {
            // Deliberately UnsupportedOperationException rather than an
            // OpenSSLException: nothing the caller can do makes this work, and
            // with no SPKI/PKCS#8 encoding for these keys either, there is no
            // alternative route to suggest.
            throw new UnsupportedOperationException(
                    "this hybrid variant does not expose its private key material");
        }
        return baseErrorHandler(code);
    }
}
