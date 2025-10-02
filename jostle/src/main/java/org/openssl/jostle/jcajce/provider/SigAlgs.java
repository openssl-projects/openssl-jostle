/*
 *  Copyright 2005-2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://www.openssl.org/source/license.html
 *
 */

package org.openssl.jostle.jcajce.provider;

/**
 * NB: Values passed to native layer as ordinals, if you change the order of any
 * values in this enum you must check the definitions in the native layer are correct.
 */
public enum SigAlgs
{
    DSA_SHA1,
    DSA_SHA2_224,
    DSA_SHA2_256,
    DSA_SHA2_384,
    DSA_SHA2_512,
    DSA_SHA3_224,
    DSA_SHA3_256,
    DSA_SHA3_384,
    DSA_SHA3_512,
    RSA_SHA2_224,
    RSA_SHA2_256,
    RSA_SHA2_384,
    RSA_SHA2_512,
    RSA_SHA3_224,
    RSA_SHA3_256,
    RSA_SHA3_384,
    RSA_SHA3_512,
    ECDSA_SHA2_224,
    ECDSA_SHA2_256,
    ECDSA_SHA2_384,
    ECDSA_SHA2_512,
    ECDSA_SHA3_224,
    ECDSA_SHA3_256,
    ECDSA_SHA3_384,
    ECDSA_SHA3_512,
    ED25519,
    ED25519_CTX,
    ED25519_PH,
    ED448,
    ED448_PH,
    MLDSA_44,
    MLDSA_65,
    MLDSA_87,
    MLDSA_44_SHA512,
    MLDSA_65_SHA512,
    MLDSA_87_SHA512,
    SLH_DSA_SHA2_128s,
    SLH_DSA_SHA2_128f,
    SLH_DSA_SHA2_192s,
    SLH_DSA_SHA2_192f,
    SLH_DSA_SHA2_256s,
    SLH_DSA_SHA2_256f,
    SLH_DSA_SHAKE_128s,
    SLH_DSA_SHAKE_128f,
    SLH_DSA_SHAKE_192s,
    SLH_DSA_SHAKE_192f,
    SLH_DSA_SHAKE_256s,
    SLH_DSA_SHAKE_256f
}
