/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.spec;

import org.openssl.jostle.util.Arrays;
import org.openssl.jostle.util.asn1.ASN1ObjectIdentifier;
import org.openssl.jostle.util.asn1.Der;
import org.openssl.jostle.util.asn1.oids.NISTObjectIdentifiers;
import org.openssl.jostle.util.asn1.oids.X9ObjectIdentifiers;

/**
 * The KDF {@code AlgorithmIdentifier} encodings the key-transport and KEM specs carry, in one place: the
 * default (X9.44 KDF3 with SHA-256, BouncyCastle's default for both), the encoding built from OIDs, and the
 * size check a caller-supplied encoding passes.
 */
final class KdfAlgorithmIdentifiers
{
    /**
     * Ceiling on the KDF {@code AlgorithmIdentifier} DER. An {@code AlgorithmIdentifier} naming a KDF and a
     * digest is under 40 bytes; 256 leaves room for parameters not yet interpreted without being open-ended.
     */
    static final int MAX_KDF_ALGORITHM_BYTES = 256;

    /** KDF3 (X9.44 concatenation KDF) with SHA-256. */
    private static final byte[] KDF3_SHA256 = of(X9ObjectIdentifiers.id_kdf_kdf3, NISTObjectIdentifiers.id_sha256);

    private KdfAlgorithmIdentifiers()
    {
    }

    /** @return a fresh copy of the default KDF encoding. */
    static byte[] defaultKdf()
    {
        return Arrays.clone(KDF3_SHA256);
    }

    /**
     * The encoding of a KDF named by its OID and, for X9.44 KDF2/KDF3, its digest's OID. {@code digest} is null
     * for the RFC 8619 HKDF OIDs, which name their digest in the KDF OID and carry no parameters.
     */
    static byte[] of(ASN1ObjectIdentifier kdf, ASN1ObjectIdentifier digest)
    {
        if (kdf == null)
        {
            throw new NullPointerException("kdf is null");
        }
        return (digest == null)
                ? Der.sequence(Der.objectIdentifier(kdf.getId()))
                : Der.sequence(Der.objectIdentifier(kdf.getId()),
                        Der.sequence(Der.objectIdentifier(digest.getId())));
    }

    /** @return a copy of a caller-supplied encoding, after the null and size checks. */
    static byte[] checked(byte[] derAlgorithmIdentifier)
    {
        if (derAlgorithmIdentifier == null)
        {
            throw new NullPointerException("derAlgorithmIdentifier is null");
        }
        if (derAlgorithmIdentifier.length > MAX_KDF_ALGORITHM_BYTES)
        {
            throw new IllegalArgumentException(
                    "KDF AlgorithmIdentifier exceeds " + MAX_KDF_ALGORITHM_BYTES + " bytes: "
                            + derAlgorithmIdentifier.length);
        }
        return Arrays.clone(derAlgorithmIdentifier);
    }
}
