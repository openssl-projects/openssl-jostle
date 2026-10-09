/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider.kts;

import org.openssl.jostle.jcajce.spec.MLXKEMParameterSpec;
import org.openssl.jostle.jcajce.spec.OSSLKeyType;

import java.security.ProviderException;

/**
 * The encapsulation and shared-secret sizes of each KEM key type, as a bound on the lengths the native layer
 * reports. The native query stays the source of every length; this table only refuses a length that disagrees
 * with the specification, before anything is allocated from it.
 *
 * <p>ML-KEM: FIPS 203, Table 3 (ciphertext 768 / 1088 / 1568 bytes, shared secret 32). The hybrids are the
 * concatenation of their two components: ML-KEM as above; X25519 and X448 shares of 32 and 56 bytes (RFC 7748,
 * section 5); P-256 and P-384 shares as uncompressed SEC 1 points of 65 and 97 bytes. The order of the two
 * components does not change the sums.
 */
public final class KemSizes
{
    private KemSizes()
    {
    }

    /**
     * The encapsulation length for the type.
     *
     * @throws ProviderException when the type is not a KEM key type.
     */
    public static int ciphertextLength(OSSLKeyType type)
    {
        switch (type)
        {
            case ML_KEM_512:
                return 768;
            case ML_KEM_768:
                return 1088;
            case ML_KEM_1024:
                return 1568;
            case X25519MLKEM768:
                return 1088 + 32;
            case X448MLKEM1024:
                return 1568 + 56;
            case SecP256r1MLKEM768:
                return 65 + 1088;
            case SecP384r1MLKEM1024:
                return 97 + 1568;
            default:
                throw new ProviderException("not a KEM key type: " + type);
        }
    }

    /**
     * The shared-secret length for the type. The hybrids' come from {@link MLXKEMParameterSpec}, which already holds
     * the two components' secret sizes.
     *
     * @throws ProviderException when the type is not a KEM key type.
     */
    public static int sharedSecretLength(OSSLKeyType type)
    {
        switch (type)
        {
            case ML_KEM_512:
            case ML_KEM_768:
            case ML_KEM_1024:
                return 32;
            case X25519MLKEM768:
            case X448MLKEM1024:
            case SecP256r1MLKEM768:
            case SecP384r1MLKEM1024:
                return MLXKEMParameterSpec.getSpecForOSSLType(type).getSharedSecretBytes();
            default:
                throw new ProviderException("not a KEM key type: " + type);
        }
    }

    /**
     * The queried encapsulation length, when it equals the table's.
     *
     * @throws ProviderException when it does not: the library and the specification disagree.
     */
    public static int checkedCiphertextLength(OSSLKeyType type, long queried)
    {
        return checked("encapsulation", type, queried, ciphertextLength(type));
    }

    /**
     * The queried shared-secret length, when it equals the table's.
     *
     * @throws ProviderException when it does not: the library and the specification disagree.
     */
    public static int checkedSharedSecretLength(OSSLKeyType type, long queried)
    {
        return checked("shared secret", type, queried, sharedSecretLength(type));
    }

    private static int checked(String what, OSSLKeyType type, long queried, int expected)
    {
        if (queried != expected)
        {
            throw new ProviderException(type + " " + what + " length reported as " + queried + ", expected "
                    + expected);
        }
        return expected;
    }
}
