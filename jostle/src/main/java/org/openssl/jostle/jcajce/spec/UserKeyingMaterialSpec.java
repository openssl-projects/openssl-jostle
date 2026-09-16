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

import java.security.spec.AlgorithmParameterSpec;

/**
 * Carries the User Keying Material (UKM) supplied to a CMS key-agreement KDF.
 * For the X9.42 ({@code id-alg-ESDH} / {@code id-alg-SSDH}) KDF the UKM is the
 * optional {@code partyAInfo}; for the X9.63 EC schemes it is the
 * {@code SharedInfo} fed verbatim to the KDF.
 *
 * <p>Mirrors {@code org.bouncycastle.jcajce.spec.UserKeyingMaterialSpec} so a
 * caller building one from BC's CMS layer can move.
 *
 * <p>The optional <b>salt</b> is the HKDF salt for the RFC 8418 XDH schemes,
 * carried separately from the UKM as BouncyCastle carries it, and unused by
 * the X9.42 and X9.63 KDFs. RFC 8418 §2.2 makes the salt the UKM; BouncyCastle
 * leaves it to the caller, so we do too. Pass the same bytes as both for the
 * RFC's derivation.
 */
public class UserKeyingMaterialSpec implements AlgorithmParameterSpec
{
    private final byte[] userKeyingMaterial;
    private final byte[] salt;

    public UserKeyingMaterialSpec(byte[] userKeyingMaterial)
    {
        this(userKeyingMaterial, null);
    }

    public UserKeyingMaterialSpec(byte[] userKeyingMaterial, byte[] salt)
    {
        this.userKeyingMaterial = Arrays.clone(userKeyingMaterial);
        this.salt = Arrays.clone(salt);
    }

    public byte[] getUserKeyingMaterial()
    {
        return Arrays.clone(userKeyingMaterial);
    }

    /** The HKDF salt, or null when none was supplied. */
    public byte[] getSalt()
    {
        return Arrays.clone(salt);
    }
}
