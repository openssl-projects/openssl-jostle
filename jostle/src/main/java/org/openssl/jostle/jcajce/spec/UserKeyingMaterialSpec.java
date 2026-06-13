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
 * caller can hand either spec to the Jostle key-agreement SPIs — the SPIs also
 * accept BouncyCastle's spec reflectively, which is what the CMS layer passes.
 */
public class UserKeyingMaterialSpec implements AlgorithmParameterSpec
{
    private final byte[] userKeyingMaterial;

    public UserKeyingMaterialSpec(byte[] userKeyingMaterial)
    {
        this.userKeyingMaterial = Arrays.clone(userKeyingMaterial);
    }

    public byte[] getUserKeyingMaterial()
    {
        return Arrays.clone(userKeyingMaterial);
    }
}
