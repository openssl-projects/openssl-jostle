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

import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPublicKeySpec;
import java.math.BigInteger;

/**
 * A {@link DHPublicKeySpec} that also carries the full domain parameter set —
 * so a peer's public value {@code y} can be imported alongside a subgroup
 * order q (via {@link DHDomainParameterSpec}), not just the bare (p, g)
 * {@link DHPublicKeySpec} carries.
 *
 * <p>Without this, a peer public value imported through the bare
 * {@link DHPublicKeySpec} is read as PKCS#3 (no q) even when the local
 * key is X9.42 (has q, from a {@link DHDomainParameterSpec}) — the two
 * keys then carry different DH encoding forms, and OpenSSL's own
 * cross-form check refuses the agreement (see
 * {@code DHKeyAgreementSpi#engineDoPhase}).
 *
 * <p>Named to match BouncyCastle's
 * {@code org.bouncycastle.jcajce.spec.DHExtendedPublicKeySpec} for caller
 * familiarity, but it is a DIFFERENT class — same reasoning as
 * {@link DHDomainParameterSpec}'s own javadoc.
 *
 * <p>Importing a peer's y with the right q does not by itself make a
 * cross-form agreement work: OpenSSL still refuses {@code doPhase} between a
 * PKCS#3 key and an X9.42 one; BC's own {@code doPhase} does not — it agrees
 * on p, g and x alone and pairs the two forms happily.
 *
 * <p>A q-bearing import is checked here, at {@code KeyFactory.generatePublic}
 * time: y must lie in the subgroup q generates. One public-key check per
 * q-bearing import; BC's own KeyFactory pays the same cost at the same site.
 */
public class DHExtendedPublicKeySpec extends DHPublicKeySpec
{
    private final DHParameterSpec params;

    /**
     * @param y      the public value.
     * @param params the domain parameter set. Must not be null; supply
     *               {@link DHDomainParameterSpec} to carry q, or the bare
     *               {@link DHParameterSpec} for PKCS#3.
     */
    public DHExtendedPublicKeySpec(BigInteger y, DHParameterSpec params)
    {
        super(y, requireParams(params).getP(), params.getG());
        this.params = params;
    }

    private static DHParameterSpec requireParams(DHParameterSpec params)
    {
        if (params == null)
        {
            throw new IllegalArgumentException("params is null");
        }
        return params;
    }

    /** The full domain parameter set this public value was imported with. */
    public DHParameterSpec getParams()
    {
        return params;
    }
}
