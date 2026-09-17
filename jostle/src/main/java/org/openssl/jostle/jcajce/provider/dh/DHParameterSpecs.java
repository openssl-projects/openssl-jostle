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

import org.openssl.jostle.jcajce.spec.DHDomainParameterSpec;

import javax.crypto.spec.DHParameterSpec;

/**
 * The only two {@link DHParameterSpec} shapes Jostle reads: the bare JDK
 * class (PKCS#3, no q) and {@link DHDomainParameterSpec} (X9.42, carries q).
 * Any other subclass — including BouncyCastle's own
 * {@code org.bouncycastle.jcajce.spec.DHDomainParameterSpec}, which also
 * extends the JDK class and also carries a q — passes an {@code instanceof
 * DHParameterSpec} check but is not read as either shape, so its q would be
 * silently dropped and the parameters would be treated as PKCS#3.
 */
final class DHParameterSpecs
{
    private DHParameterSpecs()
    {
    }

    static boolean isAccepted(DHParameterSpec spec)
    {
        return spec.getClass() == DHParameterSpec.class || spec instanceof DHDomainParameterSpec;
    }
}
