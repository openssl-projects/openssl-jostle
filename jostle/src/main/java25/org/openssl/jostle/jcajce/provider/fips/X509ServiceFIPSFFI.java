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

package org.openssl.jostle.jcajce.provider.fips;

import org.openssl.jostle.jcajce.provider.cert.X509ServiceFFI;

/**
 * FFI binding for the X.509 entry points in the FIPS interface library.
 *
 * <p>The lookup and the symbol prefix are SEPARATE arguments on purpose, per
 * {@link FIPSLibraryLookup}: bundling them into a name-rewriting lookup would
 * put the identity back in one value and restore the single point of failure
 * the split exists to remove. Either mistake alone now fails at construction.
 */
public class X509ServiceFIPSFFI
    extends X509ServiceFFI
{
    public X509ServiceFIPSFFI()
    {
        super(FIPSLibraryLookup.get(), "JoFIPS_");
    }

    /** FIPS library, so FIPS provider - see {@code DefaultServiceNI.providerName()}. */
    @Override
    public String providerName()
    {
        return JostleFIPSProvider.PROVIDER_NAME;
    }
}
