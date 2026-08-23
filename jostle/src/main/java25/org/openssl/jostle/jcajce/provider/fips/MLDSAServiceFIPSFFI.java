/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider.fips;

import org.openssl.jostle.jcajce.provider.mldsa.MLDSAServiceFFI;

/**
 * FFI implementation backed by the FIPS interface library: the base
 * marshalling with a library-scoped lookup pinned to the extracted FIPS
 * library (see {@link FIPSLibraryLookup}).
 *
 * <p>The scoped lookup is load-bearing, not tidiness: both interface
 * libraries export the same {@code Jo*} symbol names, so the process-global
 * loaderLookup would resolve into whichever loaded first.
 */
class MLDSAServiceFIPSFFI extends MLDSAServiceFFI
{
    MLDSAServiceFIPSFFI()
    {
        super(FIPSLibraryLookup.get(), FIPSLibraryLookup.SYMBOL_PREFIX);
    }

    /**
     * This NI is bound to the FIPS interface library, so the operations it
     * drives run inside the FIPS module - which supplies its own entropy and
     * never consults a caller-supplied SecureRandom (the FIPS lib ctx
     * deliberately omits the java_rand_bridge; see jostle_fips_ctx.c). The PQ
     * SPIs read this through {@code DefaultServiceNI.providerManagesEntropy()}
     * to skip a strength check that would judge a value nothing reads.
     */
    @Override
    public String providerName()
    {
        return JostleFIPSProvider.PROVIDER_NAME;
    }
}
