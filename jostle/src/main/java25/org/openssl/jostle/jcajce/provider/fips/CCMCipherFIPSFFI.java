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

import org.openssl.jostle.jcajce.provider.blockcipher.CCMCipherFFI;

/**
 * FFI implementation of CCMCipherNI backed by the FIPS interface library:
 * the base marshalling with a library-scoped lookup pinned to the extracted
 * FIPS library (see {@link FIPSLibraryLookup}).
 */
class CCMCipherFIPSFFI extends CCMCipherFFI
{
    CCMCipherFIPSFFI()
    {
        super(FIPSLibraryLookup.get());
    }
}
