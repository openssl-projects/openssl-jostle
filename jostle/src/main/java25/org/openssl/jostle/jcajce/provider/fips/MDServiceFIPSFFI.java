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

import org.openssl.jostle.jcajce.provider.md.MDServiceFFI;

/**
 * FFI implementation of MDServiceNI backed by the FIPS interface library:
 * the base marshalling with a library-scoped lookup pinned to the extracted
 * FIPS library (see {@link FIPSLibraryLookup}).
 */
class MDServiceFIPSFFI extends MDServiceFFI
{
    MDServiceFIPSFFI()
    {
        super(FIPSLibraryLookup.get());
    }
}
