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

import org.openssl.jostle.Loader;
import org.openssl.jostle.jcajce.provider.blockcipher.BlockCipherNI;
import org.openssl.jostle.jcajce.provider.blockcipher.CCMCipherNI;
import org.openssl.jostle.jcajce.provider.md.MDServiceNI;

/**
 * Java 25 override of the FIPS NI selector: picks the FFI implementations
 * when the loader resolved the FFI interface, matching the base NISelector's
 * selection. Public surface must stay identical to the Java 8 baseline
 * (multi-release ABI rule).
 */
public class FIPSNISelector
{
    public static final OpenSSLFIPSNI OpenSSLFIPSNI;
    public static final MDServiceNI MDServiceNI;
    public static final BlockCipherNI BlockCipherNI;
    public static final CCMCipherNI CCMCipherNI;

    static
    {
        Loader.loadFipsInterface();
        if (Loader.isFFI())
        {
            OpenSSLFIPSNI = new OpenSSLFIPSFFI();
            MDServiceNI = new MDServiceFIPSFFI();
            BlockCipherNI = new BlockCipherFIPSFFI();
            CCMCipherNI = new CCMCipherFIPSFFI();
        }
        else
        {
            OpenSSLFIPSNI = new OpenSSLFIPSJNI();
            MDServiceNI = new MDServiceFIPSJNI();
            BlockCipherNI = new BlockCipherFIPSJNI();
            CCMCipherNI = new CCMCipherFIPSJNI();
        }
    }
}
