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
import org.openssl.jostle.jcajce.provider.mac.MacServiceNI;
import org.openssl.jostle.jcajce.provider.md.MDServiceNI;
import org.openssl.jostle.jcajce.provider.rand.RandServiceNI;

/**
 * Selector for the FIPS NI implementations, mirroring NISelector but bound to
 * the FIPS interface library. First touch triggers the lazy, provider-driven
 * load of that library ({@link Loader#loadFipsInterface()}) - the base
 * Loader.load() never touches it, so non-FIPS deployments never load it.
 *
 * <p>This Java 8 baseline is JNI-only; the Java 25 override selects the FFI
 * implementations when the loader resolved the FFI interface.
 */
public class FIPSNISelector
{
    public static final OpenSSLFIPSNI OpenSSLFIPSNI;
    public static final MDServiceNI MDServiceNI;
    public static final BlockCipherNI BlockCipherNI;
    public static final CCMCipherNI CCMCipherNI;
    public static final MacServiceNI MacServiceNI;
    public static final RandServiceNI RandServiceNI;

    static
    {
        Loader.loadFipsInterface();
        OpenSSLFIPSNI = new OpenSSLFIPSJNI();
        MDServiceNI = new MDServiceFIPSJNI();
        BlockCipherNI = new BlockCipherFIPSJNI();
        CCMCipherNI = new CCMCipherFIPSJNI();
        MacServiceNI = new MacServiceFIPSJNI();
        RandServiceNI = new RandServiceFIPSJNI();
    }
}
