/*
 *  Copyright 2005-2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://www.openssl.org/source/license.html
 *
 */

package org.openssl.jostle.jcajce.provider;

import org.openssl.jostle.NativeServiceJNI;
import org.openssl.jostle.NativeServiceNI;
import org.openssl.jostle.jcajce.provider.mldsa.MLDSAServiceJNI;
import org.openssl.jostle.jcajce.provider.mldsa.MLDSAServiceNI;
import org.openssl.jostle.jcajce.provider.mlkem.MLKEMServiceJNI;
import org.openssl.jostle.jcajce.provider.mlkem.MLKEMServiceNI;
import org.openssl.jostle.jcajce.spec.SpecJNI;
import org.openssl.jostle.jcajce.spec.SpecNI;
import org.openssl.jostle.util.asn1.Asn1Ni;
import org.openssl.jostle.util.asn1.Asn1NiJNI;
import org.openssl.jostle.util.ops.OperationsTestJNI;
import org.openssl.jostle.util.ops.OperationsTestNI;

/**
 * Implemented in here and in java22 code path
 * Version in Java 22 src path will check for the use of FFI interface and use that if loaded.
 */
public class NISelector
{
    public static final BlockCipherNI BlockCipherNI;
    public static final OpenSSLNI OpenSSLNI;
    public static final OperationsTestNI OperationsTestNI;

    public static final NativeServiceNI NativeServiceNI;
    public static final MLDSAServiceNI MLDSAServiceNI;
    public static final SpecNI SpecNI;
    public static final Asn1Ni Asn1NI;
    public static final SLHDSAServiceNI SLHDSAServiceNI;
    public static final MLKEMServiceNI MLKEMServiceNI;

    static
    {
        BlockCipherNI = new BlockCipherJNI();
        OpenSSLNI = new OpenSSLJNI();
        NativeServiceNI = new NativeServiceJNI();
        MLDSAServiceNI = new MLDSAServiceJNI();
        SpecNI = new SpecJNI();
        Asn1NI = new Asn1NiJNI();
        OperationsTestNI = new OperationsTestJNI();
        SLHDSAServiceNI = new SLHDSAServiceJNI();
        MLKEMServiceNI = new MLKEMServiceJNI();
    }
}
