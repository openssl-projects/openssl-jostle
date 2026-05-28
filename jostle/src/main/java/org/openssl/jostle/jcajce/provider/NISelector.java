/*
 *  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider;

import org.openssl.jostle.NativeServiceJNI;
import org.openssl.jostle.NativeServiceNI;
import org.openssl.jostle.jcajce.provider.blockcipher.BlockCipherJNI;
import org.openssl.jostle.jcajce.provider.blockcipher.BlockCipherNI;
import org.openssl.jostle.jcajce.provider.ec.ECServiceJNI;
import org.openssl.jostle.jcajce.provider.ec.ECServiceNI;
import org.openssl.jostle.jcajce.provider.ed.EDServiceJNI;
import org.openssl.jostle.jcajce.provider.ed.EDServiceNI;
import org.openssl.jostle.jcajce.provider.kdf.KdfNI;
import org.openssl.jostle.jcajce.provider.kdf.KdfNIJNI;
import org.openssl.jostle.jcajce.provider.mac.MacServiceNI;
import org.openssl.jostle.jcajce.provider.mac.MacServiceJNI;
import org.openssl.jostle.jcajce.provider.md.MDServiceJNI;
import org.openssl.jostle.jcajce.provider.md.MDServiceNI;
import org.openssl.jostle.jcajce.provider.mldsa.MLDSAServiceJNI;
import org.openssl.jostle.jcajce.provider.mldsa.MLDSAServiceNI;
import org.openssl.jostle.jcajce.provider.mlkem.MLKEMServiceJNI;
import org.openssl.jostle.jcajce.provider.mlkem.MLKEMServiceNI;
import org.openssl.jostle.jcajce.provider.rand.RandServiceJNI;
import org.openssl.jostle.jcajce.provider.rand.RandServiceNI;
import org.openssl.jostle.jcajce.provider.rsa.RSAOAEPCipherJNI;
import org.openssl.jostle.jcajce.provider.rsa.RSAOAEPCipherNI;
import org.openssl.jostle.jcajce.provider.rsa.RSAPKCS1CipherJNI;
import org.openssl.jostle.jcajce.provider.rsa.RSAPKCS1CipherNI;
import org.openssl.jostle.jcajce.provider.rsa.RSAServiceJNI;
import org.openssl.jostle.jcajce.provider.rsa.RSAServiceNI;
import org.openssl.jostle.jcajce.provider.slhdsa.SLHDSAServiceJNI;
import org.openssl.jostle.jcajce.provider.slhdsa.SLHDSAServiceNI;
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
    public static final KdfNI KdfNI;
    public static final MDServiceNI MDServiceNI;
    public static final EDServiceNI EDServiceNI;
    public static final RSAServiceNI RSAServiceNI;
    public static final RSAOAEPCipherNI RSAOAEPCipherNI;
    public static final RSAPKCS1CipherNI RSAPKCS1CipherNI;
    public static final ECServiceNI ECServiceNI;
    public static final MacServiceNI MacServiceNI;
    public static final RandServiceNI RandServiceNI;

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
        KdfNI = new KdfNIJNI();
        MDServiceNI = new MDServiceJNI();
        EDServiceNI = new EDServiceJNI();
        RSAServiceNI = new RSAServiceJNI();
        RSAOAEPCipherNI = new RSAOAEPCipherJNI();
        RSAPKCS1CipherNI = new RSAPKCS1CipherJNI();
        ECServiceNI = new ECServiceJNI();
        MacServiceNI = new MacServiceJNI();
        RandServiceNI = new RandServiceJNI();
    }
}
