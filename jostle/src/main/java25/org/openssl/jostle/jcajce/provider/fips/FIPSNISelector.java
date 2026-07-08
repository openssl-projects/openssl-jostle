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
import org.openssl.jostle.jcajce.provider.dh.DHServiceNI;
import org.openssl.jostle.jcajce.provider.dsa.DSAServiceNI;
import org.openssl.jostle.jcajce.provider.ec.ECServiceNI;
import org.openssl.jostle.jcajce.provider.kdf.KdfNI;
import org.openssl.jostle.jcajce.provider.rand.RandServiceNI;
import org.openssl.jostle.jcajce.provider.xec.XECServiceNI;
import org.openssl.jostle.jcajce.provider.rsa.RSAOAEPCipherNI;
import org.openssl.jostle.jcajce.provider.rsa.RSAPKCS1CipherNI;
import org.openssl.jostle.jcajce.provider.rsa.RSAServiceNI;
import org.openssl.jostle.jcajce.spec.SpecNI;
import org.openssl.jostle.util.asn1.Asn1Ni;
import org.openssl.jostle.util.ops.OperationsTestNI;

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
    public static final MacServiceNI MacServiceNI;
    public static final RandServiceNI RandServiceNI;
    public static final SpecNI SpecNI;
    public static final Asn1Ni Asn1NI;
    public static final RSAServiceNI RSAServiceNI;
    public static final RSAOAEPCipherNI RSAOAEPCipherNI;
    public static final RSAPKCS1CipherNI RSAPKCS1CipherNI;
    public static final ECServiceNI ECServiceNI;
    public static final DSAServiceNI DSAServiceNI;
    public static final DHServiceNI DHServiceNI;
    public static final XECServiceNI XECServiceNI;
    public static final KdfNI KdfNI;
    public static final OperationsTestNI OperationsTestNI;

    static
    {
        Loader.loadFipsInterface();
        if (Loader.isFFI())
        {
            OpenSSLFIPSNI = new OpenSSLFIPSFFI();
            MDServiceNI = new MDServiceFIPSFFI();
            BlockCipherNI = new BlockCipherFIPSFFI();
            CCMCipherNI = new CCMCipherFIPSFFI();
            MacServiceNI = new MacServiceFIPSFFI();
            RandServiceNI = new RandServiceFIPSFFI();
            SpecNI = new SpecFIPSFFI();
            Asn1NI = new Asn1FIPSFFI();
            RSAServiceNI = new RSAServiceFIPSFFI();
            RSAOAEPCipherNI = new RSAOAEPCipherFIPSFFI();
            RSAPKCS1CipherNI = new RSAPKCS1CipherFIPSFFI();
            ECServiceNI = new ECServiceFIPSFFI();
            DSAServiceNI = new DSAServiceFIPSFFI();
            DHServiceNI = new DHServiceFIPSFFI();
            XECServiceNI = new XECServiceFIPSFFI();
            KdfNI = new KdfFIPSFFI();
            OperationsTestNI = new OperationsTestFIPSFFI();
        }
        else
        {
            OpenSSLFIPSNI = new OpenSSLFIPSJNI();
            MDServiceNI = new MDServiceFIPSJNI();
            BlockCipherNI = new BlockCipherFIPSJNI();
            CCMCipherNI = new CCMCipherFIPSJNI();
            MacServiceNI = new MacServiceFIPSJNI();
            RandServiceNI = new RandServiceFIPSJNI();
            SpecNI = new SpecFIPSJNI();
            Asn1NI = new Asn1FIPSJNI();
            RSAServiceNI = new RSAServiceFIPSJNI();
            RSAOAEPCipherNI = new RSAOAEPCipherFIPSJNI();
            RSAPKCS1CipherNI = new RSAPKCS1CipherFIPSJNI();
            ECServiceNI = new ECServiceFIPSJNI();
            DSAServiceNI = new DSAServiceFIPSJNI();
            DHServiceNI = new DHServiceFIPSJNI();
            XECServiceNI = new XECServiceFIPSJNI();
            KdfNI = new KdfFIPSJNI();
            OperationsTestNI = new OperationsTestFIPSJNI();
        }
    }
}
