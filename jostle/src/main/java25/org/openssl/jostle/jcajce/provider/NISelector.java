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

package org.openssl.jostle.jcajce.provider;

import org.openssl.jostle.Loader;
import org.openssl.jostle.NativeServiceJNI;
import org.openssl.jostle.NativeServiceNI;
import org.openssl.jostle.jcajce.provider.blockcipher.*;
import org.openssl.jostle.jcajce.provider.dh.DHServiceFFM;
import org.openssl.jostle.jcajce.provider.dh.DHServiceJNI;
import org.openssl.jostle.jcajce.provider.dh.DHServiceNI;
import org.openssl.jostle.jcajce.provider.dsa.DSAServiceFFM;
import org.openssl.jostle.jcajce.provider.dsa.DSAServiceJNI;
import org.openssl.jostle.jcajce.provider.dsa.DSAServiceNI;
import org.openssl.jostle.jcajce.provider.ec.ECServiceFFM;
import org.openssl.jostle.jcajce.provider.ec.ECServiceJNI;
import org.openssl.jostle.jcajce.provider.ec.ECServiceNI;
import org.openssl.jostle.jcajce.provider.xec.XECServiceFFM;
import org.openssl.jostle.jcajce.provider.xec.XECServiceJNI;
import org.openssl.jostle.jcajce.provider.cert.X509NI;
import org.openssl.jostle.jcajce.provider.certpath.CertPathNI;
import org.openssl.jostle.jcajce.provider.cert.X509ServiceFFM;
import org.openssl.jostle.jcajce.provider.cert.X509ServiceJNI;
import org.openssl.jostle.jcajce.provider.certpath.CertPathServiceFFM;
import org.openssl.jostle.jcajce.provider.certpath.CertPathServiceJNI;
import org.openssl.jostle.jcajce.provider.xec.XECServiceNI;
import org.openssl.jostle.jcajce.provider.ed.EDServiceJNI;
import org.openssl.jostle.jcajce.provider.ed.EDServiceNI;
import org.openssl.jostle.jcajce.provider.ed.EdDSAServiceFFM;
import org.openssl.jostle.jcajce.provider.kdf.KdfNI;
import org.openssl.jostle.jcajce.provider.kdf.KdfNIFFM;
import org.openssl.jostle.jcajce.provider.kdf.KdfNIJNI;
import org.openssl.jostle.jcajce.provider.kdf.MemoryHardKdfNI;
import org.openssl.jostle.jcajce.provider.kdf.MemoryHardKdfNIFFM;
import org.openssl.jostle.jcajce.provider.kdf.MemoryHardKdfNIJNI;
import org.openssl.jostle.jcajce.provider.ks.KSServiceFFM;
import org.openssl.jostle.jcajce.provider.ks.KSServiceJNI;
import org.openssl.jostle.jcajce.provider.ks.KSServiceNI;
import org.openssl.jostle.jcajce.provider.mac.MacServiceFFM;
import org.openssl.jostle.jcajce.provider.mac.MacServiceJNI;
import org.openssl.jostle.jcajce.provider.mac.MacServiceNI;
import org.openssl.jostle.jcajce.provider.md.MDServiceFFM;
import org.openssl.jostle.jcajce.provider.md.MDServiceJNI;
import org.openssl.jostle.jcajce.provider.md.MDServiceNI;
import org.openssl.jostle.jcajce.provider.mldsa.MLDSAServiceFFM;
import org.openssl.jostle.jcajce.provider.mldsa.MLDSAServiceJNI;
import org.openssl.jostle.jcajce.provider.mldsa.MLDSAServiceNI;
import org.openssl.jostle.jcajce.provider.mlkem.MLKEMServiceFFM;
import org.openssl.jostle.jcajce.provider.mlkem.MLKEMServiceJNI;
import org.openssl.jostle.jcajce.provider.mlkem.MLKEMServiceNI;
import org.openssl.jostle.jcajce.provider.mlxkem.MLXKEMServiceFFM;
import org.openssl.jostle.jcajce.provider.mlxkem.MLXKEMServiceJNI;
import org.openssl.jostle.jcajce.provider.mlxkem.MLXKEMServiceNI;
import org.openssl.jostle.jcajce.provider.rand.RandServiceFFM;
import org.openssl.jostle.jcajce.provider.rand.RandServiceJNI;
import org.openssl.jostle.jcajce.provider.rand.RandServiceNI;
import org.openssl.jostle.jcajce.provider.rsa.*;
import org.openssl.jostle.jcajce.provider.slhdsa.SLHDSAServiceFFM;
import org.openssl.jostle.jcajce.provider.slhdsa.SLHDSAServiceJNI;
import org.openssl.jostle.jcajce.provider.slhdsa.SLHDSAServiceNI;
import org.openssl.jostle.jcajce.spec.SpecFFM;
import org.openssl.jostle.jcajce.spec.SpecJNI;
import org.openssl.jostle.jcajce.spec.SpecNI;
import org.openssl.jostle.util.asn1.Asn1NIFFM;
import org.openssl.jostle.util.asn1.Asn1Ni;
import org.openssl.jostle.util.asn1.Asn1NiJNI;
import org.openssl.jostle.util.ops.OperationsTestFFM;
import org.openssl.jostle.util.ops.OperationsTestJNI;
import org.openssl.jostle.util.ops.OperationsTestNI;

/**
 * Same class is implemented in src/main/java this version
 * will select an FFM version when the FFM interface is loaded.
 * NB: FFM will replace JNI eventually, and later JVMs may not support it.
 */
public class NISelector
{
    public static final BlockCipherNI BlockCipherNI;
    public static final CCMCipherNI CCMCipherNI;
    public static final OpenSSLNI OpenSSLNI;
    public static final NativeServiceNI NativeServiceNI;
    public static final MLDSAServiceNI MLDSAServiceNI;
    public static final SpecNI SpecNI;
    public static final Asn1Ni Asn1NI;
    public static final OperationsTestNI OperationsTestNI;
    public static final SLHDSAServiceNI SLHDSAServiceNI;
    public static final MLKEMServiceNI MLKEMServiceNI;
    public static final MLXKEMServiceNI MLXKEMServiceNI;
    public static final KdfNI KdfNI;

    // Base-provider only: scrypt / Argon2 are not served by the FIPS module,
    // so there is no FIPSNISelector counterpart (see MemoryHardKdfNI).
    public static final MemoryHardKdfNI MemoryHardKdfNI;
    public static final MDServiceNI MDServiceNI;
    public static final EDServiceNI EDServiceNI;
    public static final RSAServiceNI RSAServiceNI;
    public static final RSAOAEPCipherNI RSAOAEPCipherNI;
    public static final RSAPKCS1CipherNI RSAPKCS1CipherNI;
    public static final ECServiceNI ECServiceNI;
    public static final DSAServiceNI DSAServiceNI;
    public static final DHServiceNI DHServiceNI;
    public static final CertPathNI CertPathNI;
    public static final X509NI X509NI;
    public static final XECServiceNI XECServiceNI;
    public static final MacServiceNI MacServiceNI;
    public static final RandServiceNI RandServiceNI;
    public static final KSServiceNI KSServiceNI;

    static
    {
        if (Loader.isFFM())
        {
            BlockCipherNI = new BlockCipherFFM();
            CCMCipherNI = new CCMCipherFFM();
            OpenSSLNI = new OpenSSLFFM();
            NativeServiceNI = new NativeServiceFFM();
            MLDSAServiceNI = new MLDSAServiceFFM();
            SpecNI = new SpecFFM();
            Asn1NI = new Asn1NIFFM();
            OperationsTestNI = new OperationsTestFFM();
            SLHDSAServiceNI = new SLHDSAServiceFFM();
            MLKEMServiceNI = new MLKEMServiceFFM();
            MLXKEMServiceNI = new MLXKEMServiceFFM();
            KdfNI = new KdfNIFFM();
            MemoryHardKdfNI = new MemoryHardKdfNIFFM();
            MDServiceNI = new MDServiceFFM();
            EDServiceNI = new EdDSAServiceFFM();
            RSAServiceNI = new RSAServiceFFM();
            RSAOAEPCipherNI = new RSAOAEPCipherFFM();
            RSAPKCS1CipherNI = new RSAPKCS1CipherFFM();
            ECServiceNI = new ECServiceFFM();
            DSAServiceNI = new DSAServiceFFM();
            DHServiceNI = new DHServiceFFM();
            CertPathNI = new CertPathServiceFFM();
            X509NI = new X509ServiceFFM();
            XECServiceNI = new XECServiceFFM();
            MacServiceNI = new MacServiceFFM();
            RandServiceNI = new RandServiceFFM();
            KSServiceNI = new KSServiceFFM();

        }
        else
        {
            BlockCipherNI = new BlockCipherJNI();
            CCMCipherNI = new CCMCipherJNI();
            OpenSSLNI = new OpenSSLJNI();
            NativeServiceNI = new NativeServiceJNI();
            MLDSAServiceNI = new MLDSAServiceJNI();
            SpecNI = new SpecJNI();
            Asn1NI = new Asn1NiJNI();
            OperationsTestNI = new OperationsTestJNI();
            SLHDSAServiceNI = new SLHDSAServiceJNI();
            MLKEMServiceNI = new MLKEMServiceJNI();
            MLXKEMServiceNI = new MLXKEMServiceJNI();
            KdfNI = new KdfNIJNI();
            MemoryHardKdfNI = new MemoryHardKdfNIJNI();
            MDServiceNI = new MDServiceJNI();
            EDServiceNI = new EDServiceJNI();
            RSAServiceNI = new RSAServiceJNI();
            RSAOAEPCipherNI = new RSAOAEPCipherJNI();
            RSAPKCS1CipherNI = new RSAPKCS1CipherJNI();
            ECServiceNI = new ECServiceJNI();
            DSAServiceNI = new DSAServiceJNI();
            DHServiceNI = new DHServiceJNI();
            CertPathNI = new CertPathServiceJNI();
            X509NI = new X509ServiceJNI();
            XECServiceNI = new XECServiceJNI();
            MacServiceNI = new MacServiceJNI();
            RandServiceNI = new RandServiceJNI();
            KSServiceNI = new KSServiceJNI();
        }
    }
}
