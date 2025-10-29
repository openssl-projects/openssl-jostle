package org.openssl.jostle.test.crypto;

import org.openssl.jostle.NativeServiceNI;
import org.openssl.jostle.jcajce.provider.BlockCipherNI;
import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.jcajce.provider.OpenSSLNI;
import org.openssl.jostle.jcajce.provider.SLHDSAServiceNI;
import org.openssl.jostle.jcajce.provider.kdf.KdfNI;
import org.openssl.jostle.jcajce.provider.mldsa.MLDSAServiceNI;
import org.openssl.jostle.jcajce.provider.mlkem.MLKEMServiceNI;
import org.openssl.jostle.jcajce.spec.SpecNI;
import org.openssl.jostle.util.asn1.Asn1Ni;
import org.openssl.jostle.util.ops.OperationsTestNI;

public class TestNISelector extends NISelector
{


    static BlockCipherNI getBlockCipher()
    {
        return BlockCipherNI;
    }

    protected static OpenSSLNI getOpenSSLNI()
    {
        return OpenSSLNI;
    }

    public static NativeServiceNI getNativeServiceNI()
    {
        return NativeServiceNI;
    }

    public static MLDSAServiceNI getMLDSANI()
    {
        return MLDSAServiceNI;
    }

    public static MLKEMServiceNI getMLKEMNI()
    {
        return MLKEMServiceNI;
    }


    public static SLHDSAServiceNI getSLHDSANI()
    {
        return SLHDSAServiceNI;
    }

    public static SpecNI getSpecNI()
    {
        return SpecNI;
    }

    public static Asn1Ni getAsn1NI()
    {
        return Asn1NI;
    }

    public static KdfNI getKDFNI()
    {
        return KdfNI;
    }

    public static OperationsTestNI getOperationsTestNI()
    {
        return OperationsTestNI;
    }


}
