package org.openssl.jostle.jcajce.provider;

import org.openssl.jostle.Loader;
import org.openssl.jostle.NativeServiceFFI;
import org.openssl.jostle.NativeServiceJNI;
import org.openssl.jostle.NativeServiceNI;
import org.openssl.jostle.jcajce.provider.kdf.KdfNI;
import org.openssl.jostle.jcajce.provider.kdf.KdfNIFFI;
import org.openssl.jostle.jcajce.provider.kdf.KdfNIJNI;
import org.openssl.jostle.jcajce.provider.md.MDServiceFFI;
import org.openssl.jostle.jcajce.provider.md.MDServiceJNI;
import org.openssl.jostle.jcajce.provider.md.MDServiceNI;
import org.openssl.jostle.jcajce.provider.mldsa.MLDSAServiceFFI;
import org.openssl.jostle.jcajce.provider.mldsa.MLDSAServiceJNI;
import org.openssl.jostle.jcajce.provider.mldsa.MLDSAServiceNI;
import org.openssl.jostle.jcajce.provider.mlkem.MLKEMServiceFFI;
import org.openssl.jostle.jcajce.provider.mlkem.MLKEMServiceJNI;
import org.openssl.jostle.jcajce.provider.mlkem.MLKEMServiceNI;
import org.openssl.jostle.jcajce.spec.SpecFFI;
import org.openssl.jostle.jcajce.spec.SpecJNI;
import org.openssl.jostle.jcajce.spec.SpecNI;
import org.openssl.jostle.util.asn1.Asn1NIFFI;
import org.openssl.jostle.util.asn1.Asn1Ni;
import org.openssl.jostle.util.asn1.Asn1NiJNI;
import org.openssl.jostle.util.ops.OperationsTestFFI;
import org.openssl.jostle.util.ops.OperationsTestJNI;
import org.openssl.jostle.util.ops.OperationsTestNI;

/**
 * Same class is implemented in src/main/java this version
 * will select an FFI version when the FFI interface is loaded.
 * NB: FFI will replace JNI eventually and later JVMs may not support it.
 */
public class NISelector
{
    protected static final BlockCipherNI BlockCipherNI;
    protected static final OpenSSLNI OpenSSLNI;
    public static final NativeServiceNI NativeServiceNI;
    public static final MLDSAServiceNI MLDSAServiceNI;
    public static final SpecNI SpecNI;
    public static final Asn1Ni Asn1NI;
    public static final OperationsTestNI OperationsTestNI;
    public static final SLHDSAServiceNI SLHDSAServiceNI;
    public static final MLKEMServiceNI MLKEMServiceNI;
    public static final KdfNI KdfNI;
    public static final MDServiceNI MDServiceNI;

    static
    {
        if (Loader.isFFI())
        {
            BlockCipherNI = new BlockCipherFFI();
            OpenSSLNI = new OpenSSLFFI();
            NativeServiceNI = new NativeServiceFFI();
            MLDSAServiceNI = new MLDSAServiceFFI();
            SpecNI = new SpecFFI();
            Asn1NI = new Asn1NIFFI();
            OperationsTestNI = new OperationsTestFFI();
            SLHDSAServiceNI = new SLHDSAServiceFFI();
            MLKEMServiceNI = new MLKEMServiceFFI();
            KdfNI = new KdfNIFFI();
            MDServiceNI = new MDServiceFFI();

        } else
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
        }
    }
}
