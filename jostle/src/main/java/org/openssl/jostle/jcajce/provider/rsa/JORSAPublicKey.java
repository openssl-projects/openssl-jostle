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

package org.openssl.jostle.jcajce.provider.rsa;

import org.openssl.jostle.jcajce.interfaces.OSSLKey;
import org.openssl.jostle.jcajce.interfaces.RSAPublicKey;
import org.openssl.jostle.jcajce.provider.AsymmetricKeyImpl;
import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.util.asn1.Asn1Ni;
import org.openssl.jostle.jcajce.spec.PKEYKeySpec;
import org.openssl.jostle.util.Arrays;
import org.openssl.jostle.util.asn1.ASN1Encoder;
import org.openssl.jostle.util.asn1.KeyInfoCanonicalizer;

import java.math.BigInteger;

class JORSAPublicKey extends AsymmetricKeyImpl implements RSAPublicKey, OSSLKey
{
    // The NI backends that own the underlying PKEY - component reads and
    // encoding must go through the interface library that created the key
    // (NISelector for JSL, FIPSNISelector for JSLFIPS).
    private final RSAServiceNI rsaServiceNI;
    private final Asn1Ni asn1NI;

    /**
     * AlgorithmIdentifier this key's SubjectPublicKeyInfo arrived with, when it
     * differed from the one OpenSSL will emit. An id-RSASSA-PSS key is imported
     * as plain RSA (OpenSSL has no separate type for the SPKI form we accept),
     * so without this the identifier — and any PSS parameters — would be lost on
     * re-encode. Callers key off the re-encoded form: BouncyCastle's TLS layer
     * recognises an rsa_pss_pss certificate from
     * {@code SubjectPublicKeyInfo.getInstance(getPublicKey().getEncoded())}.
     * Null for keys generated here or imported under rsaEncryption. The
     * AlgorithmIdentifier only — never the whole encoding, which for the private
     * twin would mean retaining key material on the heap.
     */
    private final byte[] sourceAlgId;

    JORSAPublicKey(PKEYKeySpec spec)
    {
        this(NISelector.RSAServiceNI, NISelector.Asn1NI, spec);
    }

    JORSAPublicKey(RSAServiceNI rsaServiceNI, Asn1Ni asn1NI, PKEYKeySpec spec)
    {
        this(rsaServiceNI, asn1NI, spec, null);
    }

    JORSAPublicKey(RSAServiceNI rsaServiceNI, Asn1Ni asn1NI, PKEYKeySpec spec, byte[] sourceAlgId)
    {
        super(spec);
        this.rsaServiceNI = rsaServiceNI;
        this.asn1NI = asn1NI;
        this.sourceAlgId = Arrays.clone(sourceAlgId);
    }

    @Override
    public String getAlgorithm()
    {
        return "RSA";
    }

    @Override
    public String getFormat()
    {
        return "X.509";
    }

    @Override
    public byte[] getEncoded()
    {
        synchronized (this)
        {
            return KeyInfoCanonicalizer.withSubjectPublicKeyInfoAlgId(
                    ASN1Encoder.asSubjectPublicKeyInfo(asn1NI, spec), sourceAlgId);
        }
    }

    @Override
    public PKEYKeySpec getSpec()
    {
        return spec;
    }

    @Override
    public BigInteger getModulus()
    {
        return RSAComponents.getRequired(rsaServiceNI, spec, RSAServiceNI.COMP_MODULUS);
    }

    @Override
    public BigInteger getPublicExponent()
    {
        return RSAComponents.getRequired(rsaServiceNI, spec, RSAServiceNI.COMP_PUBLIC_EXPONENT);
    }
}
