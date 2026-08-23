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

package org.openssl.jostle.jcajce.provider.ed;

import org.openssl.jostle.jcajce.interfaces.EdDSAPrivateKey;
import org.openssl.jostle.jcajce.interfaces.EdDSAPublicKey;
import org.openssl.jostle.jcajce.interfaces.OSSLKey;
import org.openssl.jostle.jcajce.provider.AsymmetricKeyImpl;
import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.jcajce.spec.EdDSAParameterSpec;
import org.openssl.jostle.jcajce.spec.PKEYKeySpec;
import org.openssl.jostle.util.asn1.ASN1Encoder;
import org.openssl.jostle.util.asn1.Asn1Ni;
import org.openssl.jostle.util.asn1.PrivateKeyOptions;

public class JOEdPrivateKey extends AsymmetricKeyImpl implements EdDSAPrivateKey, OSSLKey
{
    // Instance fields, not NISelector statics (NISelector for JSL,
    // FIPSNISelector for JSLFIPS): the key's native handle belongs to the
    // interface library that created it, so the NIs that read it must be the
    // same ones.
    private final EDServiceNI edServiceNI;
    private final Asn1Ni asn1NI;

    public JOEdPrivateKey(PKEYKeySpec spec)
    {
        this(NISelector.EDServiceNI, NISelector.Asn1NI, spec);
    }

    public JOEdPrivateKey(EDServiceNI edServiceNI, Asn1Ni asn1NI, PKEYKeySpec spec)
    {
        super(spec);
        this.edServiceNI = edServiceNI;
        this.asn1NI = asn1NI;
    }


    @Override
    public EdDSAPublicKey getPublicKey()
    {
        return new JOEdPublicKey(edServiceNI, asn1NI, spec);
    }

    @Override
    public String getAlgorithm()
    {
        // Canonical JCA name ("Ed25519"/"Ed448", mixed case) — matches SunEC/BC.
        return getType().getTypeName();
    }

    @Override
    public String getFormat()
    {
        return "PKCS#8";
    }

    @Override
    public byte[] getEncoded()
    {
        synchronized (this)
        {
            return ASN1Encoder.asPrivateKeyInfo(asn1NI, spec, PrivateKeyOptions.DEFAULT);
        }
    }

    @Override
    public PKEYKeySpec getSpec()
    {
        return spec;
    }

    /**
     * Raw RFC 8032 private scalar bytes (32 for Ed25519, 57 for Ed448) read
     * from the underlying EVP_PKEY. Synchronized to keep the native ref alive.
     */
    public byte[] getRawScalar()
    {
        synchronized (this)
        {
            int len = edServiceNI.getPrivateKey(spec.getReference(), null);
            byte[] raw = new byte[len];
            edServiceNI.getPrivateKey(spec.getReference(), raw);
            return raw;
        }
    }

    /**
     * Raw RFC 8032 public-key bytes corresponding to this private key, read
     * from the underlying EVP_PKEY. Synchronized to keep the native ref alive.
     */
    public byte[] getRawPublic()
    {
        synchronized (this)
        {
            int len = edServiceNI.getPublicKey(spec.getReference(), null);
            byte[] raw = new byte[len];
            edServiceNI.getPublicKey(spec.getReference(), raw);
            return raw;
        }
    }

    public EdDSAParameterSpec getParameterSpec()
    {
        switch (spec.getType())
        {
            case ED448:
                return EdDSAParameterSpec.ED448;
            case ED25519:
                return EdDSAParameterSpec.ED25519;
            default:
                throw new IllegalArgumentException("unknown parameter type: " + spec.getType().name());

        }
    }

}
