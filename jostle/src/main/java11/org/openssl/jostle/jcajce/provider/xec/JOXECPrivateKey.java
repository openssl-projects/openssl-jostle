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

package org.openssl.jostle.jcajce.provider.xec;

import org.openssl.jostle.jcajce.interfaces.OSSLKey;
import org.openssl.jostle.jcajce.interfaces.XDHKey;
import org.openssl.jostle.jcajce.provider.AsymmetricKeyImpl;
import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.jcajce.spec.PKEYKeySpec;
import org.openssl.jostle.util.asn1.ASN1Encoder;
import org.openssl.jostle.util.asn1.Asn1Ni;
import org.openssl.jostle.util.asn1.PrivateKeyOptions;

import java.lang.ref.Reference;
import java.security.interfaces.XECPrivateKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.NamedParameterSpec;
import java.util.Optional;
import java.security.PrivateKey;

/**
 * Java 11+ override, carrying BOTH the {@code java9} copy's
 * {@link Reference#reachabilityFence} form AND {@link XECPrivateKey}, the
 * JDK-standard interface available only from Java 11. The {@code java9} copy
 * stays for JDK 9 and 10; dropping the fence here would reintroduce the
 * use-after-free it exists to prevent.
 *
 * <p>Original note: Java 9+ override of the Java 8 baseline. Uses
 * {@link Reference#reachabilityFence} to keep this key reachable across the
 * native encoding call, replacing the {@code synchronized(this)} idiom in
 * the baseline. The public surface is identical to the baseline copy.
 *
 * <p>X25519 / X448 private key. Encodes as PKCS#8 PrivateKeyInfo via the
 * generic {@link ASN1Encoder}; the concrete algorithm comes from the key's
 * {@link org.openssl.jostle.jcajce.spec.OSSLKeyType}.
 */
class JOXECPrivateKey extends AsymmetricKeyImpl implements PrivateKey, XDHKey, OSSLKey, XECPrivateKey
{
    // The NI backend that encodes the underlying PKEY (NISelector for JSL,
    // FIPSNISelector for JSLFIPS).
    private final Asn1Ni asn1NI;

    JOXECPrivateKey(PKEYKeySpec spec)
    {
        this(NISelector.Asn1NI, spec);
    }

    JOXECPrivateKey(Asn1Ni asn1NI, PKEYKeySpec spec)
    {
        super(spec);
        this.asn1NI = asn1NI;
    }

    @Override
    public String getAlgorithm()
    {
        return spec.getType().getAlgorithmName();
    }

    @Override
    public String getFormat()
    {
        return "PKCS#8";
    }

    @Override
    public byte[] getEncoded()
    {
        try
        {
            return ASN1Encoder.asPrivateKeyInfo(asn1NI, spec, PrivateKeyOptions.DEFAULT);
        }
        finally
        {
            Reference.reachabilityFence(this);
        }
    }

    @Override
    public PKEYKeySpec getSpec()
    {
        return spec;
    }

    /**
     * The private scalar, per {@link XECPrivateKey}.
     *
     * <p>Read from the PKCS#8 this key produces: RFC 8410 section 7 defines
     * {@code CurvePrivateKey ::= OCTET STRING} nested inside the
     * PrivateKeyInfo's {@code privateKey}, a fixed layout with no parameters,
     * so {@code XECMontgomery} asserts the prefix rather than parsing.
     *
     * <p>Returns {@link Optional#of} a fresh array; the caller owns it and may
     * scrub it. An empty Optional is reserved by the interface for a key whose
     * scalar is not available, which cannot happen here — this key always
     * holds one.
     */
    @Override
    public Optional<byte[]> getScalar()
    {
        try
        {
            return Optional.of(XECMontgomery.rawFromPkcs8(
                    spec.getType(),
                    ASN1Encoder.asPrivateKeyInfo(asn1NI, spec, PrivateKeyOptions.DEFAULT)));
        }
        finally
        {
            Reference.reachabilityFence(this);
        }
    }

    /** {@inheritDoc} — a {@link NamedParameterSpec} for this key's type. */
    @Override
    public AlgorithmParameterSpec getParams()
    {
        return XECMontgomery.isX448(spec.getType())
                ? NamedParameterSpec.X448 : NamedParameterSpec.X25519;
    }
}
