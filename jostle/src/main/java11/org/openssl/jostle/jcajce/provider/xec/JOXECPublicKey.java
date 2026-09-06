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

import java.lang.ref.Reference;
import java.math.BigInteger;
import java.security.PublicKey;
import java.security.interfaces.XECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.NamedParameterSpec;

/**
 * Java 11+ override. Carries BOTH reasons, and neither may be dropped as
 * redundant:
 *
 * <ol>
 *   <li>the {@link Reference#reachabilityFence} form inherited from the
 *       {@code java9} copy, which keeps this key reachable across the native
 *       encoding call in place of the baseline's {@code synchronized(this)};
 *       and</li>
 *   <li>{@link XECPublicKey}, the JDK-standard interface, which exists from
 *       Java 11 and which the {@code java9} copy therefore could not
 *       implement.</li>
 * </ol>
 *
 * <p>The {@code java9} copy stays: it serves JDK 9 and 10, where (2) is
 * impossible. Removing the fence here to "avoid duplication" would silently
 * reintroduce the use-after-free the {@code java9} copy exists to prevent.
 *
 * <p>X25519 / X448 public key. The concrete algorithm ("X25519" / "X448")
 * comes from the key's {@link org.openssl.jostle.jcajce.spec.OSSLKeyType};
 * the encoding is the generic X.509 SubjectPublicKeyInfo produced by OpenSSL
 * (no curve parameters for Montgomery keys).
 */
class JOXECPublicKey extends AsymmetricKeyImpl implements PublicKey, XDHKey, OSSLKey, XECPublicKey
{
    // The NI backend that encodes the underlying PKEY (NISelector for JSL,
    // FIPSNISelector for JSLFIPS).
    private final Asn1Ni asn1NI;

    JOXECPublicKey(PKEYKeySpec spec)
    {
        this(NISelector.Asn1NI, spec);
    }

    JOXECPublicKey(Asn1Ni asn1NI, PKEYKeySpec spec)
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
        return "X.509";
    }

    @Override
    public byte[] getEncoded()
    {
        try
        {
            return ASN1Encoder.asSubjectPublicKeyInfo(asn1NI, spec);
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
     * The u-coordinate, per {@link XECPublicKey}.
     *
     * <p>Read from the SPKI this key produces: RFC 8410 section 4 puts the raw
     * public key directly in the BIT STRING with no algorithm parameters, so
     * the layout is fixed and {@code XECMontgomery} asserts the prefix rather
     * than parsing. RFC 7748 section 5's little-endian rule and its
     * X25519-only masking rule are applied there.
     */
    @Override
    public BigInteger getU()
    {
        try
        {
            byte[] raw = XECMontgomery.rawFromSpki(
                    spec.getType(), ASN1Encoder.asSubjectPublicKeyInfo(asn1NI, spec));
            return XECMontgomery.uFromLittleEndian(spec.getType(), raw);
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
