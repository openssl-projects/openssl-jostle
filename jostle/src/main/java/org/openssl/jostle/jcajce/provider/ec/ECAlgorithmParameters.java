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

package org.openssl.jostle.jcajce.provider.ec;

import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.util.asn1.Der;

import java.io.IOException;
import java.security.AlgorithmParametersSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.InvalidParameterSpecException;

/**
 * {@code AlgorithmParameters} for EC. Lets callers resolve EC domain
 * parameters from this provider by name ({@code "EC"}) or by the
 * id-ecPublicKey OID — notably BouncyCastle's TLS layer, whose
 * {@code JceTlsECDomain} obtains curve parameters via
 * {@code helper.createAlgorithmParameters("EC")} on the JSL-bound helper
 * before any NIST-curve TLS group can be negotiated.
 *
 * <p>Curve parameters come from OpenSSL's builtin table via
 * {@link ECComponents}, and the ASN.1 from {@link Der}.
 *
 * <p><b>Wire form.</b> {@code ECParameters} is a CHOICE and this provider
 * emits, and accepts, only the {@code namedCurve} arm: a bare OBJECT
 * IDENTIFIER. That is byte-for-byte what SunEC produces, and SunEC likewise
 * refuses an explicit-parameters SEQUENCE with {@code IOException}.
 *
 * <p><b>Not gated on curve capability, deliberately.</b> Describing a curve is
 * not an operation on it, so this class answers for any curve the loaded build
 * knows even when the provider would refuse to generate a key on it. Under
 * JSLFIPS that difference is observable and pinned by test — see
 * {@link ECComponents#curveNameForEncoding}.
 */
public class ECAlgorithmParameters
    extends AlgorithmParametersSpi
{
    private final ECServiceNI ecServiceNI;

    /** The OpenSSL canonical curve name, or null until initialised. */
    private String curveName;

    public ECAlgorithmParameters()
    {
        this(NISelector.ECServiceNI);
    }

    public ECAlgorithmParameters(ECServiceNI ecServiceNI)
    {
        this.ecServiceNI = ecServiceNI;
    }

    @Override
    protected void engineInit(AlgorithmParameterSpec paramSpec)
        throws InvalidParameterSpecException
    {
        if (paramSpec instanceof ECGenParameterSpec)
        {
            String requested = ((ECGenParameterSpec) paramSpec).getName();
            String resolved = ECComponents.canonicalCurveName(ecServiceNI, requested);
            if (resolved == null)
            {
                throw new InvalidParameterSpecException("unsupported EC curve: " + requested);
            }
            curveName = resolved;
            return;
        }
        if (paramSpec instanceof ECParameterSpec)
        {
            String resolved = ECComponents.curveNameForEncoding(
                    ecServiceNI, (ECParameterSpec) paramSpec);
            if (resolved == null)
            {
                throw new InvalidParameterSpecException(
                        "explicit EC parameters match no named curve known to the "
                                + "loaded OpenSSL build");
            }
            curveName = resolved;
            return;
        }
        throw new InvalidParameterSpecException(
                "expected ECGenParameterSpec or ECParameterSpec (got "
                        + (paramSpec == null ? "null" : paramSpec.getClass().getName()) + ")");
    }

    @Override
    protected void engineInit(byte[] params)
        throws IOException
    {
        if (params == null)
        {
            throw new IOException("encoded parameters are null");
        }
        Der.Reader reader = new Der.Reader(params);
        String oid = reader.readObjectIdentifier("EC parameters");
        reader.requireEnd("trailing data after EC parameters");

        String resolved = ECComponents.canonicalCurveName(ecServiceNI, oid);
        if (resolved == null)
        {
            throw new IOException("unknown EC named curve: " + oid);
        }
        curveName = resolved;
    }

    @Override
    protected void engineInit(byte[] params, String format)
        throws IOException
    {
        // SunEC accepts "ASN.1" and null and treats both as the only format it
        // has. Anything else is a caller error rather than a decode failure.
        if (format != null && !"ASN.1".equalsIgnoreCase(format))
        {
            throw new IOException("unsupported EC parameter format: " + format);
        }
        engineInit(params);
    }

    @Override
    protected <T extends AlgorithmParameterSpec> T engineGetParameterSpec(Class<T> paramSpec)
        throws InvalidParameterSpecException
    {
        requireInitialised();
        if (paramSpec == null)
        {
            throw new InvalidParameterSpecException("requested spec class is null");
        }
        if (paramSpec.isAssignableFrom(ECParameterSpec.class))
        {
            return paramSpec.cast(ECComponents.resolveParams(ecServiceNI, curveName));
        }
        if (paramSpec.isAssignableFrom(ECGenParameterSpec.class))
        {
            // The SECG spelling where one exists, matching what the platform
            // provider answers for the same curve.
            return paramSpec.cast(
                    new ECGenParameterSpec(ECComponents.jceSpellingOf(curveName)));
        }
        throw new InvalidParameterSpecException(
                "unsupported parameter spec: " + paramSpec.getName());
    }

    @Override
    protected byte[] engineGetEncoded()
        throws IOException
    {
        if (curveName == null)
        {
            throw new IOException("EC parameters are not initialised");
        }
        String oid = ECComponents.curveOid(ecServiceNI, curveName);
        if (oid == null)
        {
            // Oakley-EC2N-3 and -4 carry no OID, so there is no namedCurve
            // arm to emit for them. Fail naming the curve rather than
            // producing something that is not an ECParameters encoding.
            throw new IOException("curve " + curveName + " has no object identifier "
                    + "and cannot be encoded as a named curve");
        }
        return Der.objectIdentifier(oid);
    }

    @Override
    protected byte[] engineGetEncoded(String format)
        throws IOException
    {
        if (format != null && !"ASN.1".equalsIgnoreCase(format))
        {
            throw new IOException("unsupported EC parameter format: " + format);
        }
        return engineGetEncoded();
    }

    @Override
    protected String engineToString()
    {
        return curveName == null ? "EC parameters (not initialised)" : curveName;
    }

    private void requireInitialised() throws InvalidParameterSpecException
    {
        if (curveName == null)
        {
            throw new InvalidParameterSpecException("EC parameters are not initialised");
        }
    }
}
