/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider.blockcipher;

import org.openssl.jostle.jcajce.spec.AEADParameterSpec;
import org.openssl.jostle.util.Arrays;
import org.openssl.jostle.util.asn1.Der;

import javax.crypto.spec.IvParameterSpec;
import java.io.IOException;
import java.security.AlgorithmParametersSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

/**
 * An IV or nonce as a bare OCTET STRING — the encoding CBC, CTR and
 * ChaCha20 parameters all use.
 *
 * <p><b>Length-agnostic on purpose.</b> DESede's IV is 8 bytes and AES /
 * ARIA / CAMELLIA / SM4 use 16, while ChaCha20's nonce is 12; a codec that
 * pinned one of those would be wrong for the others. Validating the length is
 * the CIPHER's job, where the algorithm is known — this class only says how
 * the bytes go on the wire. Same division as BouncyCastle's
 * {@code IvAlgorithmParameters}.
 *
 * <p>Registered for families whose {@code getParameters()} previously resolved
 * an {@code AlgorithmParameters} from another provider — or, for ARIA,
 * CAMELLIA, SM4 and ChaCha20, found none at all and threw
 * {@code IllegalStateException}.
 */
public class IvAlgorithmParameters
    extends AlgorithmParametersSpi
{
    private byte[] iv;

    // The tag length of an AEAD mode whose parameters carry only a nonce, or 0 for a mode with no tag.
    private final int fixedTagBits;

    public IvAlgorithmParameters()
    {
        this(0);
    }

    /** For an AEAD mode whose tag length is fixed, so an AEADParameterSpec of that length means the nonce alone. */
    public IvAlgorithmParameters(int fixedTagBits)
    {
        this.fixedTagBits = fixedTagBits;
    }

    @Override
    protected void engineInit(AlgorithmParameterSpec paramSpec)
        throws InvalidParameterSpecException
    {
        // An AEADParameterSpec is an IvParameterSpec carrying a tag length these parameters do not hold: taken only
        // at the mode's fixed tag length, refused rather than dropped otherwise.
        if (paramSpec instanceof AEADParameterSpec && fixedTagBits != 0)
        {
            int tagBits = ((AEADParameterSpec) paramSpec).getMacSizeInBits();
            if (tagBits != fixedTagBits)
            {
                throw new InvalidParameterSpecException(
                        "tag length is fixed at " + fixedTagBits + " bits (got " + tagBits + ")");
            }
        }
        else if (!(paramSpec instanceof IvParameterSpec) || paramSpec instanceof AEADParameterSpec)
        {
            throw new InvalidParameterSpecException(
                    "IV parameters require an IvParameterSpec, got "
                            + (paramSpec == null ? "null" : paramSpec.getClass().getName()));
        }
        byte[] v = ((IvParameterSpec) paramSpec).getIV();
        if (v == null || v.length == 0)
        {
            throw new InvalidParameterSpecException("IV is " + (v == null ? "null" : "empty"));
        }
        this.iv = Arrays.clone(v);
    }

    @Override
    protected void engineInit(byte[] params)
        throws IOException
    {
        if (params == null)
        {
            throw new IOException("null IV parameters");
        }
        Der.Reader r = new Der.Reader(params);
        byte[] v = r.readTLV(Der.OCTET_STRING, "IV OCTET STRING").remaining();
        r.requireEnd("trailing bytes after IV");
        if (v.length == 0)
        {
            throw new IOException("IV is empty");
        }
        this.iv = v;
    }

    @Override
    protected void engineInit(byte[] params, String format)
        throws IOException
    {
        if (format == null || "ASN.1".equalsIgnoreCase(format) || "DER".equalsIgnoreCase(format))
        {
            engineInit(params);
            return;
        }
        if ("RAW".equalsIgnoreCase(format))
        {
            if (params == null || params.length == 0)
            {
                throw new IOException("IV is " + (params == null ? "null" : "empty"));
            }
            this.iv = Arrays.clone(params);
            return;
        }
        throw new IOException("unsupported IV parameters format: " + format);
    }

    @Override
    @SuppressWarnings("unchecked")
    protected <T extends AlgorithmParameterSpec> T engineGetParameterSpec(Class<T> paramSpec)
        throws InvalidParameterSpecException
    {
        requireInitialised();
        if (paramSpec == null)
        {
            throw new InvalidParameterSpecException("null parameter spec class");
        }
        if (paramSpec == AEADParameterSpec.class && fixedTagBits != 0)
        {
            return (T) new AEADParameterSpec(Arrays.clone(iv), fixedTagBits);
        }
        if (paramSpec.isAssignableFrom(IvParameterSpec.class))
        {
            return (T) new IvParameterSpec(Arrays.clone(iv));
        }
        throw new InvalidParameterSpecException("unsupported parameter spec: " + paramSpec.getName());
    }

    @Override
    protected byte[] engineGetEncoded()
        throws IOException
    {
        requireInitialisedIO();
        return Der.octetString(iv);
    }

    @Override
    protected byte[] engineGetEncoded(String format)
        throws IOException
    {
        if ("RAW".equalsIgnoreCase(format))
        {
            requireInitialisedIO();
            return Arrays.clone(iv);
        }
        if (format == null || "ASN.1".equalsIgnoreCase(format) || "DER".equalsIgnoreCase(format))
        {
            return engineGetEncoded();
        }
        throw new IOException("unsupported IV parameters format: " + format);
    }

    @Override
    protected String engineToString()
    {
        return iv == null ? "IV (uninitialised)" : "IV [" + iv.length + " bytes]";
    }

    private void requireInitialised() throws InvalidParameterSpecException
    {
        if (iv == null)
        {
            throw new InvalidParameterSpecException("IV parameters not initialised");
        }
    }

    private void requireInitialisedIO() throws IOException
    {
        if (iv == null)
        {
            throw new IOException("IV parameters not initialised");
        }
    }
}
