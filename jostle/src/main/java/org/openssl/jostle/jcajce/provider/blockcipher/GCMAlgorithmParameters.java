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

import org.openssl.jostle.util.Arrays;
import org.openssl.jostle.util.asn1.Der;

import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.io.IOException;
import java.security.AlgorithmParametersSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

/**
 * RFC 5084 {@code GCMParameters} — nonce plus an optional ICV length —
 * encoded and decoded in house.
 *
 * <pre>
 *   GCMParameters ::= SEQUENCE {
 *     aes-nonce   OCTET STRING,
 *     aes-ICVlen  AES-GCM-ICVlen DEFAULT 12 }
 * </pre>
 *
 * <p>The SPI's state IS the parsed parameters, so nothing here resolves an
 * {@code AlgorithmParameters} from another provider. That matters beyond
 * tidiness: this SPI is registered under the bare name {@code "GCM"}, and the
 * delegating version had to walk the installed providers skipping Jostle by
 * package prefix or {@code getInstance("GCM")} recursed into itself. No
 * delegate, no recursion hazard, no guard.
 *
 * <p>ICV length is 12..16 per RFC 5084, and 12 is DEFAULT so it is OMITTED on
 * encode and assumed on decode — SunJCE and BouncyCastle both do exactly this,
 * measured, so the boundary is wire-compatible with either. Note this is
 * NARROWER than what Jostle's own GCM cipher accepts (4..16 bytes, measured):
 * SP 800-38D permits the shorter tags, RFC 5084's structure cannot express
 * them, and the delegate could not either.
 *
 * @see org.openssl.jostle.jcajce.provider.blockcipher.CCMAlgorithmParameters
 */
public class GCMAlgorithmParameters
    extends AlgorithmParametersSpi
{
    private static final int DEFAULT_ICV_BYTES = 12;
    private static final int MIN_ICV_BYTES = 12;
    private static final int MAX_ICV_BYTES = 16;

    private byte[] nonce;
    private int icvBytes;

    @Override
    protected void engineInit(AlgorithmParameterSpec paramSpec)
        throws InvalidParameterSpecException
    {
        if (paramSpec instanceof GCMParameterSpec)
        {
            GCMParameterSpec spec = (GCMParameterSpec) paramSpec;
            int tagBits = spec.getTLen();
            if ((tagBits & 7) != 0)
            {
                throw new InvalidParameterSpecException("GCM tag length must be a multiple of 8 bits");
            }
            setNonceAndIcv(spec.getIV(), tagBits / 8);
        }
        else
        {
            // IvParameterSpec is refused on the way IN as well as OUT, matching
            // SunJCE (measured: "Inappropriate parameter specification").
            // Accepting it would silently apply the DEFAULT 12-byte ICV to a
            // caller who never chose a tag length — the quiet-divergence twin
            // of the read-back bug that dropped one. CCM differs deliberately:
            // it accepts a nonce-only spec for BouncyCastle parity.
            throw new InvalidParameterSpecException(
                    "GCM parameters require a GCMParameterSpec, got "
                            + (paramSpec == null ? "null" : paramSpec.getClass().getName()));
        }
    }

    private void setNonceAndIcv(byte[] iv, int icv) throws InvalidParameterSpecException
    {
        if (iv == null)
        {
            throw new InvalidParameterSpecException("GCM nonce is null");
        }
        if (iv.length == 0)
        {
            throw new InvalidParameterSpecException("GCM nonce is empty");
        }
        if (icv < MIN_ICV_BYTES || icv > MAX_ICV_BYTES)
        {
            throw new InvalidParameterSpecException(
                    "GCM ICV length must be " + MIN_ICV_BYTES + ".." + MAX_ICV_BYTES
                            + " bytes (got " + icv + ")");
        }
        this.nonce = Arrays.clone(iv);
        this.icvBytes = icv;
    }

    @Override
    protected void engineInit(byte[] params)
        throws IOException
    {
        if (params == null)
        {
            throw new IOException("null GCM parameters");
        }
        Der.Reader r = new Der.Reader(params);
        Der.Reader seq = r.readTLV(Der.SEQUENCE, "GCMParameters SEQUENCE");
        r.requireEnd("trailing bytes after GCMParameters");

        byte[] readNonce = seq.readTLV(Der.OCTET_STRING, "aes-nonce OCTET STRING").remaining();
        int readIcv = DEFAULT_ICV_BYTES;
        if (!seq.atEnd())
        {
            readIcv = seq.readSmallInteger("aes-ICVlen INTEGER");
        }
        seq.requireEnd("trailing bytes inside GCMParameters");

        if (readNonce.length == 0)
        {
            throw new IOException("GCM nonce is empty");
        }
        if (readIcv < MIN_ICV_BYTES || readIcv > MAX_ICV_BYTES)
        {
            throw new IOException("GCM ICV length out of range: " + readIcv);
        }
        this.nonce = readNonce;
        this.icvBytes = readIcv;
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
        throw new IOException("unsupported GCM parameters format: " + format);
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
        if (paramSpec.isAssignableFrom(GCMParameterSpec.class))
        {
            return (T) new GCMParameterSpec(icvBytes * 8, Arrays.clone(nonce));
        }
        // IvParameterSpec is deliberately NOT served, matching SunJCE.
        // BlockCipherSpi.availableSpecs asks for IvParameterSpec FIRST, so
        // serving it here would satisfy that probe and silently discard the
        // tag length — a 96-bit tag would decrypt as 128 and fail as a bad
        // tag. Measured: ARIAAgreementTest.ariaGCM_decryptFromAlgorithmParameters_cmsPattern
        // fails exactly that way when this arm is present.
        throw new InvalidParameterSpecException("unsupported parameter spec: " + paramSpec.getName());
    }

    @Override
    protected byte[] engineGetEncoded()
        throws IOException
    {
        requireInitialisedIO();
        if (icvBytes == DEFAULT_ICV_BYTES)
        {
            return Der.sequence(Der.octetString(nonce));
        }
        return Der.sequence(Der.octetString(nonce), Der.integer(icvBytes));
    }

    @Override
    protected byte[] engineGetEncoded(String format)
        throws IOException
    {
        if (format == null || "ASN.1".equalsIgnoreCase(format) || "DER".equalsIgnoreCase(format))
        {
            return engineGetEncoded();
        }
        throw new IOException("unsupported GCM parameters format: " + format);
    }

    @Override
    protected String engineToString()
    {
        if (nonce == null)
        {
            return "GCMParameters (uninitialised)";
        }
        return "GCMParameters [nonce=" + nonce.length + " bytes, icv=" + icvBytes + " bytes]";
    }

    private void requireInitialised() throws InvalidParameterSpecException
    {
        if (nonce == null)
        {
            throw new InvalidParameterSpecException("GCM parameters not initialised");
        }
    }

    private void requireInitialisedIO() throws IOException
    {
        if (nonce == null)
        {
            throw new IOException("GCM parameters not initialised");
        }
    }
}
