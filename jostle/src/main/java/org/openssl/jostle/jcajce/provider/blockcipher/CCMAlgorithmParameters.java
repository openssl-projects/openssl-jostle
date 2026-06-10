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

import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.io.IOException;
import java.security.AlgorithmParametersSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

/**
 * {@code AlgorithmParameters} for AES-CCM, registered under the bare name
 * {@code "CCM"} and the AES-CCM OIDs. Unlike GCM, no standard JDK provider
 * supplies a CCM {@code AlgorithmParameters}, so this implementation is
 * self-contained: it carries the nonce + ICV length and codes the RFC 5084
 * {@code CCMParameters} structure directly.
 *
 * <pre>
 *   CCMParameters ::= SEQUENCE {
 *       aes-nonce    OCTET STRING (SIZE(7..13)),
 *       aes-ICVlen   AES-CCM-ICVlen DEFAULT 12 }
 *   AES-CCM-ICVlen ::= INTEGER (4 | 6 | 8 | 10 | 12 | 14 | 16)   -- in bytes
 * </pre>
 *
 * <p>Per DER, the {@code aes-ICVlen} field is omitted when it equals the
 * DEFAULT (12 bytes / 96 bits) and present otherwise. The parameter spec
 * surfaced via {@link #engineGetParameterSpec} is a {@link GCMParameterSpec}
 * (tag length in bits + nonce) — the de-facto JCE AEAD parameter holder, which
 * the {@link CCMCipherSpi} already accepts.
 */
public class CCMAlgorithmParameters
    extends AlgorithmParametersSpi
{
    private static final int DEFAULT_ICV_BYTES = 12;
    private static final int MIN_NONCE_LEN = 7;
    private static final int MAX_NONCE_LEN = 13;

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
                throw new InvalidParameterSpecException("CCM tag length must be a multiple of 8 bits");
            }
            setNonceAndIcv(spec.getIV(), tagBits / 8);
        }
        else if (paramSpec instanceof IvParameterSpec)
        {
            // Nonce only — default the ICV length to the RFC 5084 DEFAULT.
            setNonceAndIcv(((IvParameterSpec) paramSpec).getIV(), DEFAULT_ICV_BYTES);
        }
        else
        {
            throw new InvalidParameterSpecException(
                    "CCM parameters require a GCMParameterSpec or IvParameterSpec, got "
                            + (paramSpec == null ? "null" : paramSpec.getClass().getName()));
        }
    }

    private void setNonceAndIcv(byte[] iv, int icv) throws InvalidParameterSpecException
    {
        if (iv == null)
        {
            throw new InvalidParameterSpecException("CCM nonce is null");
        }
        if (iv.length < MIN_NONCE_LEN || iv.length > MAX_NONCE_LEN)
        {
            throw new InvalidParameterSpecException(
                    "CCM nonce must be " + MIN_NONCE_LEN + ".." + MAX_NONCE_LEN + " bytes (got " + iv.length + ")");
        }
        if (!isValidIcvLen(icv))
        {
            throw new InvalidParameterSpecException(
                    "CCM ICV length must be 4, 6, 8, 10, 12, 14, or 16 bytes (got " + icv + ")");
        }
        this.nonce = Arrays.clone(iv);
        this.icvBytes = icv;
    }

    @Override
    protected void engineInit(byte[] params)
        throws IOException
    {
        // CCMParameters ::= SEQUENCE { OCTET STRING nonce, INTEGER icvLen DEFAULT 12 }
        if (params == null)
        {
            throw new IOException("null CCM parameters");
        }
        Reader r = new Reader(params);
        Reader seq = r.readTLV(0x30, "CCMParameters SEQUENCE");
        r.requireEnd("trailing bytes after CCMParameters");

        byte[] readNonce = seq.readTLV(0x04, "aes-nonce OCTET STRING").remaining();
        int readIcv = DEFAULT_ICV_BYTES;
        if (!seq.atEnd())
        {
            byte[] icvEnc = seq.readTLV(0x02, "aes-ICVlen INTEGER").remaining();
            readIcv = decodeIcvInteger(icvEnc);
        }
        seq.requireEnd("trailing bytes inside CCMParameters");

        if (readNonce.length < MIN_NONCE_LEN || readNonce.length > MAX_NONCE_LEN)
        {
            throw new IOException("CCM nonce out of range: " + readNonce.length);
        }
        if (!isValidIcvLen(readIcv))
        {
            throw new IOException("CCM ICV length out of range: " + readIcv);
        }
        this.nonce = readNonce;
        this.icvBytes = readIcv;
    }

    @Override
    protected void engineInit(byte[] params, String format)
        throws IOException
    {
        // RFC 5084 defines only the DER encoding; treat null/"ASN.1"/"DER" alike.
        if (format == null || "ASN.1".equalsIgnoreCase(format) || "DER".equalsIgnoreCase(format))
        {
            engineInit(params);
            return;
        }
        throw new IOException("unsupported CCM parameters format: " + format);
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
        if (paramSpec.isAssignableFrom(IvParameterSpec.class))
        {
            return (T) new IvParameterSpec(Arrays.clone(nonce));
        }
        throw new InvalidParameterSpecException("unsupported parameter spec: " + paramSpec.getName());
    }

    @Override
    protected byte[] engineGetEncoded()
        throws IOException
    {
        requireInitialisedIO();
        // Inner: OCTET STRING nonce [+ INTEGER icvLen when != DEFAULT].
        byte[] octetString = tlv(0x04, nonce);
        byte[] inner;
        if (icvBytes == DEFAULT_ICV_BYTES)
        {
            inner = octetString;
        }
        else
        {
            byte[] integer = tlv(0x02, new byte[]{(byte) icvBytes});
            inner = concat(octetString, integer);
        }
        return tlv(0x30, inner);
    }

    @Override
    protected byte[] engineGetEncoded(String format)
        throws IOException
    {
        if (format == null || "ASN.1".equalsIgnoreCase(format) || "DER".equalsIgnoreCase(format))
        {
            return engineGetEncoded();
        }
        throw new IOException("unsupported CCM parameters format: " + format);
    }

    @Override
    protected String engineToString()
    {
        if (nonce == null)
        {
            return "CCMParameters (uninitialised)";
        }
        return "CCMParameters [nonce=" + nonce.length + " bytes, icv=" + icvBytes + " bytes]";
    }

    private void requireInitialised() throws InvalidParameterSpecException
    {
        if (nonce == null)
        {
            throw new InvalidParameterSpecException("CCM parameters not initialised");
        }
    }

    private void requireInitialisedIO() throws IOException
    {
        if (nonce == null)
        {
            throw new IOException("CCM parameters not initialised");
        }
    }

    private static boolean isValidIcvLen(int icvBytes)
    {
        return icvBytes == 4 || icvBytes == 6 || icvBytes == 8 || icvBytes == 10
                || icvBytes == 12 || icvBytes == 14 || icvBytes == 16;
    }

    /**
     * Decode a minimally-encoded non-negative DER INTEGER (the ICV length is a
     * small positive value, so it is one content byte with the top bit clear).
     */
    private static int decodeIcvInteger(byte[] content) throws IOException
    {
        if (content.length != 1 || (content[0] & 0x80) != 0)
        {
            throw new IOException("malformed CCM ICV length INTEGER");
        }
        return content[0] & 0xFF;
    }

    /** Encode a TLV with a single-byte definite length (content < 128 bytes). */
    private static byte[] tlv(int tag, byte[] content)
    {
        // Every CCMParameters field is well under 128 bytes, so the length is a
        // single octet — this codec deliberately does not handle longer forms.
        byte[] out = new byte[2 + content.length];
        out[0] = (byte) tag;
        out[1] = (byte) content.length;
        System.arraycopy(content, 0, out, 2, content.length);
        return out;
    }

    private static byte[] concat(byte[] a, byte[] b)
    {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    /**
     * Minimal DER reader for the short-form (length &lt; 128) TLVs used by
     * CCMParameters. Rejects long-form lengths and truncation.
     */
    private static final class Reader
    {
        private final byte[] buf;
        private int pos;
        private final int end;

        Reader(byte[] buf)
        {
            this(buf, 0, buf.length);
        }

        Reader(byte[] buf, int off, int len)
        {
            this.buf = buf;
            this.pos = off;
            this.end = off + len;
        }

        boolean atEnd()
        {
            return pos >= end;
        }

        void requireEnd(String message) throws IOException
        {
            if (pos != end)
            {
                throw new IOException(message);
            }
        }

        /** Read one TLV of the expected tag and return a Reader over its content. */
        Reader readTLV(int expectedTag, String what) throws IOException
        {
            if (end - pos < 2)
            {
                throw new IOException("truncated " + what);
            }
            int tag = buf[pos++] & 0xFF;
            if (tag != expectedTag)
            {
                throw new IOException("expected " + what + " (tag 0x"
                        + Integer.toHexString(expectedTag) + "), got tag 0x" + Integer.toHexString(tag));
            }
            int len = buf[pos++] & 0xFF;
            if ((len & 0x80) != 0)
            {
                throw new IOException("unsupported long-form length in " + what);
            }
            if (len > end - pos)
            {
                throw new IOException("truncated content in " + what);
            }
            Reader content = new Reader(buf, pos, len);
            pos += len;
            return content;
        }

        /** The remaining (content) bytes of this reader as a fresh array. */
        byte[] remaining()
        {
            byte[] out = new byte[end - pos];
            System.arraycopy(buf, pos, out, 0, out.length);
            pos = end;
            return out;
        }
    }
}
