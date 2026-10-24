/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider.rsa;

import org.openssl.jostle.util.Arrays;
import org.openssl.jostle.util.asn1.Der;
import org.openssl.jostle.util.asn1.oids.PKCSObjectIdentifiers;

import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.io.IOException;
import java.security.AlgorithmParametersSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.MGF1ParameterSpec;

/**
 * RFC 4055 {@code RSAES-OAEP-params}, encoded and decoded in house.
 *
 * <pre>
 *   RSAES-OAEP-params ::= SEQUENCE {
 *     hashAlgorithm      [0] HashAlgorithm    DEFAULT sha1Identifier,
 *     maskGenAlgorithm   [1] MaskGenAlgorithm DEFAULT mgf1SHA1Identifier,
 *     pSourceAlgorithm   [2] PSourceAlgorithm DEFAULT pSpecifiedEmptyIdentifier }
 * </pre>
 *
 * <p>Encoding omits every field at its DEFAULT; decoding accepts them present or absent, so a re-encode
 * normalises. Trailing bytes after the SEQUENCE are refused. The digest spellings are those
 * {@link RSADigestNames} accepts, and the JCA standard name is what comes back out.
 */
public class RSAOAEPAlgorithmParameters
    extends AlgorithmParametersSpi
{
    private static final int TAG_HASH = 0xA0;
    private static final int TAG_MGF = 0xA1;
    private static final int TAG_PSOURCE = 0xA2;

    private static final String DEFAULT_DIGEST = "SHA-1";

    /**
     * Whole-blob ceiling. The structure is three short AlgorithmIdentifiers plus the label, and a label is a short
     * context string; this is far above any label written into an AlgorithmIdentifier.
     */
    private static final int MAX_ENCODED_BYTES = 65536;

    private String digest;
    private String mgfDigest;
    private byte[] label;

    @Override
    protected void engineInit(AlgorithmParameterSpec paramSpec)
        throws InvalidParameterSpecException
    {
        if (!(paramSpec instanceof OAEPParameterSpec))
        {
            throw new InvalidParameterSpecException(
                    "RSAES-OAEP parameters require an OAEPParameterSpec, got "
                            + (paramSpec == null ? "null" : paramSpec.getClass().getName()));
        }
        OAEPParameterSpec oaep = (OAEPParameterSpec) paramSpec;

        String hash = RSADigestNames.canonicalDigestName(oaep.getDigestAlgorithm());
        if (hash == null)
        {
            throw new InvalidParameterSpecException("unsupported OAEP digest: " + oaep.getDigestAlgorithm());
        }
        String mgf = oaep.getMGFAlgorithm();
        if (mgf != null && !"MGF1".equalsIgnoreCase(mgf))
        {
            throw new InvalidParameterSpecException("only MGF1 is supported (got " + mgf + ")");
        }
        String mgfHash = hash;
        AlgorithmParameterSpec mgfParams = oaep.getMGFParameters();
        if (mgfParams instanceof MGF1ParameterSpec)
        {
            mgfHash = RSADigestNames.canonicalDigestName(((MGF1ParameterSpec) mgfParams).getDigestAlgorithm());
            if (mgfHash == null)
            {
                throw new InvalidParameterSpecException("unsupported MGF1 digest: "
                        + ((MGF1ParameterSpec) mgfParams).getDigestAlgorithm());
            }
        }
        else if (mgfParams != null)
        {
            throw new InvalidParameterSpecException(
                    "unsupported MGF parameters: " + mgfParams.getClass().getName());
        }
        PSource pSource = oaep.getPSource();
        byte[] value = new byte[0];
        if (pSource instanceof PSource.PSpecified)
        {
            byte[] v = ((PSource.PSpecified) pSource).getValue();
            value = v == null ? new byte[0] : v;
        }
        else if (pSource != null)
        {
            throw new InvalidParameterSpecException("unsupported PSource: " + pSource.getClass().getName());
        }

        this.digest = hash;
        this.mgfDigest = mgfHash;
        this.label = value;
    }

    @Override
    protected void engineInit(byte[] params)
        throws IOException
    {
        if (params == null)
        {
            throw new IOException("null RSAES-OAEP parameters");
        }
        if (params.length > MAX_ENCODED_BYTES)
        {
            throw new IOException("RSAES-OAEP parameters longer than "
                    + MAX_ENCODED_BYTES + " bytes (" + params.length + ")");
        }

        Der.Reader outer = new Der.Reader(params);
        Der.Reader seq = outer.readTLV(Der.SEQUENCE, "RSAES-OAEP-params SEQUENCE");
        outer.requireEnd("trailing bytes after RSAES-OAEP-params");

        String hash = DEFAULT_DIGEST;
        String mgfHash = DEFAULT_DIGEST;
        byte[] value = new byte[0];

        if (seq.peekTag() == TAG_HASH)
        {
            hash = RSADigestNames.readHashAlgorithm(seq.readTLV(TAG_HASH, "hashAlgorithm [0]"), "hashAlgorithm");
        }
        if (seq.peekTag() == TAG_MGF)
        {
            Der.Reader mgfOuter = seq.readTLV(TAG_MGF, "maskGenAlgorithm [1]");
            Der.Reader mgfAlg = mgfOuter.readTLV(Der.SEQUENCE, "MaskGenAlgorithm SEQUENCE");
            mgfOuter.requireEnd("trailing bytes in maskGenAlgorithm [1]");
            String mgfOid = mgfAlg.readObjectIdentifier("maskGenAlgorithm OID");
            if (!PKCSObjectIdentifiers.id_mgf1.getId().equals(mgfOid))
            {
                throw new IOException("only MGF1 is supported (got " + mgfOid + ")");
            }
            mgfHash = RSADigestNames.readHashAlgorithm(mgfAlg, "MGF1 hash");
        }
        if (seq.peekTag() == TAG_PSOURCE)
        {
            Der.Reader pOuter = seq.readTLV(TAG_PSOURCE, "pSourceAlgorithm [2]");
            Der.Reader pAlg = pOuter.readTLV(Der.SEQUENCE, "PSourceAlgorithm SEQUENCE");
            pOuter.requireEnd("trailing bytes in pSourceAlgorithm [2]");
            String pOid = pAlg.readObjectIdentifier("pSourceAlgorithm OID");
            if (!PKCSObjectIdentifiers.id_pSpecified.getId().equals(pOid))
            {
                throw new IOException("only pSpecified is supported (got " + pOid + ")");
            }
            value = pAlg.readTLV(Der.OCTET_STRING, "pSpecified label").remaining();
            pAlg.requireEnd("trailing bytes in PSourceAlgorithm");
        }
        seq.requireEnd("trailing bytes inside RSAES-OAEP-params");

        this.digest = hash;
        this.mgfDigest = mgfHash;
        this.label = value;
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
        throw new IOException("unsupported RSAES-OAEP parameters format: " + format);
    }

    @Override
    @SuppressWarnings("unchecked")
    protected <T extends AlgorithmParameterSpec> T engineGetParameterSpec(Class<T> paramSpec)
        throws InvalidParameterSpecException
    {
        if (digest == null)
        {
            throw new InvalidParameterSpecException("RSAES-OAEP parameters not initialised");
        }
        if (paramSpec == null)
        {
            throw new InvalidParameterSpecException("null parameter spec class");
        }
        if (paramSpec.isAssignableFrom(OAEPParameterSpec.class))
        {
            return (T) new OAEPParameterSpec(digest, "MGF1", new MGF1ParameterSpec(mgfDigest),
                    new PSource.PSpecified(Arrays.clone(label)));
        }
        throw new InvalidParameterSpecException("unsupported parameter spec: " + paramSpec.getName());
    }

    @Override
    protected byte[] engineGetEncoded()
        throws IOException
    {
        if (digest == null)
        {
            throw new IOException("RSAES-OAEP parameters not initialised");
        }
        byte[] hashPart = DEFAULT_DIGEST.equals(digest)
                ? null
                : Der.tlv(TAG_HASH, RSADigestNames.hashAlgorithmIdentifier(digest));
        byte[] mgfPart = DEFAULT_DIGEST.equals(mgfDigest)
                ? null
                : Der.tlv(TAG_MGF, Der.sequence(
                        Der.objectIdentifier(PKCSObjectIdentifiers.id_mgf1.getId()),
                        RSADigestNames.hashAlgorithmIdentifier(mgfDigest)));
        byte[] pSourcePart = label.length == 0
                ? null
                : Der.tlv(TAG_PSOURCE, Der.sequence(
                        Der.objectIdentifier(PKCSObjectIdentifiers.id_pSpecified.getId()),
                        Der.octetString(label)));
        int n = (hashPart == null ? 0 : 1) + (mgfPart == null ? 0 : 1) + (pSourcePart == null ? 0 : 1);
        byte[][] parts = new byte[n][];
        int i = 0;
        for (byte[] part : new byte[][]{hashPart, mgfPart, pSourcePart})
        {
            if (part != null)
            {
                parts[i++] = part;
            }
        }
        return Der.sequence(parts);
    }

    @Override
    protected byte[] engineGetEncoded(String format)
        throws IOException
    {
        if (format == null || "ASN.1".equalsIgnoreCase(format) || "DER".equalsIgnoreCase(format))
        {
            return engineGetEncoded();
        }
        throw new IOException("unsupported RSAES-OAEP parameters format: " + format);
    }

    @Override
    protected String engineToString()
    {
        if (digest == null)
        {
            return "RSAES-OAEP parameters (uninitialised)";
        }
        return "RSAES-OAEP[hash=" + digest + ", MGF1=" + mgfDigest + ", label=" + label.length + " bytes]";
    }
}
