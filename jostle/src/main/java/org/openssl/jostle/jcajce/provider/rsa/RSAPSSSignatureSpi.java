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

import org.openssl.jostle.rand.RandSource;

import java.security.InvalidAlgorithmParameterException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

/**
 * RSA Signature SPI for RSASSA-PSS.
 *
 * <p>Defaulting policy when {@code PSSParameterSpec} is unset or
 * partially specified — locked in by the v1 design decision:
 * <ul>
 *   <li>Digest: SHA-256 (modern safe default; the JDK default is
 *       SHA-1 which we deliberately don't follow).</li>
 *   <li>MGF: MGF1 with the same hash as the signing digest. Other
 *       providers historically default to MGF1-SHA-1; we chose to
 *       match the signing hash because it's the modern best practice
 *       and avoids surprising callers who specify a strong hash and
 *       expect the MGF to follow.</li>
 *   <li>Salt length: digest output length (passed as the native
 *       sentinel {@code -1} which maps to {@code RSA_PSS_SALTLEN_DIGEST}).</li>
 *   <li>Trailer field: 1 (the only value the JCE / PKCS#1 v2.2 spec
 *       allows).</li>
 * </ul>
 */
public class RSAPSSSignatureSpi extends RSASignatureSpiBase
{
    /** Default digest used when no PSSParameterSpec is supplied. */
    private static final String DEFAULT_DIGEST = "SHA-256";

    private String digestName = DEFAULT_DIGEST;
    private String mgf1Digest = DEFAULT_DIGEST;
    /** Negative is the "use digest output length" sentinel. */
    private int saltLen = -1;


    public RSAPSSSignatureSpi() {}

    /**
     * Per-digest constructor for the named {@code SHAxxxWITHRSAANDMGF1} /
     * {@code SHAxxxWITHRSASSA-PSS} convenience algorithms, where the digest is
     * implied by the algorithm name. Defaults MGF1 to the same hash and the
     * salt length to the digest output length, matching PKCS#1 v2.2 practice.
     * If the caller subsequently supplies a {@link PSSParameterSpec} (as the
     * PKIX layer does for non-default parameters) it overrides these.
     */
    public RSAPSSSignatureSpi(String digest)
    {
        this.digestName = digest;
        this.mgf1Digest = digest;
        this.saltLen = -1;
    }

    @Override
    protected void engineSetParameter(AlgorithmParameterSpec params) throws InvalidAlgorithmParameterException
    {
        if (params == null)
        {
            // Reset to defaults.
            this.digestName = DEFAULT_DIGEST;
            this.mgf1Digest = DEFAULT_DIGEST;
            this.saltLen = -1;
            return;
        }

        if (!(params instanceof PSSParameterSpec))
        {
            throw new InvalidAlgorithmParameterException("expected PSSParameterSpec");
        }

        PSSParameterSpec pss = (PSSParameterSpec) params;

        // Digest — translate JDK alg names to OpenSSL EVP_MD names
        // (the two are nearly identical but JDK uses "SHA-256" while
        // OpenSSL's EVP_get_digestbyname is also happy with that;
        // accept both forms).
        String digest = pss.getDigestAlgorithm();
        if (digest == null || digest.isEmpty())
        {
            throw new InvalidAlgorithmParameterException("PSSParameterSpec missing digest");
        }

        // MGF — only MGF1 is supported by RSASSA-PSS / RFC 8017.
        String mgf = pss.getMGFAlgorithm();
        if (mgf != null && !"MGF1".equalsIgnoreCase(mgf))
        {
            throw new InvalidAlgorithmParameterException(
                    "only MGF1 is supported (got " + mgf + ")");
        }

        // MGF1 hash — default to the signing hash if the parameters
        // didn't specify one. PSSParameterSpec returns a non-null
        // MGF1ParameterSpec by default (initialised to SHA-1) so the
        // "default to signing hash" policy applies when the caller
        // either passes null mgfParams or explicitly omits them.
        AlgorithmParameterSpec mgfParams = pss.getMGFParameters();
        String mgfHash;
        if (mgfParams == null)
        {
            mgfHash = digest;
        }
        else if (mgfParams instanceof MGF1ParameterSpec)
        {
            String h = ((MGF1ParameterSpec) mgfParams).getDigestAlgorithm();
            mgfHash = (h == null || h.isEmpty()) ? digest : h;
        }
        else
        {
            throw new InvalidAlgorithmParameterException(
                    "unsupported MGF parameters: " + mgfParams.getClass().getName());
        }

        int salt = pss.getSaltLength();
        // Trailer field — RSASSA-PSS only defines value 1; reject anything
        // else explicitly (PSSParameterSpec.getTrailerField() can return
        // arbitrary ints if hand-constructed).
        int trailer = pss.getTrailerField();
        if (trailer != 1)
        {
            throw new InvalidAlgorithmParameterException(
                    "trailer field must be 1 (got " + trailer + ")");
        }

        this.digestName = digest;
        this.mgf1Digest = mgfHash;
        this.saltLen = salt;
    }

    @Override
    protected void nativeInitSign(long ref, long keyRef, RandSource rnd)
    {
        rsaServiceNI.initSign(ref, keyRef,
                digestName,
                RSAServiceNI.PADDING_PSS,
                mgf1Digest,
                saltLen,
                rnd);
    }

    @Override
    protected void nativeInitVerify(long ref, long keyRef)
    {
        rsaServiceNI.initVerify(ref, keyRef,
                digestName,
                RSAServiceNI.PADDING_PSS,
                mgf1Digest,
                saltLen);
    }
}
