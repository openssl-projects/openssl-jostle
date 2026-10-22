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

import org.openssl.jostle.jcajce.interfaces.RSAKey;
import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.jcajce.provider.md.MDServiceNI;
import org.openssl.jostle.rand.RandSource;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.ProviderException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
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

    /** Negative is the "use digest output length" sentinel. */
    private static final int DIGEST_LENGTH_SALT = -1;

    // What setParameter(null) restores: the name's parameters for a named instance.
    private final String defaultDigest;
    private final String defaultMgf1Digest;
    private final int defaultSaltLen;

    private String digestName;
    private String mgf1Digest;
    private int saltLen;


    /** Resolves the salt length the native sentinel stands for. May be null. */
    private final MDServiceNI mdServiceNI;

    public RSAPSSSignatureSpi()
    {
        this(NISelector.MDServiceNI, DEFAULT_DIGEST);
    }

    private RSAPSSSignatureSpi(MDServiceNI mdServiceNI, String digest)
    {
        this.mdServiceNI = mdServiceNI;
        this.defaultDigest = digest;
        this.defaultMgf1Digest = digest;
        this.defaultSaltLen = DIGEST_LENGTH_SALT;
        resetToDefaults();
    }

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
        this(NISelector.MDServiceNI, digest);
    }

    //
    // NI-binding constructors for the FIPS provider: identical behaviour,
    // bound to the FIPS interface library's RSAServiceNI.
    //
    public RSAPSSSignatureSpi(RSAServiceNI rsaServiceNI, MDServiceNI mdServiceNI,
                              RSAKeyFactorySpi keyFactory)
    {
        this(rsaServiceNI, mdServiceNI, keyFactory, DEFAULT_DIGEST);
    }

    public RSAPSSSignatureSpi(RSAServiceNI rsaServiceNI, MDServiceNI mdServiceNI,
                              RSAKeyFactorySpi keyFactory, String digest)
    {
        super(rsaServiceNI, keyFactory);
        this.mdServiceNI = mdServiceNI;
        this.defaultDigest = digest;
        this.defaultMgf1Digest = digest;
        this.defaultSaltLen = DIGEST_LENGTH_SALT;
        resetToDefaults();
    }

    private void resetToDefaults()
    {
        this.digestName = defaultDigest;
        this.mgf1Digest = defaultMgf1Digest;
        this.saltLen = defaultSaltLen;
    }

    @Override
    protected void engineSetParameter(AlgorithmParameterSpec params) throws InvalidAlgorithmParameterException
    {
        if (updateStarted)
        {
            // JCE state-machine contract: PSS parameters must be fixed before the
            // first update() of a sign/verify cycle — changing them mid-stream
            // would sign/verify under parameters the update data never saw.
            // Matches EdSignatureSpi's guard.
            throw new ProviderException("cannot call setParameter in the middle of update");
        }
        String digest;
        String mgfHash;
        int salt;
        if (params == null)
        {
            // A named instance's defaults are its name's parameters.
            digest = defaultDigest;
            mgfHash = defaultMgf1Digest;
            salt = defaultSaltLen;
        }
        else
        {
            if (!(params instanceof PSSParameterSpec))
            {
                throw new InvalidAlgorithmParameterException("expected PSSParameterSpec");
            }
            PSSParameterSpec pss = (PSSParameterSpec) params;

            String requested = pss.getDigestAlgorithm();
            if (requested == null || requested.isEmpty())
            {
                throw new InvalidAlgorithmParameterException("PSSParameterSpec missing digest");
            }
            // JDK and BouncyCastle spellings in, the canonical name out; a known digest other than
            // the name's is accepted, an unknown spelling is not.
            digest = RSAPSSAlgorithmParameters.canonicalDigestName(requested);
            if (digest == null)
            {
                throw new InvalidAlgorithmParameterException("unsupported PSS digest: " + requested);
            }

            // MGF - only MGF1 is supported by RSASSA-PSS / RFC 8017.
            String mgf = pss.getMGFAlgorithm();
            if (mgf != null && !"MGF1".equalsIgnoreCase(mgf))
            {
                throw new InvalidAlgorithmParameterException(
                        "only MGF1 is supported (got " + mgf + ")");
            }

            // MGF1 hash: the signing hash when the parameters name none.
            AlgorithmParameterSpec mgfParams = pss.getMGFParameters();
            if (mgfParams == null)
            {
                mgfHash = digest;
            }
            else if (mgfParams instanceof MGF1ParameterSpec)
            {
                String h = ((MGF1ParameterSpec) mgfParams).getDigestAlgorithm();
                mgfHash = (h == null || h.isEmpty()) ? digest : RSAPSSAlgorithmParameters.canonicalDigestName(h);
                if (mgfHash == null)
                {
                    throw new InvalidAlgorithmParameterException("unsupported PSS digest: " + h);
                }
            }
            else
            {
                throw new InvalidAlgorithmParameterException(
                        "unsupported MGF parameters: " + mgfParams.getClass().getName());
            }

            salt = pss.getSaltLength();
            if (!RSAPSSAlgorithmParameters.saltLengthInRange(salt))
            {
                throw new InvalidAlgorithmParameterException("PSS salt length out of range [0, "
                        + RSAPSSAlgorithmParameters.MAX_SALT_LENGTH + "]: " + salt);
            }
            // Trailer field - RSASSA-PSS only defines value 1.
            int trailer = pss.getTrailerField();
            if (trailer != 1)
            {
                throw new InvalidAlgorithmParameterException(
                        "trailer field must be 1 (got " + trailer + ")");
            }
        }

        // A bound key is checked before anything changes, then the session is re-bound under the new values.
        RSAKey key = boundKey();
        if (key != null)
        {
            try
            {
                checkKeyLength(key, digest, salt);
            }
            catch (InvalidKeyException e)
            {
                throw new InvalidAlgorithmParameterException(e.getMessage(), e);
            }
        }
        this.digestName = digest;
        this.mgf1Digest = mgfHash;
        this.saltLen = salt;
        if (key != null)
        {
            reapplyParameters();
        }
    }

    @Override
    protected String signDigestName()
    {
        return digestName;
    }

    @Override
    protected void checkKey(RSAKey key) throws InvalidKeyException
    {
        checkKeyLength(key, digestName, saltLen);
    }

    /**
     * RFC 8017 9.1.1: emLen = ceil((modBits - 1) / 8) must reach hLen + sLen + 2. The digest length is
     * asked of the library; a digest it cannot answer for is left to the native init to refuse.
     */
    private void checkKeyLength(RSAKey key, String digest, int salt) throws InvalidKeyException
    {
        int hLen = digestLength(digest);
        if (hLen <= 0)
        {
            return;
        }
        int sLen = salt < 0 ? hLen : salt;
        int emLen = (key.getModulus().bitLength() + 6) / 8;
        long need = (long) hLen + sLen + 2;
        if (emLen < need)
        {
            throw new InvalidKeyException("Key is too short, need min " + need + " bytes");
        }
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

    /**
     * The parameters this instance will actually sign under.
     *
     * <p>Must not return null: the JDK's TLS SignatureScheme disables every
     * rsa_pss_* scheme when this throws or returns nothing.
     *
     * <p>Resolved through this SPI's own provider instance, never a name and
     * never JCA search order. An unbound SPI (direct construction) has no
     * provider to resolve through and reports null.
     */
    @Override
    protected AlgorithmParameters engineGetParameters()
    {
        Provider provider = keyFactory == null ? null : keyFactory.ownProviderInstance();
        if (provider == null)
        {
            return null;
        }
        int salt = effectiveSaltLength();
        if (salt < 0)
        {
            return null;
        }
        try
        {
            AlgorithmParameters params = AlgorithmParameters.getInstance("RSASSA-PSS", provider);
            params.init(RSAPSSAlgorithmParameters.specFor(digestName, mgf1Digest, salt));
            return params;
        }
        catch (NoSuchAlgorithmException | InvalidParameterSpecException e)
        {
            throw new ProviderException("unable to encode RSASSA-PSS parameters", e);
        }
    }

    /**
     * Salt length as a concrete byte count. {@code saltLen} carries the native
     * sentinel -1 for RSA_PSS_SALTLEN_DIGEST, so the digest is asked how long
     * it is. Returns -1 when the library cannot answer for this digest.
     */
    private int effectiveSaltLength()
    {
        if (saltLen >= 0)
        {
            return saltLen;
        }
        return digestLength(digestName);
    }

    /** The digest's output length from the library, or -1 when it cannot answer. */
    private int digestLength(String digest)
    {
        if (mdServiceNI == null)
        {
            return -1;
        }
        try
        {
            int len = mdServiceNI.digestOutputLength(digest);
            return len > 0 ? len : -1;
        }
        catch (RuntimeException e)
        {
            // A digest this library cannot fetch means we cannot state the
            // salt length; the caller gets null rather than a wrong number.
            return -1;
        }
    }
}
