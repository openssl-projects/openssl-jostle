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

package org.openssl.jostle.jcajce.provider.dsa;

import org.openssl.jostle.CryptoServicesRegistrar;
import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.jcajce.spec.OSSLKeyType;
import org.openssl.jostle.jcajce.spec.PKEYKeySpec;
import org.openssl.jostle.jcajce.spec.SpecNI;
import org.openssl.jostle.rand.DefaultRandSource;
import org.openssl.jostle.rand.RandSource;

import java.security.AlgorithmParameterGeneratorSpi;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.ProviderException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.DSAParameterSpec;

/**
 * {@code AlgorithmParameterGenerator} for DSA. Generates FIPS 186-4
 * domain parameters (p, q, g) natively via {@code EVP_PKEY_paramgen}
 * and returns them as an {@code AlgorithmParameters("DSA")} instance
 * initialised with the resulting {@link DSAParameterSpec}.
 *
 * <p>Supported modulus sizes mirror {@link DSAKeyPairGenerator}:
 * 1024 (q = 160), 2048 and 3072 (q = 256). Parameter generation is a
 * multi-second prime search for the larger sizes.
 */
public class DSAAlgorithmParameterGenerator extends AlgorithmParameterGeneratorSpi
{
    // Instance fields, not NISelector statics (NISelector for JSL,
    // FIPSNISelector for JSLFIPS). The specNI must match the NI that
    // allocated the params ref: the parameters-only EVP_PKEY is bound to
    // one interface library's OSSL_LIB_CTX, and its PKEYKeySpec disposer
    // must free it through that same library.
    private final DSAServiceNI dsaServiceNI;
    private final SpecNI specNI;

    /**
     * The provider this generator belongs to, or null when it was constructed
     * directly rather than through a provider (MT-14's unbound realm).
     */
    private final java.security.Provider providerInstance;

    /**
     * The sizes this generator accepts, or null for any size in
     * [{@link #MIN_P_BITS}, {@link #MAX_P_BITS}]. Per-provider on the
     * {@code ProvFIPSRSA} precedent: a FIPS module enforces the FIPS 186-4
     * &sect;4.2 (L, N) pairs, so {@code ProvFIPSDSA} passes that set.
     */
    private final int[] acceptedPBits;

    public DSAAlgorithmParameterGenerator()
    {
        this(NISelector.DSAServiceNI, NISelector.SpecNI);
    }

    public DSAAlgorithmParameterGenerator(DSAServiceNI dsaServiceNI, SpecNI specNI)
    {
        this(dsaServiceNI, specNI, null);
    }

    /**
     * @param providerInstance the provider this generator belongs to; its own
     *                         AlgorithmParameters serve the generated parameters.
     */
    public DSAAlgorithmParameterGenerator(DSAServiceNI dsaServiceNI, SpecNI specNI, java.security.Provider providerInstance)
    {
        this(dsaServiceNI, specNI, null, providerInstance);
    }

    /**
     * @param acceptedPBits the exact modulus sizes to accept, or null for any
     *                      size in [{@link #MIN_P_BITS}, {@link #MAX_P_BITS}].
     */
    public DSAAlgorithmParameterGenerator(DSAServiceNI dsaServiceNI, SpecNI specNI,
                                          int[] acceptedPBits,
                                          java.security.Provider providerInstance)
    {
        this.providerInstance = providerInstance;
        this.dsaServiceNI = dsaServiceNI;
        this.specNI = specNI;
        this.acceptedPBits = org.openssl.jostle.util.Arrays.clone(acceptedPBits);
    }

    /** Default modulus size when no engineInit is performed. */
    private static final int DEFAULT_KEY_SIZE = 2048;

    private int pBits = DEFAULT_KEY_SIZE;
    private int qBits = 256;
    private RandSource random = DefaultRandSource.wrap(CryptoServicesRegistrar.getSecureRandom());


    /**
     * Both bounds are OpenSSL's, not jostle policy: 512 is where the default
     * provider starts generating, and 10000 is
     * {@code OPENSSL_DSA_MAX_MODULUS_BITS} (openssl
     * {@code include/openssl/dsa.h:61}) - enforced at parameter check
     * ({@code crypto/dsa/dsa_check.c:30}) and at sign
     * ({@code crypto/dsa/dsa_ossl.c:378}), though NOT at paramgen.
     */
    private static final int MIN_P_BITS = 512;
    private static final int MAX_P_BITS = 10000;

    @Override
    protected void engineInit(int size, SecureRandom random)
    {
        // AlgorithmParameterGenerator.init(int) throws
        // InvalidParameterException (RuntimeException) per the JCA contract.
        if (acceptedPBits != null)
        {
            if (!org.openssl.jostle.util.Arrays.contains(acceptedPBits, size))
            {
                throw new InvalidParameterException(
                        "DSA parameter size " + size + " is not supported. "
                                + "Supported sizes: " + sizeList());
            }
        }
        else if (size < MIN_P_BITS || size > MAX_P_BITS)
        {
            throw new InvalidParameterException(
                    "DSA parameter size " + size + " is not supported. "
                            + "Sizes must be " + MIN_P_BITS + ".." + MAX_P_BITS + ".");
        }

        // FIPS 186-4 4.2 pairs N with L; q follows the modulus, it does not
        // restrict it.
        this.qBits = size < 2048 ? 160 : 256;
        this.pBits = size;
        this.random = DefaultRandSource.replaceWith(this.random, random);
    }

    private String sizeList()
    {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < acceptedPBits.length; i++)
        {
            sb.append(i > 0 ? ", " : "").append(acceptedPBits[i]);
        }
        return sb.toString();
    }

    @Override
    protected void engineInit(AlgorithmParameterSpec genParamSpec, SecureRandom random)
            throws InvalidAlgorithmParameterException
    {
        // The JCA-standard generation spec for DSA is the size-only
        // form; there is no standard DSAGenParameterSpec on the Java 8
        // baseline this provider compiles against.
        throw new InvalidAlgorithmParameterException(
                "DSA parameter generation takes a key size, not an AlgorithmParameterSpec; "
                        + "use init(int, SecureRandom)");
    }

    @Override
    protected AlgorithmParameters engineGenerateParameters()
    {
        long paramsRef;
        try
        {
            paramsRef = dsaServiceNI.generateParameters(pBits, qBits, random);
        }
        catch (org.openssl.jostle.jcajce.provider.ProviderCapabilityException e)
        {
            // The loaded provider refuses DSA domain-parameter generation
            // (OpenSSL's 3.5+ FIPS module gates it behind the "sign-check"
            // FIPS indicator). ProviderException per the JCE contract —
            // engineGenerateParameters declares no checked type.
            throw new ProviderException(e.getMessage(), e);
        }
        // Deliberately UNBOUND: a PARAMETERS spec, not a key. See the note in
        // the matching KeyPairGenerator — MT-14 binds keys, and domain
        // parameters never surface to a caller as a java.security.Key.
        PKEYKeySpec paramsSpec = new PKEYKeySpec(specNI, paramsRef, OSSLKeyType.DSA);
        DSAParameterSpec spec = DSAComponents.getParams(dsaServiceNI, paramsSpec);
        try
        {
            // Resolve from THIS generator's own provider. getInstance(String,
            // Provider) reads the provider OBJECT and never consults the
            // Security registry, so a foreign provider ahead of Jostle cannot
            // supply the parameters. A directly-constructed generator has no
            // provider to pin and falls back to registry order.
            AlgorithmParameters params = providerInstance != null
                    ? AlgorithmParameters.getInstance("DSA", providerInstance)
                    : AlgorithmParameters.getInstance("DSA");
            params.init(spec);
            return params;
        }
        catch (Exception e)
        {
            throw new ProviderException("unable to materialise DSA AlgorithmParameters", e);
        }
    }
}
