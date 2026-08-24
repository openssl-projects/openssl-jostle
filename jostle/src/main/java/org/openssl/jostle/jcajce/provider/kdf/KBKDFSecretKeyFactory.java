/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */
package org.openssl.jostle.jcajce.provider.kdf;

import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.jcajce.spec.KBKDFParameterSpec;
import org.openssl.jostle.jcajce.util.DigestUtil;
import org.openssl.jostle.util.Arrays;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactorySpi;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

/**
 * {@code SecretKeyFactory} surface for the NIST SP 800-108 key-based KDF,
 * backed by the native {@code EVP_KDF "KBKDF"} via {@link KdfNI#kbkdf}. The PRF
 * is fixed per registered algorithm — {@code KBKDF-HMAC-SHA256} and its digest
 * siblings, {@code KBKDF-CMAC-AES128} and its key-size siblings — following the
 * {@code HKDF-SHA256} precedent; the {@link KBKDFParameterSpec} supplies the
 * key-derivation key, Label, Context, mode, counter width and output length.
 *
 * <p>No Java-side output ceiling is imposed. OpenSSL's counter mode enforces
 * its own bound (a request whose block count reaches 2<sup>r</sup> is refused
 * with "invalid key length"), reports it identically on every supported build,
 * and does not repeat keying material below it — so a transcribed
 * {@code 255 * macLen} limit here would be a second source of truth that
 * disagrees with the first. This is the deliberate difference from
 * {@link HKDFSecretKeyFactory}, whose RFC 5869 ceiling OpenSSL does NOT
 * enforce.</p>
 */
public class KBKDFSecretKeyFactory extends SecretKeyFactorySpi
{
    /** {@code OSSL_KDF_PARAM_MAC} value for the HMAC-based PRF. */
    public static final String HMAC = "HMAC";

    /** {@code OSSL_KDF_PARAM_MAC} value for the CMAC-based PRF. */
    public static final String CMAC = "CMAC";

    private final KdfNI kdfNI;
    private final String macName;
    private final String digestAlgorithm;
    private final String cipherAlgorithm;

    /**
     * @param macName         {@link #HMAC} or {@link #CMAC}.
     * @param digestAlgorithm the JCE digest name for an HMAC PRF, else null.
     * @param cipherAlgorithm the OpenSSL cipher name for a CMAC PRF, else null.
     */
    public KBKDFSecretKeyFactory(String macName, String digestAlgorithm, String cipherAlgorithm)
    {
        this(NISelector.KdfNI, macName, digestAlgorithm, cipherAlgorithm);
    }

    public KBKDFSecretKeyFactory(KdfNI kdfNI, String macName, String digestAlgorithm, String cipherAlgorithm)
    {
        if (digestAlgorithm == null && cipherAlgorithm == null)
        {
            throw new IllegalArgumentException("KBKDF needs a digest (HMAC) or a cipher (CMAC)");
        }
        this.kdfNI = kdfNI;
        this.macName = macName;
        this.digestAlgorithm = digestAlgorithm == null
                ? null : DigestUtil.getCanonicalDigestName(digestAlgorithm);
        this.cipherAlgorithm = cipherAlgorithm;
    }

    @Override
    protected SecretKey engineGenerateSecret(KeySpec keySpec) throws InvalidKeySpecException
    {
        if (!(keySpec instanceof KBKDFParameterSpec))
        {
            throw new InvalidKeySpecException("unsupported KeySpec "
                    + (keySpec == null ? "null" : keySpec.getClass().getName()));
        }

        KBKDFParameterSpec spec = (KBKDFParameterSpec) keySpec;

        byte[] ki = spec.getKI();
        byte[] rawKey = new byte[spec.getOutputLength()];

        try
        {
            kdfNI.handleErrorCodes(kdfNI.kbkdf(
                    spec.getMode().getOpenSSLName(),
                    macName,
                    digestAlgorithm,
                    cipherAlgorithm,
                    ki,
                    spec.getLabel(),
                    spec.getContext(),
                    spec.getIV(),
                    spec.getR(),
                    spec.useL() ? 1 : 0,
                    spec.useSeparator() ? 1 : 0,
                    rawKey, 0, rawKey.length));

            return new SecretKeySpec(rawKey, "KBKDF");
        }
        finally
        {
            // Both the key-derivation key and the derived bytes are secret
            // material; SecretKeySpec took its own copy, and getKI() returned a
            // fresh copy, so clearing here cannot damage the caller's spec.
            Arrays.clear(ki);
            Arrays.clear(rawKey);
        }
    }

    @Override
    protected KeySpec engineGetKeySpec(SecretKey key, Class<?> keySpec) throws InvalidKeySpecException
    {
        throw new UnsupportedOperationException("not implemented");
    }

    @Override
    protected SecretKey engineTranslateKey(SecretKey key) throws InvalidKeyException
    {
        throw new InvalidKeyException("not implemented");
    }
}
