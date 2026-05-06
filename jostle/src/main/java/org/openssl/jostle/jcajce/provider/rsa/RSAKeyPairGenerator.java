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

import org.openssl.jostle.CryptoServicesRegistrar;
import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.jcajce.spec.OSSLKeyType;
import org.openssl.jostle.jcajce.spec.PKEYKeySpec;
import org.openssl.jostle.rand.DefaultRandSource;
import org.openssl.jostle.rand.RandSource;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;

public class RSAKeyPairGenerator extends KeyPairGenerator
{
    private static final int DEFAULT_KEY_SIZE_BITS = 2048;

    /**
     * 65537 — the standard, fast, and effectively-universal default
     * public exponent (F4). Used unless the caller overrides via
     * {@link RSAKeyGenParameterSpec}.
     */
    private static final BigInteger DEFAULT_PUBLIC_EXPONENT = RSAKeyGenParameterSpec.F4;

    /**
     * Lower bound on the public exponent. Per the v1 design decision,
     * we trust the caller above this floor (no primality check, no
     * even-value rejection); OpenSSL itself rejects pathological
     * combinations during keygen.
     */
    private static final BigInteger MIN_PUBLIC_EXPONENT = BigInteger.valueOf(3);


    private int keySizeBits = DEFAULT_KEY_SIZE_BITS;
    private BigInteger publicExponent = DEFAULT_PUBLIC_EXPONENT;
    private RandSource random = DefaultRandSource.wrap(CryptoServicesRegistrar.getSecureRandom());


    public RSAKeyPairGenerator()
    {
        super("RSA");
    }

    @Override
    public void initialize(int keysize, SecureRandom random)
    {
        this.keySizeBits = keysize;
        this.random = DefaultRandSource.replaceWith(this.random, random);
    }

    @Override
    public void initialize(AlgorithmParameterSpec params, SecureRandom random) throws InvalidAlgorithmParameterException
    {
        if (!(params instanceof RSAKeyGenParameterSpec))
        {
            throw new InvalidAlgorithmParameterException("expected instance of RSAKeyGenParameterSpec");
        }
        RSAKeyGenParameterSpec spec = (RSAKeyGenParameterSpec) params;

        BigInteger e = spec.getPublicExponent();
        if (e == null)
        {
            e = DEFAULT_PUBLIC_EXPONENT;
        }
        if (e.compareTo(MIN_PUBLIC_EXPONENT) < 0)
        {
            throw new InvalidAlgorithmParameterException("public exponent must be >= 3");
        }

        this.keySizeBits = spec.getKeysize();
        this.publicExponent = e;
        this.random = DefaultRandSource.replaceWith(this.random, random);
    }

    @Override
    public void initialize(AlgorithmParameterSpec params) throws InvalidAlgorithmParameterException
    {
        initialize(params, null);
    }

    @Override
    public KeyPair generateKeyPair()
    {
        // toByteArray returns big-endian two's complement; for any positive
        // BigInteger that's the unsigned magnitude with at most one extra
        // leading 0x00 byte (which BN_bin2bn handles correctly).
        byte[] e = publicExponent.toByteArray();

        long ref = NISelector.RSAServiceNI.generateKeyPair(keySizeBits, e, random);
        if (ref == 0)
        {
            throw new IllegalStateException("unexpected null pointer from native layer");
        }

        PKEYKeySpec spec = new PKEYKeySpec(ref, OSSLKeyType.RSA);
        return new KeyPair(new JORSAPublicKey(spec), new JORSAPrivateKey(spec));
    }
}
