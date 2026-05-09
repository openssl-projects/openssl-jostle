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
import java.security.InvalidParameterException;
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
     * Lower bound on the public exponent. Above this floor we additionally
     * require {@code e} to be odd (RSA spec — even {@code e} is structurally
     * invalid because it shares the factor 2 with phi(n) for any RSA
     * modulus). We do not require {@code e} to be a Fermat prime; OpenSSL
     * accepts any odd {@code e ≥ 3} that's coprime to phi(n).
     */
    private static final BigInteger MIN_PUBLIC_EXPONENT = BigInteger.valueOf(3);

    /**
     * Minimum modulus size in bits. RSA below 1024 bits is broken
     * cryptographically (768-bit factored in 2010, 829-bit in 2020).
     * OpenSSL 3.x's default provider also rejects very small keys at
     * keygen time, but enforcing a friendly floor here surfaces a typed
     * {@code InvalidParameterException} with a clear message instead of
     * a generic {@code OpenSSLException} from deep in the stack.
     */
    private static final int MIN_KEY_SIZE_BITS = 1024;

    /**
     * Maximum modulus size in bits. RSA keygen runtime is O(bits<sup>3</sup>);
     * a request for {@code keysize = 1_000_000} would never complete and
     * could OOM the process. 16384 is the largest size that any realistic
     * deployment uses (and even that is overkill — modern recommendations
     * top out at 4096). Provides DoS protection at the JCA boundary against
     * a caller passing an absurd value.
     */
    private static final int MAX_KEY_SIZE_BITS = 16384;


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
        // KeyPairGenerator.initialize(int) throws InvalidParameterException
        // (RuntimeException) for unsupported sizes per the JCA contract.
        String err = validateKeySize(keysize);
        if (err != null)
        {
            throw new InvalidParameterException(err);
        }
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

        String err = validateKeySize(spec.getKeysize());
        if (err != null)
        {
            throw new InvalidAlgorithmParameterException(err);
        }

        BigInteger e = spec.getPublicExponent();
        if (e == null)
        {
            e = DEFAULT_PUBLIC_EXPONENT;
        }
        if (e.compareTo(MIN_PUBLIC_EXPONENT) < 0)
        {
            throw new InvalidAlgorithmParameterException("public exponent must be >= 3");
        }
        if (!e.testBit(0))
        {
            // Even e shares a factor of 2 with phi(n) and produces a
            // mathematically broken RSA key. OpenSSL would reject at
            // keygen time; surface as a typed InvalidAlgorithmParameterException
            // with a clear message rather than a generic OpenSSLException
            // from deep in the native stack.
            throw new InvalidAlgorithmParameterException(
                    "public exponent must be odd (got " + e + ")");
        }

        this.keySizeBits = spec.getKeysize();
        this.publicExponent = e;
        this.random = DefaultRandSource.replaceWith(this.random, random);
    }


    /**
     * Validates the requested modulus size against the project bounds.
     * Returns null if the size is in range, or a human-readable error
     * message if not. The caller wraps the message in the appropriate
     * exception type — {@link InvalidParameterException} for the
     * {@code initialize(int)} path or
     * {@link InvalidAlgorithmParameterException} for the
     * {@code initialize(AlgorithmParameterSpec)} path.
     */
    private static String validateKeySize(int keysize)
    {
        if (keysize < MIN_KEY_SIZE_BITS || keysize > MAX_KEY_SIZE_BITS)
        {
            return "RSA key size " + keysize + " is out of range "
                    + "[" + MIN_KEY_SIZE_BITS + ", " + MAX_KEY_SIZE_BITS + "]";
        }
        return null;
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
