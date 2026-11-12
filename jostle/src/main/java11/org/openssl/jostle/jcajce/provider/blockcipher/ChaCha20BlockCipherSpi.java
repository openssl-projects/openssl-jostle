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

import org.openssl.jostle.jcajce.provider.NISelector;

import javax.crypto.spec.ChaCha20ParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.Provider;

/**
 * Java 11+ copy of {@link ChaCha20BlockCipherSpi}. Identical to the baseline
 * (java/) copy except that it additionally accepts
 * {@link javax.crypto.spec.ChaCha20ParameterSpec} (added in Java 11, which the
 * baseline cannot reference at {@code release = 8}). SunJCE's "ChaCha20" Cipher
 * requires that spec, so accepting it — alongside the BouncyCastle-style
 * {@link IvParameterSpec} — gives parity with both providers.
 *
 * <p>The multi-release jar loads this copy on JDK 11+ (from
 * {@code META-INF/versions/11}); JDK 8–10 load the baseline copy. The public
 * ABI is identical (same class, same public no-arg constructor) per the
 * multi-release ABI-stability rule.
 *
 * <p>NOTE: keep this class's behaviour in lockstep with the baseline copy in
 * {@code src/main/java} — only the {@code ChaCha20ParameterSpec} acceptance
 * differs.
 */
public class ChaCha20BlockCipherSpi extends BlockCipherSpi
{
    private static final int NONCE_LEN = 12;

    private int initialCounter;

    public ChaCha20BlockCipherSpi()
    {
        this((Provider) null);
    }

    //
    // Provider-binding constructor (MT-10) - see AESBlockCipherSpi.
    //
    public ChaCha20BlockCipherSpi(Provider providerInstance)
    {
        super(NISelector.BlockCipherNI, OSSLCipher.CHACHA20, OSSLMode.STREAM, "ChaCha20",
                providerInstance);
        // Fixed cipher (no key-size variant selection), so set osslCipher here:
        // the base 3-arg constructor seeds only osslMode, leaving osslCipher for
        // subclasses (AES/ARIA/...) that resolve it from key length at init.
        osslCipher = OSSLCipher.CHACHA20;
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        synchronized (this)
        {
            if (params instanceof ChaCha20ParameterSpec)
            {
                ChaCha20ParameterSpec cc = (ChaCha20ParameterSpec) params;
                // The counter is the unsigned 32-bit block counter; engineGetIV still reports the nonce.
                initialCounter = cc.getCounter();
                super.engineInit(opmode, key, new IvParameterSpec(cc.getNonce()), random);
                return;
            }
            initialCounter = 0;
            super.engineInit(opmode, key, params, random);
        }
    }

    @Override
    protected byte[] nativeIv(byte[] iv) throws InvalidAlgorithmParameterException
    {
        // The native layer reads a 16-byte IV as counter || nonce; an IvParameterSpec carries the nonce only.
        if (iv == null)
        {
            return null;
        }
        if (iv.length != NONCE_LEN)
        {
            throw new InvalidAlgorithmParameterException("invalid iv length");
        }
        if (initialCounter == 0)
        {
            return iv;
        }
        byte[] counterAndNonce = new byte[4 + NONCE_LEN];
        counterAndNonce[0] = (byte) initialCounter;
        counterAndNonce[1] = (byte) (initialCounter >>> 8);
        counterAndNonce[2] = (byte) (initialCounter >>> 16);
        counterAndNonce[3] = (byte) (initialCounter >>> 24);
        System.arraycopy(iv, 0, counterAndNonce, 4, NONCE_LEN);
        return counterAndNonce;
    }

    @Override
    protected OSSLCipher blockSizeReference()
    {
        // a stream cipher: OpenSSL says 1, the JCE surface reports 0
        return OSSLCipher.CHACHA20;
    }
}
