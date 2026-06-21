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

import javax.crypto.spec.ChaCha20ParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

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
    public ChaCha20BlockCipherSpi()
    {
        super(OSSLCipher.CHACHA20, OSSLMode.STREAM, "ChaCha20");
        // Fixed cipher (no key-size variant selection), so set osslCipher here:
        // the base 3-arg constructor seeds only osslMode, leaving osslCipher for
        // subclasses (AES/ARIA/...) that resolve it from key length at init.
        osslCipher = OSSLCipher.CHACHA20;
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        if (params instanceof ChaCha20ParameterSpec)
        {
            ChaCha20ParameterSpec cc = (ChaCha20ParameterSpec) params;
            // OpenSSL's raw ChaCha20 fixes the initial block counter at 0 (the
            // native layer builds the 16-byte EVP IV as counter(0) || nonce).
            // Reject a non-zero counter rather than silently ignoring it.
            if (cc.getCounter() != 0)
            {
                throw new InvalidAlgorithmParameterException(
                        "ChaCha20 counter must be 0; arbitrary initial counters are not supported");
            }
            // Convert to the 12-byte-nonce IvParameterSpec the base/native expect.
            super.engineInit(opmode, key, new IvParameterSpec(cc.getNonce()), random);
            return;
        }
        super.engineInit(opmode, key, params, random);
    }
}
