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
import org.openssl.jostle.jcajce.spec.SSHKDFParameterSpec;
import org.openssl.jostle.jcajce.util.DigestUtil;
import org.openssl.jostle.util.Arrays;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactorySpi;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

/**
 * {@code SecretKeyFactory} surface for the RFC 4253 section 7.2 SSH key
 * derivation, backed by the native {@code EVP_KDF "SSHKDF"} via
 * {@link KdfNI#sshkdf}. The digest is fixed by the registered algorithm name
 * ({@code SSHKDF-SHA256} and siblings) and must be the one the key exchange
 * itself used; the {@link SSHKDFParameterSpec} supplies K, H, the session id,
 * which of the six keys to derive, and the output length.
 *
 * <p>SHA-3 variants are deliberately not registered: the 3.5.x FIPS module
 * refuses SHA3-256 for SSHKDF when {@code sshkdf-digest-check} is configured,
 * while accepting it on 3.1.2 and on mainline. Registering it would create a
 * capability-gated group for a digest SSH itself does not use.</p>
 */
public class SSHKDFSecretKeyFactory extends SecretKeyFactorySpi
{
    private final KdfNI kdfNI;
    private final String digestAlgorithm;

    public SSHKDFSecretKeyFactory(String digestAlgorithm)
    {
        this(NISelector.KdfNI, digestAlgorithm);
    }

    public SSHKDFSecretKeyFactory(KdfNI kdfNI, String digestAlgorithm)
    {
        this.kdfNI = kdfNI;
        this.digestAlgorithm = DigestUtil.getCanonicalDigestName(digestAlgorithm);
    }

    @Override
    protected SecretKey engineGenerateSecret(KeySpec keySpec) throws InvalidKeySpecException
    {
        if (!(keySpec instanceof SSHKDFParameterSpec))
        {
            throw new InvalidKeySpecException("unsupported KeySpec "
                    + (keySpec == null ? "null" : keySpec.getClass().getName()));
        }

        SSHKDFParameterSpec spec = (SSHKDFParameterSpec) keySpec;

        byte[] sharedSecret = spec.getSharedSecret();
        byte[] rawKey = new byte[spec.getOutputLength()];

        try
        {
            kdfNI.handleErrorCodes(kdfNI.sshkdf(
                    digestAlgorithm,
                    sharedSecret,
                    spec.getExchangeHash(),
                    spec.getSessionId(),
                    spec.getType().getCode(),
                    rawKey, 0, rawKey.length));

            return new SecretKeySpec(rawKey, "SSHKDF");
        }
        finally
        {
            // The exchange hash and session id are public; only K and the
            // derived bytes are secret.
            Arrays.clear(sharedSecret);
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
