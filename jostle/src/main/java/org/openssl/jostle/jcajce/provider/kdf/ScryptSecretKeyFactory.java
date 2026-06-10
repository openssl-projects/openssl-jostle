/*
 *  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */
package org.openssl.jostle.jcajce.provider.kdf;

import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.jcajce.spec.ScryptKeySpec;
import org.openssl.jostle.util.Arrays;
import org.openssl.jostle.util.Strings;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactorySpi;
import javax.crypto.interfaces.PBEKey;
import java.security.InvalidKeyException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

public class ScryptSecretKeyFactory extends SecretKeyFactorySpi
{
    @Override
    protected SecretKey engineGenerateSecret(KeySpec keySpec) throws InvalidKeySpecException
    {
        char[] password;
        byte[] salt;
        int costParameter, blockSize, parallelizationParameter, keyLengthBits;

        if (keySpec instanceof ScryptKeySpec)
        {
            ScryptKeySpec spec = (ScryptKeySpec) keySpec;
            password = spec.getPassword();
            salt = spec.getSalt();
            costParameter = spec.getCostParameter();
            blockSize = spec.getBlockSize();
            parallelizationParameter = spec.getParallelizationParameter();
            keyLengthBits = spec.getKeyLength();
        }
        else if (keySpec != null)
        {
            // Accept any structurally-compatible ScryptKeySpec (notably BouncyCastle's
            // org.bouncycastle.jcajce.spec.ScryptKeySpec) without a compile-time dependency
            // on it, so high-level PBES2/PKCS#8/PKCS#12 builders that construct that type can
            // derive keys through this native scrypt KDF. Same accessor contract, same units
            // (keyLength in bits); the password is UTF-8 encoded below either way. A spec
            // missing any accessor surfaces as InvalidKeySpecException from the reflective call.
            Class<?> cls = keySpec.getClass();
            try
            {
                password = (char[]) cls.getMethod("getPassword").invoke(keySpec);
                salt = (byte[]) cls.getMethod("getSalt").invoke(keySpec);
                costParameter = (Integer) cls.getMethod("getCostParameter").invoke(keySpec);
                blockSize = (Integer) cls.getMethod("getBlockSize").invoke(keySpec);
                parallelizationParameter = (Integer) cls.getMethod("getParallelizationParameter").invoke(keySpec);
                keyLengthBits = (Integer) cls.getMethod("getKeyLength").invoke(keySpec);
            }
            catch (ReflectiveOperationException | ClassCastException | NullPointerException e)
            {
                throw new InvalidKeySpecException("unsupported KeySpec " + cls.getName(), e);
            }
        }
        else
        {
            throw new InvalidKeySpecException("unsupported KeySpec null");
        }

        byte[] rawKey = new byte[keyLengthBits >> 3];

        // The UTF-8 password bytes are secret material — scrub the temporary
        // copy once the native call has consumed it, on failure paths too.
        byte[] passwordBytes = Strings.toUTF8ByteArray(password);
        try
        {
            NISelector.KdfNI.handleErrorCodes(NISelector.KdfNI.scrypt(
                    passwordBytes,
                    salt,
                    costParameter,
                    blockSize,
                    parallelizationParameter,
                    rawKey, 0, rawKey.length));
        }
        finally
        {
            if (passwordBytes != null)
            {
                Arrays.fill(passwordBytes, (byte) 0);
            }
        }

        return new JOScryptKey("ScryptWithUTF8", password, salt, costParameter, blockSize, parallelizationParameter, rawKey);
    }

    @Override
    protected KeySpec engineGetKeySpec(SecretKey key, Class<?> keySpec) throws InvalidKeySpecException
    {
        throw new UnsupportedOperationException("not implemented");
    }

    @Override
    protected SecretKey engineTranslateKey(SecretKey key) throws InvalidKeyException
    {
        if (key == null)
        {
            throw new InvalidKeyException("key parameter is null");
        }

        if (key instanceof PBEKey)
        {
            PBEKey pbeKey = (PBEKey) key;
            return new JOPBEKey(key.getAlgorithm(), pbeKey.getPassword(), pbeKey.getSalt(), pbeKey.getIterationCount(), pbeKey.getEncoded());
        }

        throw new InvalidKeyException("unsupported key type: " + key.getClass());

    }
}
