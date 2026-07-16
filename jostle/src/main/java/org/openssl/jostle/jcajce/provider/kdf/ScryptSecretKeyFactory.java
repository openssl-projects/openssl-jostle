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
import org.openssl.jostle.jcajce.provider.OpenSSLException;
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
    // Instance field, not a NISelector static (NISelector for JSL,
    // FIPSNISelector for JSLFIPS) — matches PBKDF2/HKDF so scrypt runs on the
    // injected NI's library rather than being structurally pinned to the
    // non-FIPS libcrypto if it were ever registered for a FIPS provider.
    private final KdfNI kdfNI;

    public ScryptSecretKeyFactory()
    {
        this(NISelector.KdfNI);
    }

    public ScryptSecretKeyFactory(KdfNI kdfNI)
    {
        this.kdfNI = kdfNI;
    }

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

        // A zero/negative key length would silently mint an empty key (or throw
        // a raw NegativeArraySizeException below); require a positive,
        // byte-aligned length (the derive buffer is sized by >> 3).
        if (keyLengthBits <= 0)
        {
            throw new InvalidKeySpecException("key length must be positive");
        }
        if ((keyLengthBits & 7) != 0)
        {
            throw new InvalidKeySpecException("key length must be a multiple of 8 bits");
        }

        byte[] rawKey = new byte[keyLengthBits >> 3];

        // The UTF-8 password bytes and the derived key are secret material —
        // scrub both once the native call has consumed them, on failure paths
        // too (JOScryptKey took its own clones). The char[] password is the
        // caller's own array (ScryptKeySpec exposes it directly, not a copy),
        // so it is deliberately NOT cleared here — that would corrupt the
        // caller's spec.
        byte[] passwordBytes = Strings.toUTF8ByteArray(password);
        try
        {
            kdfNI.handleErrorCodes(kdfNI.scrypt(
                    passwordBytes,
                    salt,
                    costParameter,
                    blockSize,
                    parallelizationParameter,
                    rawKey, 0, rawKey.length));

            return new JOScryptKey("ScryptWithUTF8", password, salt, costParameter, blockSize, parallelizationParameter, rawKey);
        }
        catch (IllegalArgumentException | OpenSSLException e)
        {
            // The NI surfaces bad-parameter failures (r/p/N bounds, and any
            // OpenSSL derive rejection) as unchecked exceptions; re-throw as the
            // checked KeyFactory type per the JCE contract.
            throw new InvalidKeySpecException(e.getMessage(), e);
        }
        finally
        {
            Arrays.clear(passwordBytes);
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
        if (key == null)
        {
            throw new InvalidKeyException("key parameter is null");
        }

        if (key instanceof PBEKey)
        {
            PBEKey pbeKey = (PBEKey) key;
            // getPassword() and getEncoded() return fresh copies of secret
            // material (PBEKey contract); JOPBEKey clones what it keeps, so
            // scrub our transient copies once it has taken ownership.
            char[] password = pbeKey.getPassword();
            byte[] encoded = pbeKey.getEncoded();
            try
            {
                return new JOPBEKey(key.getAlgorithm(), password, pbeKey.getSalt(), pbeKey.getIterationCount(), encoded);
            }
            finally
            {
                Arrays.clear(encoded);
                if (password != null)
                {
                    Arrays.fill(password, (char) 0);
                }
            }
        }

        throw new InvalidKeyException("unsupported key type: " + key.getClass());

    }
}
