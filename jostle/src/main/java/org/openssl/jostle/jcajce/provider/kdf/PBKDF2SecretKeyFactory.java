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
import org.openssl.jostle.jcajce.spec.PBKDF2KeySpec;
import org.openssl.jostle.jcajce.util.DigestUtil;
import org.openssl.jostle.util.Arrays;
import org.openssl.jostle.util.Strings;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactorySpi;
import javax.crypto.interfaces.PBEKey;
import javax.crypto.spec.PBEKeySpec;
import java.security.InvalidKeyException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

public class PBKDF2SecretKeyFactory extends SecretKeyFactorySpi
{

    private final String forcedDigestAlgorithm;

    // Instance field, not a NISelector static (NISelector for JSL,
    // FIPSNISelector for JSLFIPS).
    private final KdfNI kdfNI;

    public PBKDF2SecretKeyFactory(String forcedDigestAlgorithm)
    {
        this(NISelector.KdfNI, forcedDigestAlgorithm);
    }

    public PBKDF2SecretKeyFactory()
    {
        this.kdfNI = NISelector.KdfNI;
        this.forcedDigestAlgorithm = null;
    }

    public PBKDF2SecretKeyFactory(KdfNI kdfNI, String forcedDigestAlgorithm)
    {
        this.kdfNI = kdfNI;
        this.forcedDigestAlgorithm = forcedDigestAlgorithm == null
                ? null : DigestUtil.getCanonicalDigestName(forcedDigestAlgorithm);
    }


    @Override
    protected SecretKey engineGenerateSecret(KeySpec keySpec) throws InvalidKeySpecException
    {
        if (keySpec instanceof PBEKeySpec)
        {
            PBEKeySpec spec = (PBEKeySpec) keySpec;

            // A PBEKeySpec built with the 1- or 3-arg constructor reports a key
            // length of 0; deriving a zero-length key would silently mint an
            // empty SecretKey. Require a positive, byte-aligned length (the
            // derive buffer is sized by >> 3, so a non-multiple would truncate).
            int keyLengthBits = spec.getKeyLength();
            if (keyLengthBits <= 0)
            {
                throw new InvalidKeySpecException("key length must be positive");
            }
            if ((keyLengthBits & 7) != 0)
            {
                throw new InvalidKeySpecException("key length must be a multiple of 8 bits");
            }

            String algo = null;
            if (spec instanceof PBKDF2KeySpec)
            {
                algo = ((PBKDF2KeySpec) spec).getPrf();
            }

            if (algo == null)
            {
                algo = forcedDigestAlgorithm;
            }

            if (forcedDigestAlgorithm != null && !forcedDigestAlgorithm.equals(algo))
            {
                throw new InvalidKeySpecException("PRF in spec " + algo + " does not match forced prf " + forcedDigestAlgorithm);
            }

            if (algo == null)
            {
                algo = DigestUtil.getCanonicalDigestName("SHA-1");
            }

            byte[] rawKey = new byte[keyLengthBits >> 3];
            // Retrieve the password once (PBEKeySpec.getPassword returns a fresh
            // copy each call) and scrub every secret copy we make in the finally:
            // the UTF-8 bytes, the char[] copy, and the derived key (JOPBEKey took
            // its own clones). The salt is not secret, so it is left as-is.
            char[] password = spec.getPassword();
            byte[] passwordBytes = Strings.toUTF8ByteArray(password);
            byte[] salt = spec.getSalt();
            try
            {
                kdfNI.handleErrorCodes(kdfNI.pbkdf2(
                        passwordBytes,
                        salt,
                        spec.getIterationCount(),
                        algo, rawKey, 0, rawKey.length));

                String name = "PBKDF2WithHmac" + algo + "andUTF8";
                return new JOPBEKey(name, password, salt, spec.getIterationCount(), rawKey);
            }
            catch (IllegalArgumentException | OpenSSLException e)
            {
                // The NI surfaces bad-parameter failures as unchecked
                // IllegalArgumentException / OpenSSLException (the latter also
                // carries FIPS SP 800-132 salt/iteration-floor rejections);
                // re-throw as the checked KeyFactory type per the JCE contract.
                throw new InvalidKeySpecException(e.getMessage(), e);
            }
            finally
            {
                Arrays.clear(passwordBytes);
                Arrays.clear(rawKey);
                if (password != null)
                {
                    Arrays.fill(password, (char) 0);
                }
            }
        }

        throw new InvalidKeySpecException("unsupported KeySpec " + keySpec.getClass().getName());
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
