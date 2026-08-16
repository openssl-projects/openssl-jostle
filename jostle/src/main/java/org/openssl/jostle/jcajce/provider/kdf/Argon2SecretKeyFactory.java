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
import org.openssl.jostle.jcajce.provider.OpenSSLException;
import org.openssl.jostle.jcajce.spec.Argon2KeySpec;
import org.openssl.jostle.util.Arrays;
import org.openssl.jostle.util.Strings;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactorySpi;
import javax.crypto.interfaces.PBEKey;
import java.security.InvalidKeyException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

/**
 * Argon2 (RFC 9106) SecretKeyFactory, registered as {@code ARGON2} on the
 * non-FIPS provider only — Argon2 is not an approved service of the FIPS
 * module.
 *
 * <p>The type (Argon2d / Argon2i / Argon2id) and version travel in the
 * {@link Argon2KeySpec} rather than in the service name, matching how
 * BouncyCastle registers its own single {@code ARGON2} factory.</p>
 */
public class Argon2SecretKeyFactory extends SecretKeyFactorySpi
{
    /**
     * Upper bound on the memory cost, rejected here rather than left to the
     * native allocation: {@code memory} is kibibytes and a caller-controlled
     * int, so anything approaching Integer.MAX_VALUE asks OpenSSL for terabytes.
     * 4 GiB is far above any legitimate password-hashing configuration and
     * still leaves the KiB→byte multiply well inside a 64-bit size_t.
     */
    private static final int MAX_MEMORY_KIB = 4 * 1024 * 1024;

    // Instance field, not a NISelector static (NISelector for JSL,
    // FIPSNISelector for JSLFIPS) — matches scrypt/PBKDF2/HKDF so the derive
    // runs on the injected NI's library rather than being structurally pinned
    // to the non-FIPS libcrypto.
    private final MemoryHardKdfNI kdfNI;

    public Argon2SecretKeyFactory()
    {
        this(NISelector.MemoryHardKdfNI);
    }

    public Argon2SecretKeyFactory(MemoryHardKdfNI kdfNI)
    {
        this.kdfNI = kdfNI;
    }

    @Override
    protected SecretKey engineGenerateSecret(KeySpec keySpec) throws InvalidKeySpecException
    {
        if (!(keySpec instanceof Argon2KeySpec))
        {
            throw new InvalidKeySpecException("unsupported KeySpec "
                    + (keySpec == null ? "null" : keySpec.getClass().getName())
                    + ", expected " + Argon2KeySpec.class.getName());
        }

        Argon2KeySpec spec = (Argon2KeySpec) keySpec;
        char[] password = spec.getPassword();
        byte[] salt = spec.getSalt();
        int keyLengthBits = spec.getKeyLength();

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
        if (spec.getMemory() > MAX_MEMORY_KIB)
        {
            throw new InvalidKeySpecException("memory must not exceed " + MAX_MEMORY_KIB + " KiB");
        }

        byte[] rawKey = new byte[keyLengthBits >> 3];

        // The UTF-8 password bytes and the derived key are secret material —
        // scrub both once the native call has consumed them, on failure paths
        // too (JOArgon2Key took its own clones). The char[] password is this
        // spec's own defensive copy, so clear it here as well.
        byte[] passwordBytes = Strings.toUTF8ByteArray(password);
        try
        {
            kdfNI.handleErrorCodes(kdfNI.argon2(
                    passwordBytes,
                    salt,
                    spec.getType(),
                    spec.getVersion(),
                    spec.getIterations(),
                    spec.getMemory(),
                    spec.getParallelism(),
                    rawKey, 0, rawKey.length));

            return new JOArgon2Key("Argon2", password, salt, spec.getType(), spec.getVersion(),
                    spec.getIterations(), spec.getMemory(), spec.getParallelism(), rawKey);
        }
        catch (IllegalArgumentException | OpenSSLException e)
        {
            // The NI surfaces bad-parameter failures (type/version/iteration/
            // lane/memory bounds, and any OpenSSL derive rejection) as unchecked
            // exceptions; re-throw as the checked KeyFactory type per the JCE
            // contract.
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
