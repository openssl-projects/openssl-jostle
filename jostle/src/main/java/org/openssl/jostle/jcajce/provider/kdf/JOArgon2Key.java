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

package org.openssl.jostle.jcajce.provider.kdf;

import org.openssl.jostle.util.Arrays;

import javax.crypto.SecretKey;
import javax.crypto.interfaces.PBEKey;
import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;
import java.io.Serializable;
import java.security.MessageDigest;
import java.security.spec.KeySpec;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicBoolean;

class JOArgon2Key implements KeySpec, PBEKey, Destroyable, Serializable
{
    private final AtomicBoolean hasBeenDestroyed = new AtomicBoolean(false);
    private static final long serialVersionUID = 4471109262148835113L;

    private final String algoName;
    private final char[] password;
    private final byte[] salt;
    private final int type;
    private final int version;
    private final int iterations;
    private final int memory;
    private final int parallelism;


    private final byte[] rawKey;


    JOArgon2Key(String algoName, char[] password, byte[] salt, int type, int version, int iterations,
               int memory, int parallelism, byte[] rawKey)
    {
        this.algoName = algoName;
        this.salt = Arrays.clone(salt);
        this.type = type;
        this.version = version;
        this.iterations = iterations;
        this.memory = memory;
        this.parallelism = parallelism;
        this.password = Arrays.clone(password);
        this.rawKey = Arrays.clone(rawKey);
    }


    public char[] getPassword()
    {
        checkDestroyed(this);
        return Arrays.clone(password);
    }


    public byte[] getSalt()
    {
        checkDestroyed(this);
        return Arrays.clone(salt);
    }


    public int getType()
    {
        checkDestroyed(this);
        return type;
    }


    public int getVersion()
    {
        checkDestroyed(this);
        return version;
    }


    public int getMemory()
    {
        checkDestroyed(this);
        return memory;
    }


    public int getParallelism()
    {
        checkDestroyed(this);
        return parallelism;
    }

    /**
     * PBEKey contract. Argon2's time cost IS an iteration count, so this
     * reports it directly. Implementing {@link PBEKey} marks this as
     * password-derived key material so a block cipher accepts it in a PBES2
     * flow; the value is informational — the raw key bytes are already derived
     * and used via {@link #getEncoded()}.
     */
    @Override
    public int getIterationCount()
    {
        checkDestroyed(this);
        return iterations;
    }

    @Override
    public String getAlgorithm()
    {
        checkDestroyed(this);
        return algoName;
    }

    @Override
    public String getFormat()
    {
        checkDestroyed(this);
        return "RAW";
    }

    @Override
    public byte[] getEncoded()
    {
        checkDestroyed(this);
        return Arrays.clone(rawKey);
    }

    @Override
    public void destroy() throws DestroyFailedException
    {
        // Arrays.clear is null-safe; Arrays.fill(char[], ...) is NOT, and
        // password may be null (a PBEKey translated via engineTranslateKey can
        // carry a null password/salt).
        Arrays.clear(rawKey);
        Arrays.clear(salt);
        if (password != null)
        {
            Arrays.fill(password, (char) 0);
        }
        hasBeenDestroyed.set(true);
    }

    @Override
    public boolean isDestroyed()
    {
        return hasBeenDestroyed.get();
    }

    static void checkDestroyed(Destroyable destroyable)
    {
        if (destroyable.isDestroyed())
        {
            throw new IllegalStateException("key has been destroyed");
        }
    }

    /**
     * Value equality following the {@code javax.crypto.spec.SecretKeySpec} contract:
     * same algorithm (case-insensitive) and same raw key bytes. The byte comparison
     * uses the constant-time {@link MessageDigest#isEqual} because the raw key is
     * secret material (a non-constant-time compare would leak it via timing).
     */
    @Override
    public boolean equals(Object o)
    {
        if (this == o)
        {
            return true;
        }
        if (!(o instanceof SecretKey))
        {
            return false;
        }
        SecretKey other = (SecretKey) o;
        if (!algoName.equalsIgnoreCase(other.getAlgorithm()))
        {
            return false;
        }
        return MessageDigest.isEqual(rawKey, other.getEncoded());
    }

    @Override
    public int hashCode()
    {
        return java.util.Arrays.hashCode(rawKey) ^ algoName.toLowerCase(Locale.ROOT).hashCode();
    }
}
