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

class JOScryptKey implements KeySpec, PBEKey, Destroyable, Serializable
{
    private final AtomicBoolean hasBeenDestroyed = new AtomicBoolean(false);
    private static final long serialVersionUID = 658060872465898190L;

    private final String algoName;
    private final char[] password;
    private final byte[] salt;
    private final int n;
    private final int r;
    private final int p;


    private final byte[] rawKey;


    JOScryptKey(String algoName, char[] password, byte[] salt, int n, int r, int p, byte[] rawKey)
    {
        this.algoName = algoName;
        this.salt = Arrays.clone(salt);
        this.n = n;
        this.r = r;
        this.p = p;
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


    public int getCostParameter()
    {
        checkDestroyed(this);
        return n;
    }


    public int getBlockSize()
    {
        checkDestroyed(this);
        return r;
    }


    public int getParallelizationParameter()
    {
        checkDestroyed(this);
        return p;
    }

    /**
     * PBEKey contract. scrypt has no PBKDF-style iteration count; the closest
     * analogue is the CPU/memory cost parameter N (also available, unambiguously,
     * via {@link #getCostParameter()}). Implementing {@link PBEKey} marks this as
     * password-derived key material so a block cipher accepts it directly in a
     * PBES2 flow; the value is informational — the raw key bytes are already
     * derived and used via {@link #getEncoded()}.
     */
    @Override
    public int getIterationCount()
    {
        checkDestroyed(this);
        return n;
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
        Arrays.fill(rawKey, (byte) 0);
        Arrays.fill(salt, (byte) 0);
        Arrays.fill(password, (char) 0);
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
