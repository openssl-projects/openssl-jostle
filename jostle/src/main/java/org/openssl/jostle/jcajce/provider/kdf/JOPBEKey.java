package org.openssl.jostle.jcajce.provider.kdf;

import org.openssl.jostle.util.Arrays;

import javax.crypto.SecretKey;
import javax.crypto.interfaces.PBEKey;
import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;
import java.io.Serializable;
import java.security.spec.KeySpec;
import java.util.concurrent.atomic.AtomicBoolean;

class JOPBEKey implements PBEKey, KeySpec, SecretKey, Destroyable, Serializable
{
    private final AtomicBoolean hasBeenDestroyed = new AtomicBoolean(false);
    private static final long serialVersionUID = 8674719565960006634L;

    private final String algoName;
    private final char[] password;
    private final byte[] salt;
    private final byte[] rawKey;
    private final int iterationCount;



    JOPBEKey(String algoName, char[] password, byte[] salt, int iterationCount, byte[] rawKey)
    {
        this.algoName = algoName;
        this.salt = Arrays.clone(salt);
        this.iterationCount = iterationCount;
        this.password = Arrays.clone(password);
        this.rawKey = Arrays.clone(rawKey);
    }

    @Override
    public char[] getPassword()
    {
        checkDestroyed(this);
        return Arrays.clone(password);
    }

    @Override
    public byte[] getSalt()
    {
        checkDestroyed(this);
        return Arrays.clone(salt);
    }

    @Override
    public int getIterationCount()
    {
        checkDestroyed(this);
        return iterationCount;
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
}
