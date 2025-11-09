package org.openssl.jostle.jcajce.provider.kdf;

import org.openssl.jostle.util.Arrays;

import javax.crypto.SecretKey;
import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;
import java.io.Serializable;
import java.security.spec.KeySpec;
import java.util.concurrent.atomic.AtomicBoolean;

class JOScryptKey implements KeySpec, SecretKey, Destroyable, Serializable
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
