package org.openssl.jostle.jcajce.provider;

import org.openssl.jostle.util.Arrays;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.spec.KeySpec;
import java.util.concurrent.atomic.AtomicBoolean;


final class ProvSecretKeySpec
        implements KeySpec, SecretKey
{
    private byte[] keyBytes;
    private String algorithm;
    private final AtomicBoolean hasBeenDestroyed = new AtomicBoolean(false);

    private static final long serialVersionUID = 2746065883609139941L;


    public ProvSecretKeySpec(byte[] key)
    {
        this(key, "RAW");
    }

    public ProvSecretKeySpec(byte[] key, String standardName)
    {
        keyBytes = Arrays.clone(key);
        this.algorithm = standardName;
    }

    public String getAlgorithm()
    {
        KeyUtil.checkDestroyed(this);
        return algorithm;
    }

    public String getFormat()
    {
        KeyUtil.checkDestroyed(this);
        return "RAW";
    }

    public byte[] getEncoded()
    {
        KeyUtil.checkDestroyed(this);

        return Arrays.clone(keyBytes);
    }

    public void destroy()
    {
        if (!hasBeenDestroyed.getAndSet(true))
        {
            Arrays.fill(keyBytes, (byte) 0);
        }
    }

    public boolean isDestroyed()
    {
        return hasBeenDestroyed.get();
    }

    private void readObject(
            ObjectInputStream in)
            throws IOException, ClassNotFoundException
    {
        in.defaultReadObject();

        algorithm = (String) in.readObject();
        keyBytes = (byte[]) in.readObject();
    }

    private void writeObject(
            ObjectOutputStream out)
            throws IOException
    {
        if (isDestroyed())
        {
            throw new IOException("key has been destroyed");
        }

        out.defaultWriteObject();

        out.writeObject(algorithm);
        out.writeObject(this.getEncoded());
    }
}
