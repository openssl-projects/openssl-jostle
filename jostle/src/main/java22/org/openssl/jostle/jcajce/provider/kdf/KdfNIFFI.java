package org.openssl.jostle.jcajce.provider.kdf;

public class KdfNIFFI implements KdfNI
{
    @Override
    public int scrypt(byte[] password, byte[] salt, int n, int r, int p, byte[] out, int outOffset, int outLen)
    {
        throw new UnsupportedOperationException();
    }

    @Override
    public int pbkdf2(byte[] password, byte[] salt, int iter, String digest, byte[] out, int outOffset, int outLen)
    {
        throw new UnsupportedOperationException();
    }

    @Override
    public int pkcs12(byte[] password, byte[] salt, int iter, String digest, byte[] out, int outOffset, int outLen)
    {
        return 0;
    }
}
