package org.openssl.jostle.jcajce.provider.kdf;

public class KdfNIJNI implements KdfNI
{
    @Override
    public native int scrypt(byte[] password, byte[] salt, int n, int r, int p, byte[] out, int outOffset, int outLen);

    @Override
    public native int pbkdf2(byte[] password, byte[] salt, int iter, String digest, byte[] out, int outOffset, int outLen);

    @Override
    public native int pkcs12(byte[] password, byte[] salt, int iter, String digest, byte[] out, int outOffset, int outLen);
}

