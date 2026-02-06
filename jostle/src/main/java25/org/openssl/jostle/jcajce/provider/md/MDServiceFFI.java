package org.openssl.jostle.jcajce.provider.md;

public class MDServiceFFI implements MDServiceNI
{
    @Override
    public long ni_allocateDigest(String name, int xofLen, int[] err)
    {
        throw new UnsupportedOperationException();
    }

    @Override
    public int ni_updateByte(long ref, byte b)
    {
        return 0;
    }

    @Override
    public int ni_updateBytes(long ref, byte[] input, int offset, int len)
    {
        return 0;
    }

    @Override
    public void ni_dispose(long reference)
    {

    }

    @Override
    public int ni_getDigestOutputLen(long ref)
    {
        return 0;
    }

    @Override
    public int ni_digest(long ref, byte[] out, int offset, int length)
    {
        return 0;
    }

    @Override
    public void ni_reset(long ref)
    {

    }
}
