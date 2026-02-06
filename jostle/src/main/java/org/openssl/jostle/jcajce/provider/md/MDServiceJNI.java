package org.openssl.jostle.jcajce.provider.md;

public class MDServiceJNI implements MDServiceNI
{
    @Override
    native public long ni_allocateDigest(String name, int xofLen, int[] err);


    @Override
    native public int ni_updateByte(long ref, byte b);


    @Override
    native public int ni_updateBytes(long ref, byte[] input, int offset, int len);


    @Override
    native public void ni_dispose(long ref);


    @Override
    native public int ni_getDigestOutputLen(long ref);


    @Override
    native public int ni_digest(long ref, byte[] out, int offset, int length);


    @Override
    native public void ni_reset(long ref);

}
