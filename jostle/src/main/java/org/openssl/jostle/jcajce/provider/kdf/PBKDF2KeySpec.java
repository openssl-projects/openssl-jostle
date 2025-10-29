package org.openssl.jostle.jcajce.provider.kdf;

import org.openssl.jostle.jcajce.util.DigestUtil;

import javax.crypto.spec.PBEKeySpec;

public class PBKDF2KeySpec extends PBEKeySpec
{
    private final String prf;

    public PBKDF2KeySpec(char[] password, String digestAlgorithm)
    {
        super(password);
        this.prf = DigestUtil.getCanonicalDigestName(digestAlgorithm);
    }

    public PBKDF2KeySpec(char[] password, byte[] salt, int iterationCount, int keyLength, String digestAlgorithm)
    {
        super(password, salt, iterationCount, keyLength);
        this.prf = DigestUtil.getCanonicalDigestName(digestAlgorithm);
    }

    public PBKDF2KeySpec(char[] password, byte[] salt, int iterationCount, String digestAlgorithm)
    {
        super(password, salt, iterationCount);
        this.prf = DigestUtil.getCanonicalDigestName(digestAlgorithm);
    }

    public String getPrf()
    {
        return prf;
    }
}
