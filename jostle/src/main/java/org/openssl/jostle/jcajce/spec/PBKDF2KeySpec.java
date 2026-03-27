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

package org.openssl.jostle.jcajce.spec;

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
