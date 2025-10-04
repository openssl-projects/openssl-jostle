/*
 *  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider;

import java.security.*;

/**
 * Base class for
 */
public class SignerVerifierSpi extends SignatureSpi
{
    protected final SigAlgs sigAlg;

    public SignerVerifierSpi(SigAlgs sigAlg)
    {
        this.sigAlg = sigAlg;
    }


    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException
    {

    }

    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException
    {

    }

    @Override
    protected void engineUpdate(byte b) throws SignatureException
    {

    }

    @Override
    protected void engineUpdate(byte[] b, int off, int len) throws SignatureException
    {

    }

    @Override
    protected byte[] engineSign() throws SignatureException
    {
        return new byte[0];
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException
    {
        return false;
    }

    @Override
    protected void engineSetParameter(String param, Object value) throws InvalidParameterException
    {

    }

    @Override
    protected Object engineGetParameter(String param) throws InvalidParameterException
    {
        return null;
    }
}
