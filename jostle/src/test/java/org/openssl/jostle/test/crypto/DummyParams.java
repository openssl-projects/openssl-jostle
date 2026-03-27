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

package org.openssl.jostle.test.crypto;

import javax.crypto.spec.IvParameterSpec;
import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.AlgorithmParametersSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

class DummyParams extends AlgorithmParameters
{


    protected DummyParams()
    {
        super(new AlgorithmParametersSpi()
        {
            @Override
            protected void engineInit(AlgorithmParameterSpec paramSpec) throws InvalidParameterSpecException
            {

            }

            @Override
            protected void engineInit(byte[] params) throws IOException
            {

            }

            @Override
            protected void engineInit(byte[] params, String format) throws IOException
            {

            }

            @Override
            protected <T extends AlgorithmParameterSpec> T engineGetParameterSpec(Class<T> paramSpec) throws InvalidParameterSpecException
            {
                return paramSpec.cast(new IvParameterSpec(new byte[16]));
            }

            @Override
            protected byte[] engineGetEncoded() throws IOException
            {
                return new byte[0];
            }

            @Override
            protected byte[] engineGetEncoded(String format) throws IOException
            {
                return new byte[0];
            }

            @Override
            protected String engineToString()
            {
                return "";
            }
        }, null, "cats");
    }

}
