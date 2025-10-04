/*
 *  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.util.test;

import org.openssl.jostle.util.encoders.Hex;

/**
 * A fixed secure random designed to return data for someone needing random bytes.
 */
public class TestRandomData
    extends FixedSecureRandom
{
    /**
     * Constructor from a Hex encoding of the data.
     *
     * @param encoding a Hex encoding of the data to be returned.
     */
    public TestRandomData(String encoding)
    {
        super(new Source[] { new FixedSecureRandom.Data(Hex.decode(encoding)) });
    }

    /**
     * Constructor from an array of bytes.
     *
     * @param encoding a byte array representing the data to be returned.
     */
    public TestRandomData(byte[] encoding)
    {
        super(new Source[] { new FixedSecureRandom.Data(encoding) });
    }
}
