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

import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;

/**
 * This is a testing utility class to check the property that an {@link OutputStream} is never
 * closed in some particular context - typically when wrapped by another {@link OutputStream} that
 * should not be forwarding its {@link OutputStream#close()} calls. Not needed in production code.
 */
public class UncloseableOutputStream extends FilterOutputStream
{
    public UncloseableOutputStream(OutputStream s)
    {
        super(s);
    }

    public void close()
    {
        throw new RuntimeException("close() called on UncloseableOutputStream");
    }

    public void write(byte[] b, int off, int len) throws IOException
    {
        out.write(b, off, len);
    }
 }
