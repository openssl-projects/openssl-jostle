/*
 *  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.util.io;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * An input stream which copies anything read through it to another stream.
 */
public class TeeInputStream
    extends InputStream
{
    private final InputStream input;
    private final OutputStream output;

    /**
     * Base constructor.
     *
     * @param input input stream to be wrapped.
     * @param output output stream to copy any input read to.
     */
    public TeeInputStream(InputStream input, OutputStream output)
    {
        this.input = input;
        this.output = output;
    }

    public int available() throws IOException
    {
        return input.available();
    }

    public int read(byte[] buf)
        throws IOException
    {
        return read(buf, 0, buf.length);
    }

    public int read(byte[] buf, int off, int len)
        throws IOException
    {
        int i = input.read(buf, off, len);

        if (i > 0)
        {
            output.write(buf, off, i);
        }

        return i;
    }

    public int read()
        throws IOException
    {
        int i = input.read();

        if (i >= 0)
        {
            output.write(i);
        }

        return i;
    }

    public void close()
        throws IOException
    {
        this.input.close();
        this.output.close();
    }

    public OutputStream getOutputStream()
    {
        return output;
    }
}
