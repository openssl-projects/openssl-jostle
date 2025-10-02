/*
 *  Copyright 2005-2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://www.openssl.org/source/license.html
 *
 */

package org.openssl.jostle.util;

import java.io.IOException;

/**
 * Interface implemented by objects that can be converted into byte arrays.
 */
public interface Encodable
{
    /**
     * Return a byte array representing the implementing object.
     *
     * @return a byte array representing the encoding.
     * @throws java.io.IOException if an issue arises generation the encoding.
     */
    byte[] getEncoded()
        throws IOException;
}
