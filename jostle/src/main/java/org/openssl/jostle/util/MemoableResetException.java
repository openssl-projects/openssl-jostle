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

/**
 * Exception to be thrown on a failure to reset an object implementing Memoable.
 * <p>
 * The exception extends ClassCastException to enable users to have a single handling case,
 * only introducing specific handling of this one if required.
 * </p>
 */
public class MemoableResetException
    extends ClassCastException
{
    /**
     * Basic Constructor.
     *
     * @param msg message to be associated with this exception.
     */
    public MemoableResetException(String msg)
    {
        super(msg);
    }
}
