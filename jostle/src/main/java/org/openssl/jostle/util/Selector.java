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
 * Interface a selector from a store should conform to.
 *
 * @param <T> the type stored in the store.
 */
public interface Selector<T>
    extends Cloneable
{
    /**
     * Match the passed in object, returning true if it would be selected by this selector, false otherwise.
     *
     * @param obj the object to be matched.
     * @return true if the object is a match for this selector, false otherwise.
     */
    boolean match(T obj);

    Object clone();
}
