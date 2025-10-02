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

import java.util.Collection;

/**
 * A generic interface describing a simple store of objects.
 *
 * @param <T> the object type stored.
 */
public interface Store<T>
{
    /**
     * Return a possibly empty collection of objects that match the criteria implemented
     * in the passed in Selector.
     *
     * @param selector the selector defining the match criteria.
     * @return a collection of matching objects, empty if none available.
     * @throws StoreException if there is a failure during matching.
     */
    Collection<T> getMatches(Selector<T> selector)
        throws StoreException;
}
