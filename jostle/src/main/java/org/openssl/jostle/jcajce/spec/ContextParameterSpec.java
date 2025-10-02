/*
 *  Copyright 2005-2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://www.openssl.org/source/license.html
 *
 */

package org.openssl.jostle.jcajce.spec;

import org.openssl.jostle.util.Arrays;

import java.security.spec.AlgorithmParameterSpec;
import java.util.Objects;

public class ContextParameterSpec implements AlgorithmParameterSpec
{
    public static final ContextParameterSpec EMPTY_CONTEXT_SPEC = new ContextParameterSpec(new byte[0]);

    private final byte[] context;

    public ContextParameterSpec(byte[] context)
    {
        this.context = Arrays.clone(context);
    }

    public byte[] getContext()
    {
        return Arrays.clone(context);
    }

    @Override
    public boolean equals(Object o)
    {
        if (o == null || getClass() != o.getClass()) return false;
        ContextParameterSpec that = (ContextParameterSpec) o;
        return Objects.deepEquals(context, that.context);
    }

    @Override
    public int hashCode()
    {
        return java.util.Arrays.hashCode(context);
    }
}
