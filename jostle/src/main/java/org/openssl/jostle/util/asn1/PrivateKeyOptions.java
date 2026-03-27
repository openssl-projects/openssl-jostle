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

package org.openssl.jostle.util.asn1;

public enum PrivateKeyOptions
{
    DEFAULT("default"), SEED_ONLY("seed_only");
    private final String option;

    PrivateKeyOptions(final String value)
    {
        this.option = value;
    }

    public String getValue()
    {
        return option;
    }

    public static PrivateKeyOptions forOption(String option)
    {
        if (option == null)
        {
            return DEFAULT;
        }
        option = option.trim();

        for (PrivateKeyOptions value : values())
        {
            if (value.option.equalsIgnoreCase(option))
            {
                return value;
            }
        }
        throw new IllegalArgumentException("Unknown option: " + option);
    }

}
