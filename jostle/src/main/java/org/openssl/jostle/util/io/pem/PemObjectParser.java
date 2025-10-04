/*
 *  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.util.io.pem;

import java.io.IOException;

/**
 * Base interface for parsers to convert PEM objects into specific objects.
 */
public interface PemObjectParser
{
    /**
     * Parse an object out of the PEM object passed in.
     *
     * @param obj the PEM object containing the details for the specific object.
     * @return a specific object represented by the  PEM object.
     * @throws IOException on a parsing error.
     */
    Object parseObject(PemObject obj)
            throws IOException;
}
