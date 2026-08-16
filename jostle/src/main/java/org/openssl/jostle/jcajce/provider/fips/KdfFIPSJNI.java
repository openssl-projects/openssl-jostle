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

package org.openssl.jostle.jcajce.provider.fips;

import org.openssl.jostle.jcajce.provider.kdf.KdfNI;

/**
 * JNI implementation of KdfNI backed by the FIPS interface library;
 * the glue is the base bridge re-included under renamed exports.
 */
class KdfFIPSJNI implements KdfNI
{

    @Override
    public native int pbkdf2(byte[] password, byte[] salt, int iter, String digest, byte[] out, int outOffset, int outLen);

    @Override
    public native int hkdf(byte[] ikm, byte[] salt, byte[] info, String digest, byte[] out, int outOffset, int outLen);
}

