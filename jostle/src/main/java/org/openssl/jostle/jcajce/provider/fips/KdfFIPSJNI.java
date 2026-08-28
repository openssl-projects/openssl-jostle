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

    @Override
    public native int kbkdf(String mode, String mac, String digest, String cipher,
                            byte[] key, byte[] label, byte[] context, byte[] seed,
                            int r, int useL, int useSeparator,
                            byte[] out, int outOffset, int outLen);

    @Override
    public native int sskdf(String digest, byte[] secret, byte[] info, byte[] out, int outOffset, int outLen);

    @Override
    public native int sshkdf(String digest, byte[] key, byte[] xcghash, byte[] sessionId, String type,
                             byte[] out, int outOffset, int outLen);

    /** FIPS library, so FIPS provider - see {@code DefaultServiceNI.providerName()}. */
    @Override
    public String providerName()
    {
        return JostleFIPSProvider.PROVIDER_NAME;
    }
}

