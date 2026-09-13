/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.spec;

import org.openssl.jostle.util.Arrays;

import java.security.spec.AlgorithmParameterSpec;

/**
 * Parameters for the integrated-encryption KEM of IEEE 1609.2 (ITS), as
 * consumed by {@code Cipher.ETSIKEMwithSHA256}.
 *
 * <p>The <b>recipientInfo</b> is the shared info fed to the KDF, and the
 * derivation depends on it — an unwrap must present the same bytes the wrap
 * used. BouncyCastle's ITS layer passes the recipient certificate's hash.
 *
 * <p><b>Point compression applies to the wrap only.</b> It selects the form of
 * the ephemeral public key written into the output; an unwrap reads whichever
 * form the input carries and ignores this flag.
 *
 * <p>Mirrors {@code org.bouncycastle.jcajce.spec.IESKEMParameterSpec} so a
 * caller can hand either spec to the Jostle KEM — the SPI also accepts
 * BouncyCastle's spec reflectively, which is what its ITS wrapper and
 * decryptor pass.
 */
public class IESKEMParameterSpec implements AlgorithmParameterSpec
{
    private final byte[] recipientInfo;
    private final boolean usePointCompression;

    public IESKEMParameterSpec(byte[] recipientInfo)
    {
        this(recipientInfo, false);
    }

    public IESKEMParameterSpec(byte[] recipientInfo, boolean usePointCompression)
    {
        this.recipientInfo = Arrays.clone(recipientInfo);
        this.usePointCompression = usePointCompression;
    }

    /** The KDF's shared info, or null when none was supplied. */
    public byte[] getRecipientInfo()
    {
        return Arrays.clone(recipientInfo);
    }

    /** Whether a wrap emits the ephemeral public key in compressed form. */
    public boolean hasUsePointCompression()
    {
        return usePointCompression;
    }
}
