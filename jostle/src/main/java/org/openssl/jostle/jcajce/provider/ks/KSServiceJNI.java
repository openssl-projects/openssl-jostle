/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider.ks;

public class KSServiceJNI
    implements KSServiceNI
{
    @Override
    public native long ni_allocateKeyStore(String type, int[] err);

    @Override
    public native void ni_dispose(long ref);

    @Override
    public native int ni_load(long ref, byte[] input, byte[] password);

    @Override
    public native byte[] ni_store(long ref, byte[] password, int keyPbe, int certPbe, int macScheme,
                                  int macDigest, int pbeIter, int macIter, int[] err);

    @Override
    public native byte[] ni_getKey(long ref, String alias, byte[] password, int[] err);

    @Override
    public native int ni_setKey(long ref, String alias, byte[] key, byte[] password);

    @Override
    public native byte[] ni_getCertificateChain(long ref, String alias, int[] err);

    @Override
    public native int ni_setCertificateChain(long ref, String alias, byte[] chain);

    @Override
    public native int ni_setCertificateEntry(long ref, String alias, byte[] certificate);

    @Override
    public native int ni_deleteEntry(long ref, String alias);

    @Override
    public native byte[] ni_getAliases(long ref, int[] err);

    @Override
    public native int ni_containsAlias(long ref, String alias);

    @Override
    public native int ni_size(long ref);

    @Override
    public native int ni_isKeyEntry(long ref, String alias);

    @Override
    public native int ni_isCertificateEntry(long ref, String alias);

    @Override
    public native long ni_getCreationDate(long ref, String alias, int[] err);
}
