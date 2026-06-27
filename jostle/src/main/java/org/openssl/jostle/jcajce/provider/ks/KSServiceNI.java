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

import org.openssl.jostle.jcajce.provider.DefaultServiceNI;

import java.io.IOException;
import java.security.KeyStoreException;

public interface KSServiceNI
    extends DefaultServiceNI
{
    long ni_allocateKeyStore(String type, int[] err);

    void ni_dispose(long ref);

    int ni_load(long ref, byte[] input, byte[] password);

    byte[] ni_store(long ref, byte[] password, int keyPbe, int certPbe, int macScheme,
                    int macDigest, int pbeIter, int macIter, int[] err);

    byte[] ni_getKey(long ref, String alias, byte[] password, int[] err);

    int ni_setKey(long ref, String alias, byte[] key, byte[] password);

    byte[] ni_getCertificateChain(long ref, String alias, int[] err);

    int ni_setCertificateChain(long ref, String alias, byte[] chain);

    int ni_setCertificateEntry(long ref, String alias, byte[] certificate);

    int ni_deleteEntry(long ref, String alias);

    byte[] ni_getAliases(long ref, int[] err);

    int ni_containsAlias(long ref, String alias);

    int ni_size(long ref);

    int ni_isKeyEntry(long ref, String alias);

    int ni_isCertificateEntry(long ref, String alias);

    long ni_getCreationDate(long ref, String alias, int[] err);

    default long allocateKeyStore(String type)
    {
        int[] err = new int[1];
        long v = ni_allocateKeyStore(type, err);
        handleErrors(err[0]);
        return v;
    }

    default void dispose(long ref)
    {
        ni_dispose(ref);
    }

    default void load(long ref, byte[] input, byte[] password)
        throws IOException
    {
        handleIoErrors(ni_load(ref, input, password));
    }

    default byte[] store(long ref, byte[] password,
                         int keyPbe, int certPbe, int macScheme, int macDigest,
                         int pbeIter, int macIter)
        throws IOException
    {
        int[] err = new int[1];
        byte[] out = ni_store(ref, password, keyPbe, certPbe, macScheme,
                macDigest, pbeIter, macIter, err);
        handleIoErrors(err[0]);
        return out;
    }

    default byte[] getKey(long ref, String alias, byte[] password)
        throws KeyStoreException
    {
        int[] err = new int[1];
        byte[] key = ni_getKey(ref, alias, password, err);
        handleKeyStoreErrors(err[0]);
        return key;
    }

    default void setKey(long ref, String alias, byte[] key, byte[] password)
        throws KeyStoreException
    {
        handleKeyStoreErrors(ni_setKey(ref, alias, key, password));
    }

    default byte[] getCertificateChain(long ref, String alias)
        throws KeyStoreException
    {
        int[] err = new int[1];
        byte[] chain = ni_getCertificateChain(ref, alias, err);
        handleKeyStoreErrors(err[0]);
        return chain;
    }

    default void setCertificateChain(long ref, String alias, byte[] chain)
        throws KeyStoreException
    {
        handleKeyStoreErrors(ni_setCertificateChain(ref, alias, chain));
    }

    default void setCertificateEntry(long ref, String alias, byte[] certificate)
        throws KeyStoreException
    {
        handleKeyStoreErrors(ni_setCertificateEntry(ref, alias, certificate));
    }

    default void deleteEntry(long ref, String alias)
        throws KeyStoreException
    {
        handleKeyStoreErrors(ni_deleteEntry(ref, alias));
    }

    default byte[] getAliases(long ref)
        throws KeyStoreException
    {
        int[] err = new int[1];
        byte[] aliases = ni_getAliases(ref, err);
        handleKeyStoreErrors(err[0]);
        return aliases;
    }

    default boolean containsAlias(long ref, String alias)
    {
        return handleErrors(ni_containsAlias(ref, alias)) != 0;
    }

    default int size(long ref)
    {
        return (int)handleErrors(ni_size(ref));
    }

    default boolean isKeyEntry(long ref, String alias)
    {
        return handleErrors(ni_isKeyEntry(ref, alias)) != 0;
    }

    default boolean isCertificateEntry(long ref, String alias)
    {
        return handleErrors(ni_isCertificateEntry(ref, alias)) != 0;
    }

    default long getCreationDate(long ref, String alias)
        throws KeyStoreException
    {
        int[] err = new int[1];
        long creationDate = ni_getCreationDate(ref, alias, err);
        handleKeyStoreErrors(err[0]);
        return creationDate;
    }

    default long handleIoErrors(long code)
        throws IOException
    {
        try
        {
            return handleErrors(code);
        }
        catch (RuntimeException e)
        {
            IOException ioe = new IOException(e.getMessage());
            ioe.initCause(e);
            throw ioe;
        }
    }

    default long handleErrors(long code)
    {
        if (code >= 0)
        {
            return code;
        }

        return baseErrorHandler(code);
    }

    default long handleKeyStoreErrors(long code)
        throws KeyStoreException
    {
        try
        {
            return handleErrors(code);
        }
        catch (RuntimeException e)
        {
            KeyStoreException kse = new KeyStoreException(e.getMessage());
            kse.initCause(e);
            throw kse;
        }
    }
}
