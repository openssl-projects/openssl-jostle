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

package org.openssl.jostle.jcajce.provider.certpath;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CRL;
import java.security.cert.CRLSelector;
import java.security.cert.CertSelector;
import java.security.cert.CertStoreException;
import java.security.cert.CertStoreParameters;
import java.security.cert.CertStoreSpi;
import java.security.cert.Certificate;
import java.security.cert.CollectionCertStoreParameters;
import java.util.Collection;
import java.util.ConcurrentModificationException;
import java.util.HashSet;
import java.util.Set;

/**
 * The JCA Collection CertStore: certificates and CRLs drawn from a caller's collection by the standard selectors.
 *
 * <p>The collection is not copied: as CollectionCertStoreParameters specifies, later changes to it are seen by later
 * queries. Objects that are neither a Certificate nor a CRL, and null elements, are ignored. A null selector selects
 * every object of the asked kind. Each query returns a new, mutable set. A selector's own exception passes through,
 * except ConcurrentModificationException, which is taken for a modification of the collection, as by the JDK's store.
 *
 * <p>Concurrent queries are safe; nothing more is promised under concurrent modification. A scan that meets a
 * ConcurrentModificationException is retried as described below; any other behaviour is the collection's own.
 */
public class JostleCollectionCertStoreSpi
    extends CertStoreSpi
{
    /** A scan that meets a concurrent modification is retried, up to this many scans in all, as the JDK's store. */
    static final int MAX_SCANS = 10;

    static final String PARAMETERS_REFUSAL = "parameters must be CollectionCertStoreParameters";

    private final Collection<?> collection;

    public JostleCollectionCertStoreSpi(CertStoreParameters params)
        throws InvalidAlgorithmParameterException
    {
        super(params);
        if (!(params instanceof CollectionCertStoreParameters))
        {
            throw new InvalidAlgorithmParameterException(PARAMETERS_REFUSAL);
        }
        this.collection = ((CollectionCertStoreParameters) params).getCollection();
    }

    /**
     * The registration's constructor. A parameters object of the wrong kind is reported as
     * InvalidAlgorithmParameterException inside NoSuchAlgorithmException, the shape CertStore.getInstance unwraps.
     */
    public static JostleCollectionCertStoreSpi create(Object params)
        throws NoSuchAlgorithmException
    {
        try
        {
            if (params != null && !(params instanceof CertStoreParameters))
            {
                throw new InvalidAlgorithmParameterException(PARAMETERS_REFUSAL);
            }
            return new JostleCollectionCertStoreSpi((CertStoreParameters) params);
        }
        catch (InvalidAlgorithmParameterException e)
        {
            NoSuchAlgorithmException wrapped = new NoSuchAlgorithmException(e.getMessage());
            wrapped.initCause(e);
            throw wrapped;
        }
    }

    @Override
    public Collection<? extends Certificate> engineGetCertificates(CertSelector selector)
        throws CertStoreException
    {
        for (int scan = 0; scan < MAX_SCANS; scan++)
        {
            try
            {
                Set<Certificate> selected = new HashSet<Certificate>();
                for (Object o : collection)
                {
                    if (o instanceof Certificate && (selector == null || selector.match((Certificate) o)))
                    {
                        selected.add((Certificate) o);
                    }
                }
                return selected;
            }
            catch (ConcurrentModificationException e)
            {
                // Scan again from the start.
            }
        }
        throw new ConcurrentModificationException("Too many ConcurrentModificationExceptions");
    }

    @Override
    public Collection<? extends CRL> engineGetCRLs(CRLSelector selector)
        throws CertStoreException
    {
        for (int scan = 0; scan < MAX_SCANS; scan++)
        {
            try
            {
                Set<CRL> selected = new HashSet<CRL>();
                for (Object o : collection)
                {
                    if (o instanceof CRL && (selector == null || selector.match((CRL) o)))
                    {
                        selected.add((CRL) o);
                    }
                }
                return selected;
            }
            catch (ConcurrentModificationException e)
            {
                // Scan again from the start.
            }
        }
        throw new ConcurrentModificationException("Too many ConcurrentModificationExceptions");
    }
}
