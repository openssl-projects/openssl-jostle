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

package org.openssl.jostle.test.certpath;

import java.security.cert.CRL;
import java.security.cert.CRLSelector;
import java.security.cert.CertSelector;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.CertStoreSpi;
import java.security.cert.Certificate;
import java.security.cert.CollectionCertStoreParameters;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

/**
 * Test-local CertStores that belong to no provider: one that returns its objects in list order, so every
 * ordering of a pool reaches a builder (the Collection stores of JSL and SUN return a hash-ordered set, which
 * collapses the orderings), and one that throws on every read.
 */
final class OrderedCertStores
{
    private OrderedCertStores()
    {
    }

    /** A store returning the given certificates and CRLs in list order, filtered by the selector. */
    static CertStore ordered(List<?> objects) throws Exception
    {
        return new CertStore(new Ordered(new ArrayList<Object>(objects)), null, "Ordered",
                new CollectionCertStoreParameters())
        {
        };
    }

    /**
     * A store whose every read throws: CertStoreException when checked, else IllegalStateException. The
     * messages name the read, "certificates" or "CRLs".
     */
    static CertStore throwing(boolean checked) throws Exception
    {
        return new CertStore(new Throwing(checked), null, "Throwing", new CollectionCertStoreParameters())
        {
        };
    }

    /** Every ordering of the list, each a new list. */
    static <T> List<List<T>> permutations(List<T> in)
    {
        List<List<T>> out = new ArrayList<List<T>>();
        permute(new ArrayList<T>(in), 0, out);
        return out;
    }

    private static <T> void permute(List<T> in, int k, List<List<T>> out)
    {
        if (k == in.size())
        {
            out.add(new ArrayList<T>(in));
            return;
        }
        for (int i = k; i < in.size(); i++)
        {
            Collections.swap(in, k, i);
            permute(in, k + 1, out);
            Collections.swap(in, k, i);
        }
    }

    private static final class Ordered
        extends CertStoreSpi
    {
        private final List<Object> objects;

        Ordered(List<Object> objects) throws Exception
        {
            super(new CollectionCertStoreParameters());
            this.objects = objects;
        }

        @Override
        public Collection<? extends Certificate> engineGetCertificates(CertSelector selector)
        {
            List<Certificate> out = new ArrayList<Certificate>();
            for (Object o : objects)
            {
                if (o instanceof Certificate && (selector == null || selector.match((Certificate) o)))
                {
                    out.add((Certificate) o);
                }
            }
            return out;
        }

        @Override
        public Collection<? extends CRL> engineGetCRLs(CRLSelector selector)
        {
            List<CRL> out = new ArrayList<CRL>();
            for (Object o : objects)
            {
                if (o instanceof CRL && (selector == null || selector.match((CRL) o)))
                {
                    out.add((CRL) o);
                }
            }
            return out;
        }
    }

    private static final class Throwing
        extends CertStoreSpi
    {
        private final boolean checked;

        Throwing(boolean checked) throws Exception
        {
            super(new CollectionCertStoreParameters());
            this.checked = checked;
        }

        @Override
        public Collection<? extends Certificate> engineGetCertificates(CertSelector selector)
            throws CertStoreException
        {
            if (checked)
            {
                throw new CertStoreException("the store refuses to read certificates");
            }
            throw new IllegalStateException("the store broke reading certificates");
        }

        @Override
        public Collection<? extends CRL> engineGetCRLs(CRLSelector selector)
            throws CertStoreException
        {
            if (checked)
            {
                throw new CertStoreException("the store refuses to read CRLs");
            }
            throw new IllegalStateException("the store broke reading CRLs");
        }
    }
}
