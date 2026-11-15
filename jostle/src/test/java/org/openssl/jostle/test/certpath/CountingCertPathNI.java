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

import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.jcajce.provider.certpath.CertPathNI;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * A CertPathNI that forwards to the real one, counts the OpenSSL verify calls made through it and keeps the
 * certificates of the last call.
 */
final class CountingCertPathNI
{
    final CertPathNI ni;
    private int calls;
    /** The certificates of the last call, as marshalled: anchors, then the untrusted ones, then the target. */
    List<byte[]> lastCerts = new ArrayList<byte[]>();
    /** The anchors at the head of {@link #lastCerts}. */
    int lastAnchors;
    /** Each call's X509_V_ERR code and error depth, in call order, since the last {@link #take}. */
    final List<String> errors = new ArrayList<String>();

    CountingCertPathNI()
    {
        final CertPathNI real = NISelector.CertPathNI;
        ni = (CertPathNI) Proxy.newProxyInstance(CountingCertPathNI.class.getClassLoader(),
                new Class<?>[]{CertPathNI.class}, new InvocationHandler()
                {
                    public Object invoke(Object proxy, Method m, Object[] args) throws Throwable
                    {
                        if ("ni_verify".equals(m.getName()))
                        {
                            calls++;
                            byte[] der = (byte[]) args[0];
                            int[] sizes = (int[]) args[1];
                            int count = (Integer) args[2];
                            List<byte[]> certs = new ArrayList<byte[]>();
                            int off = 0;
                            for (int i = 0; i < count; i++)
                            {
                                certs.add(Arrays.copyOfRange(der, off, off + sizes[i]));
                                off += sizes[i];
                            }
                            lastCerts = certs;
                            lastAnchors = (Integer) args[4];
                        }
                        try
                        {
                            Object out = m.invoke(real, args);
                            if ("ni_verify".equals(m.getName()))
                            {
                                int[] info = (int[]) args[12];
                                errors.add(info[0] + "@" + info[1]);
                            }
                            return out;
                        }
                        catch (InvocationTargetException e)
                        {
                            throw e.getCause();
                        }
                    }
                });
    }

    /** The calls counted since the last read, and a reset. */
    int take()
    {
        int n = calls;
        calls = 0;
        errors.clear();
        return n;
    }
}
