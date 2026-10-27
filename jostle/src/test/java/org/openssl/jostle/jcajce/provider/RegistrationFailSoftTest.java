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

package org.openssl.jostle.jcajce.provider;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.Security;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

/**
 * A family whose registration throws is logged and skipped; the provider's other families stay registered. In the
 * provider package because the registrars are package-private.
 */
public class RegistrationFailSoftTest
{
    /** The registrars probe the native library, which only a constructed provider loads. */
    @BeforeAll
    public static void before()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    /** A bare provider that refuses any registration whose name starts with the given prefix. */
    private static final class RefusingProvider
            extends JostleProvider
    {
        private final String refusedPrefix;

        RefusingProvider(String refusedPrefix)
        {
            super("JSL-FAILSOFT", 1.0, "registration fail-soft test");
            this.refusedPrefix = refusedPrefix;
        }

        @Override
        public void addAlgorithmImplementation(String type, String name, String className,
                                               Map<String, String> attributes, EngineCreator creator)
        {
            if (name.toUpperCase().startsWith(refusedPrefix))
            {
                throw new IllegalStateException("refused " + type + "." + name);
            }
            super.addAlgorithmImplementation(type, name, className, attributes, creator);
        }
    }

    private static final class Recorder
            extends Handler
    {
        final List<LogRecord> records = new ArrayList<LogRecord>();

        @Override
        public void publish(LogRecord record)
        {
            records.add(record);
        }

        @Override
        public void flush()
        {
        }

        @Override
        public void close()
        {
        }
    }

    private static List<LogRecord> configureBoth(JostleProvider provider, String refusedLogger)
    {
        Logger logger = Logger.getLogger(refusedLogger);
        Recorder recorder = new Recorder();
        logger.addHandler(recorder);
        try
        {
            new ProvMLDSA().configure(provider);
            new ProvSLHDSA().configure(provider);
        }
        finally
        {
            logger.removeHandler(recorder);
        }
        return recorder.records;
    }

    @Test
    public void aRefusedSlhDsaRegistrationLeavesMlDsaRegistered()
    {
        RefusingProvider provider = new RefusingProvider("SLH");
        List<LogRecord> records = configureBoth(provider, ProvSLHDSA.class.getName());

        Assertions.assertNotNull(provider.getService("Signature", "ML-DSA-65"));
        Assertions.assertNotNull(provider.getService("KeyPairGenerator", "ML-DSA"));
        Assertions.assertNull(provider.getService("Signature", "SLH-DSA-SHA2-128F"));

        Assertions.assertEquals(1, records.size());
        Assertions.assertEquals(Level.WARNING, records.get(0).getLevel());
        Assertions.assertEquals("SLH-DSA provider registration failed; SLH-DSA algorithms will be unavailable",
                records.get(0).getMessage());
        Assertions.assertEquals(IllegalStateException.class, records.get(0).getThrown().getClass());
    }

    @Test
    public void aRefusedMlDsaRegistrationLeavesSlhDsaRegistered()
    {
        RefusingProvider provider = new RefusingProvider("ML");
        List<LogRecord> records = configureBoth(provider, ProvMLDSA.class.getName());

        Assertions.assertNotNull(provider.getService("Signature", "SLH-DSA-SHA2-128F"));
        Assertions.assertNotNull(provider.getService("KeyPairGenerator", "SLH-DSA"));
        Assertions.assertNull(provider.getService("Signature", "ML-DSA-65"));

        Assertions.assertEquals(1, records.size());
        Assertions.assertEquals(Level.WARNING, records.get(0).getLevel());
        Assertions.assertEquals("ML-DSA provider registration failed; ML-DSA algorithms will be unavailable",
                records.get(0).getMessage());
        Assertions.assertEquals(IllegalStateException.class, records.get(0).getThrown().getClass());
    }

    /** Control: nothing refused, both families register and nothing is logged. */
    @Test
    public void withNothingRefusedBothFamiliesRegister()
    {
        RefusingProvider provider = new RefusingProvider("NO-SUCH-PREFIX");
        List<LogRecord> slh = configureBoth(provider, ProvSLHDSA.class.getName());

        Assertions.assertNotNull(provider.getService("Signature", "ML-DSA-65"));
        Assertions.assertNotNull(provider.getService("Signature", "SLH-DSA-SHA2-128F"));
        Assertions.assertTrue(slh.isEmpty());
    }
}
