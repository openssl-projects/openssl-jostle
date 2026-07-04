/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider.fips;

import org.openssl.jostle.CryptoServicesRegistrar;
import org.openssl.jostle.util.ConfigParser;
import org.openssl.jostle.util.Properties;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Provider;
import java.util.Map;

/**
 * The Jostle FIPS provider ("JSLFIPS"): backs its services with the OpenSSL
 * FIPS provider module, loaded into a dedicated FIPS-only lib ctx inside the
 * FIPS interface library. It coexists with the non-FIPS JostleProvider
 * ("JSL") in the same JVM - each runs on its own interface library and lib
 * ctx - so users arrange provider preference by JCA registration order.
 *
 * <p><b>Configuration.</b> The provider needs to know where the OpenSSL FIPS
 * module lives. The configuration string is a {@link ConfigParser}
 * comma-separated key=value list (values may be quoted with ", ' or `, and
 * resolve via the file:, prop:, env: and str: schemes):
 * <ol>
 *   <li>{@code fips_module} - REQUIRED. Path to the FIPS provider module
 *       (e.g. {@code .../ossl-modules/fips.dylib}). The module search path is
 *       its parent directory and the provider name its file name minus
 *       extension.</li>
 *   <li>{@code fips_config} - OPTIONAL. Path to the fipsinstall-generated
 *       config carrying the module-mac. Defaults to {@code fipsmodule.cnf}
 *       in the module's directory.</li>
 * </ol>
 *
 * <p>Pass it via {@link #configure(String)} (the {@code java.security}
 * static-registration argument uses the same path), the String constructor,
 * or - for the no-arg constructor - the {@code org.openssl.jostle.fips.config}
 * property (java.security property, thread-local override, or system
 * property). A no-arg construction with no property remains unconfigured and
 * registers no services.
 *
 * <p>Example: {@code new JostleFIPSProvider("fips_module='/opt/openssl-fips/lib/ossl-modules/fips.so'")}
 *
 * <p>The FIPS module itself is loaded by libcrypto (which verifies the
 * module's integrity MAC and runs its self-tests) - never by the JVM. The
 * initialisation is one-shot per JVM: constructing a second provider with the
 * identical configuration is a no-op; a different configuration throws
 * IllegalStateException.
 */
public final class JostleFIPSProvider
    extends Provider
{
    public static final String PROVIDER_NAME = "JSLFIPS";
    public static final String INFO = "Jostle FIPS Provider for OpenSSL v1.0.0-SNAPSHOT";
    private static final double VERSION = 0.1;

    /**
     * Property consulted by the no-arg constructor for the configuration
     * string (java.security property, thread-local override, then system
     * property).
     */
    public static final String FIPS_CONFIG_PROPERTY = "org.openssl.jostle.fips.config";

    /**
     * Configuration key: path to the FIPS provider module. Required.
     */
    public static final String CONFIG_KEY_MODULE = "fips_module";

    /**
     * Configuration key: path to the fipsinstall-generated config file.
     * Optional - defaults to fipsmodule.cnf beside the module.
     */
    public static final String CONFIG_KEY_CONFIG = "fips_config";

    private static final String DEFAULT_CONFIG_FILE_NAME = "fipsmodule.cnf";

    private final boolean configured;

    public JostleFIPSProvider()
    {
        super(PROVIDER_NAME, VERSION, INFO);

        String config = Properties.getPropertyValue(FIPS_CONFIG_PROPERTY);
        if (config != null)
        {
            init(config);
            configured = true;
        }
        else
        {
            configured = false;
        }
    }

    public JostleFIPSProvider(String config)
    {
        super(PROVIDER_NAME, VERSION, INFO);

        if (config == null)
        {
            throw new NullPointerException("config was null");
        }

        init(config);
        configured = true;
    }

    // Overrides java.security.Provider.configure at runtime on JDK 9+ (no
    // @Override: the method does not exist in the Java 8 API this baseline
    // compiles against).
    public Provider configure(String configArg)
    {
        return new JostleFIPSProvider(configArg);
    }

    // Overrides java.security.Provider.isConfigured at runtime on JDK 9+.
    public boolean isConfigured()
    {
        return configured;
    }

    private void init(String config)
    {
        // All file-path handling happens here on the Java side; the native
        // layer receives the resolved module directory, provider name and
        // config path.
        Map<String, String> parsed = ConfigParser.parse(config);

        String module = parsed.get(CONFIG_KEY_MODULE);
        if (module == null || module.isEmpty())
        {
            throw new IllegalArgumentException(String.format(
                    "config requires '%s' (path to the OpenSSL FIPS provider module)", CONFIG_KEY_MODULE));
        }

        Path modulePath = Paths.get(module);
        Path moduleDir = modulePath.getParent();
        if (moduleDir == null)
        {
            throw new IllegalArgumentException(String.format(
                    "'%s' must include the module's parent directory: %s", CONFIG_KEY_MODULE, module));
        }

        Path fileName = modulePath.getFileName();
        String moduleFile = fileName == null ? "" : fileName.toString();
        int extension = moduleFile.lastIndexOf('.');
        String providerName = extension > 0 ? moduleFile.substring(0, extension) : moduleFile;
        if (providerName.isEmpty())
        {
            throw new IllegalArgumentException(String.format(
                    "'%s' has no module file name: %s", CONFIG_KEY_MODULE, module));
        }

        String configPath = parsed.get(CONFIG_KEY_CONFIG);
        if (configPath == null || configPath.isEmpty())
        {
            configPath = moduleDir.resolve(DEFAULT_CONFIG_FILE_NAME).toString();
        }

        synchronized (JostleFIPSProvider.class)
        {
            //
            // Will trigger loading of native libraries
            //
            CryptoServicesRegistrar.assertNativeAvailable();

            // One-shot: no-op on an identical repeat configuration, throws on
            // a different one. Maps JO_FIPS_* codes to typed exceptions.
            FIPSOpenSSL.initialise(moduleDir.toString(), providerName, configPath);
        }

        // Service registration (the FIPS-approved algorithm set) lands with
        // the FIPS NI families.
    }
}
