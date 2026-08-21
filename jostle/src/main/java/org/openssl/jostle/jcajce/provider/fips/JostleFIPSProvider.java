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
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.util.AccessSupplier;
import org.openssl.jostle.util.AccessWrapper;
import org.openssl.jostle.util.ConfigParser;
import org.openssl.jostle.util.Properties;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.ProviderException;
import java.security.SecureRandom;
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
    extends JostleProvider
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


    private transient SecureRandom defaultSecureRandom;

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

        AccessWrapper.doAction(new AccessSupplier()
        {
            @Override
            public Object run()
            {
                setup();
                return null;
            }
        });
    }

    /**
     * The provider's default SecureRandom - the FIPS module's DRBG via this
     * provider's own "DEFAULT" SecureRandom service - cached because
     * SecureRandom acquisition is expensive. Used by the ProvFIPS*
     * registrations that need key-generation entropy.
     */
    synchronized SecureRandom getDefaultSecureRandom()
    {
        if (defaultSecureRandom == null)
        {
            try
            {
                defaultSecureRandom = SecureRandom.getInstance("DEFAULT", this);
            }
            catch (NoSuchAlgorithmException e)
            {
                throw new ProviderException("JSLFIPS DEFAULT SecureRandom unavailable", e);
            }
        }
        return defaultSecureRandom;
    }

    /**
     * The loaded FIPS module's self-reported name and version, e.g.
     * {@code "OpenSSL FIPS Provider 3.1.2"}, or {@code "unknown FIPS module"}
     * when it cannot be queried.
     *
     * <p><b>Diagnostics only.</b> Nothing in this provider branches on it —
     * a version names the build, not the capability, and keying behaviour on
     * one is the transcribed table {@code java-spi.md} forbids (see
     * {@link FIPSCapabilities}). It is exposed because it is the first thing
     * to check when JSLFIPS serves a different surface than expected: the
     * validated 3.1.2 module and a 3.5.x one disagree about what they
     * implement. Only meaningful after the provider has been configured.
     */
    public static String moduleDescription()
    {
        return FIPSCapabilities.describeModule();
    }

    private void setup()
    {
        // JSLFIPS exposes what the FIPS MODULE SERVES, not a subset filtered
        // against the security policy's approved-services tables. The module is
        // the arbiter of what is available: its implementations carry a fips=yes
        // or fips=no property and the lib ctx's fips=yes default property query
        // is what excludes the latter, so Triple-DES, ChaCha20 and OCB (for
        // example) fail at the native fetch without any Java-side list.
        //
        // We deliberately do NOT filter further. Whether a given operation is
        // FIPS-APPROVED is a determination about compliance, per cert #4985's
        // policy, and it is the operator's to make: the module does not enforce
        // its own validated envelope (it signs happily with a 3072-bit key
        // through a service the policy caps at 2048), 3.1.2 exposes no runtime
        // approved-mode indicator, and the policy's non-approved entries are
        // usage-scoped (HMAC key length, X963KDF PRF choice) rather than
        // per-service — so no registration surface could express them. A
        // hand-maintained approved-subset was a second, drift-prone copy of a
        // determination we cannot make correctly, and mistakes in it removed
        // working algorithms from callers. See SERVICES.md.
        //
        // A registrar MAY still decline to register when the loaded module
        // cannot perform the algorithm AT ALL — that is capability, not
        // approval, and it is decided by asking this module rather than by a
        // compiled-in list (JSLFIPS serves one build against both the
        // validated 3.1.2 and a future 3.5.x, which disagree in both
        // directions). ProvFIPSXDH is the only such registrar today; see
        // FIPSCapabilities for the scoping rule that keeps it that way, and
        // note this runs AFTER FIPSOpenSSL.initialise above, so the lib ctx
        // the probes query already exists.
        new ProvFIPSMD().configure(this);
        new ProvFIPSAES().configure(this);
        new ProvFIPSMac().configure(this);
        new ProvFIPSRand().configure(this);
        new ProvFIPSRSA().configure(this);
        new ProvFIPSEC().configure(this);
        new ProvFIPSDSA().configure(this);
        new ProvFIPSDH().configure(this);
        new ProvFIPSKDF().configure(this);
        new ProvFIPSXDH().configure(this);
        // No PKCS#12 KeyStore registrar. This is a module capability limit, not
        // an approval judgement: the traditional PKCS#12 integrity MAC derives
        // its key with PKCS12KDF, which OpenSSL registers in the DEFAULT
        // provider only (the FIPS provider serves HKDF, TLS13-KDF, SSKDF,
        // PBKDF2, SSHKDF, X963KDF, X942KDF, TLS1-PRF, KBKDF, CTR-DRBG). The
        // consequence is not merely that we cannot WRITE a conventional
        // keystore - we cannot READ one either, whoever wrote it, because
        // verifying its MAC needs that KDF. Only RFC 9579 PBMAC1 keystores
        // (PBKDF2-derived MAC key) work, and those are rare and recent.
        //
        // Registering the service would therefore offer callers something that
        // fails on essentially every .p12 they already have, which is worse than
        // its absence. JSL serves PKCS#12; use it, or a PBMAC1 keystore.
        // CertificateFactory: structure parsing is not a cryptographic service;
        // the registration is provider-bound so keys and verification flowing
        // from parsed certificates stay inside the FIPS boundary (fail-loud on
        // algorithms the module does not serve). See ProvFIPSX509.
        new ProvFIPSX509().configure(this);
        // A deployment needing to restrict this provider's surface should use the
        // JVM's own mechanism (jdk.security.providers.filter) rather than expect
        // JSLFIPS to withhold what the module implements.
    }
}
