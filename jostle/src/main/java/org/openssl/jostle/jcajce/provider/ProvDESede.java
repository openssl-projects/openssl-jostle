/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider;


import org.openssl.jostle.jcajce.provider.blockcipher.DESedeBlockCipherSpi;
import org.openssl.jostle.jcajce.provider.blockcipher.DESedeKeyGenerator;
import org.openssl.jostle.jcajce.provider.blockcipher.OSSLCipher;
import org.openssl.jostle.jcajce.provider.blockcipher.OSSLMode;

import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Registers 3-key Triple DES (DES-EDE3) with JCE. Only the ECB and
 * CBC mode wirings appear here — OpenSSL 3.5 keeps those in its
 * default provider; CFB*, OFB and the 2-key DES-EDE variants live in
 * the legacy provider and are intentionally out of scope.
 */
class ProvDESede
{
    private static final Logger LOG = Logger.getLogger(ProvDESede.class.getName());

    private static final Map<String, String> generalAttributes = new HashMap<String, String>();

    static
    {
        generalAttributes.put("SupportedKeyClasses", "javax.crypto.SecretKey");
        generalAttributes.put("SupportedKeyFormats", "RAW");
    }

    /**
     * PKCS#9 OID for {@code des-EDE3-CBC} from RSA Labs.
     * Registering the OID as a Cipher alias lets PKCS#8 / PKCS#12
     * parsing routines that look up a cipher by OID find this impl.
     */
    private static final String DES_EDE3_CBC_OID = "1.2.840.113549.3.7";

    private static final String PREFIX = ProvDESede.class.getName();

    public void configure(final JostleProvider provider)
    {
        // CLAUDE.md "Provider registration: resilient configure()":
        // wrap each registration so one failure doesn't break the
        // rest of the provider — a Prov<NAME>.configure that throws
        // would take the whole provider down with
        // ExceptionInInitializerError, and the JVM never retries a
        // failed class initializer.

        // Bare "DESede" — JCE form-4 fallback path: engineSetMode and
        // engineSetPadding will be called with whatever the caller
        // specified in the transformation string.
        safeRegister("Cipher.DESede", () ->
                provider.addAlgorithmImplementation("Cipher", "DESede", PREFIX + "Base",
                        generalAttributes, (arg) -> new DESedeBlockCipherSpi()));

        // "TripleDES" is the JCE-standard alias.
        safeRegister("Cipher.TripleDES (alias of DESede)", () ->
                provider.addAlias("Cipher", "DESede", "TripleDES"));

        // OID alias for DES-EDE3-CBC — bound to a pre-configured SPI
        // with the CBC mode locked in. See the CLAUDE.md "form-1 alias
        // vs form-4 fallback" note: registering an OID alias on the
        // bare "DESede" wouldn't run engineSetMode, so we register a
        // distinct primary SPI for the OID with the mode pre-set.
        safeRegister("Cipher." + DES_EDE3_CBC_OID + " (OID, CBC-locked)", () ->
                provider.addAlgorithmImplementation("Cipher", DES_EDE3_CBC_OID,
                        PREFIX + "DESedeCBC", generalAttributes,
                        (arg) -> new DESedeBlockCipherSpi(OSSLCipher.DES_EDE3, OSSLMode.CBC)));

        safeRegister("KeyGenerator.DESede", () ->
                provider.addAlgorithmImplementation("KeyGenerator", "DESede",
                        PREFIX + "KeyGen", generalAttributes, (arg) -> new DESedeKeyGenerator()));
        safeRegister("KeyGenerator.TripleDES (alias of DESede)", () ->
                provider.addAlias("KeyGenerator", "DESede", "TripleDES"));
    }

    /**
     * Run a single algorithm-registration call, swallowing and logging
     * any {@link Throwable} so the rest of {@link #configure} continues.
     * A {@code ExceptionInInitializerError} from a single bad
     * registration would otherwise leave the entire provider unloaded
     * — and the JVM doesn't retry a failed class initializer for the
     * lifetime of the process.
     */
    private static void safeRegister(String description, Runnable r)
    {
        try
        {
            r.run();
        }
        catch (Throwable t)
        {
            LOG.log(Level.WARNING,
                    "ProvDESede: skipped " + description + " — " + t.getMessage(),
                    t);
        }
    }
}
