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

import org.openssl.jostle.jcajce.provider.blockcipher.IvAlgorithmParameters;
import org.openssl.jostle.jcajce.provider.blockcipher.DESedeBlockCipherSpi;
import org.openssl.jostle.jcajce.provider.blockcipher.DESedeKeyGenerator;
import org.openssl.jostle.jcajce.provider.blockcipher.OSSLCipher;
import org.openssl.jostle.jcajce.provider.blockcipher.OSSLMode;

import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * 3-key Triple DES (DES-EDE3) registrations for the FIPS provider, mirroring
 * ProvDESede's Cipher and KeyGenerator surface bound to the FIPS interface
 * library. ECB and CBC only, as in the base registrar — the CFB* and OFB
 * DES-EDE3 variants live in OpenSSL's legacy provider.
 *
 * <p><b>Registered only when the loaded module serves the cipher.</b> The two
 * supported modules disagree, and it is a module-VERSION difference rather
 * than a fipsinstall configuration one — measured across all three supported
 * configurations by {@code fips-c-review/probes/tdes_gate_probe.c}:
 *
 * <pre>
 *   3.1.2               : EVP_CIPHER_fetch = 0  -&gt; nothing registered
 *   3.5.8 default       : fetch = 1, provider=fips, encrypt AND decrypt run
 *   3.5.8 -pedantic     : fetch = 1, provider=fips, decrypt runs, ENCRYPT refused
 * </pre>
 *
 * <p><b>The gate is registration-only, and deliberately so.</b> The fetch
 * answers "does this module implement Triple-DES at all", which is the
 * question {@code getInstance} must answer; it cannot see the
 * {@code tdes-encrypt-disabled} fipsinstall switch, which refuses the encrypt
 * direction at operation time and raises nothing while doing it. That half is
 * classified where it fails — {@code classify_tdes_encrypt_init_failure} in
 * {@code block_cipher_ctx.c} re-drives both directions and returns
 * {@code JO_TDES_ENCRYPT_UNAVAILABLE} when encrypt refuses while decrypt
 * accepts — and surfaces as {@code InvalidKeyException} carrying the
 * capability message from {@code Cipher.init}. Decryption works on every
 * configuration, so withholding the whole family because one direction may be
 * gated would remove a working service from callers.
 *
 * <p>This is <b>capability</b> filtering, not <b>approval</b> filtering.
 * SP 800-131A disallows Triple-DES <i>encryption</i> and keeps decryption
 * available for legacy data; that determination belongs to the operator, and
 * JSLFIPS serves what the module serves.
 */
class ProvFIPSDESede
{
    private static final Logger LOG = Logger.getLogger(ProvFIPSDESede.class.getName());

    /**
     * PKCS#9 OID for {@code des-EDE3-CBC}, as in {@code ProvDESede}.
     */
    private static final String DES_EDE3_CBC_OID = "1.2.840.113549.3.7";


    private static final Map<String, String> generalAttributes = new HashMap<String, String>();

    static
    {
        generalAttributes.put("SupportedKeyClasses", "javax.crypto.SecretKey");
        generalAttributes.put("SupportedKeyFormats", "RAW");
    }

    public void configure(final JostleFIPSProvider provider)
    {
        if (!FIPSCapabilities.canFetchCipher("DES-EDE3-CBC"))
        {
            return;
        }

        // Bare "DESede" — JCE form-4 fallback: engineSetMode / engineSetPadding
        // run with whatever the caller put in the transformation string.
        safeRegister("Cipher.DESede", () ->
                provider.addAlgorithmImplementation("Cipher", "DESede", DESedeBlockCipherSpi.class.getName(),
                        generalAttributes, (arg) -> new DESedeBlockCipherSpi(FIPSNISelector.BlockCipherNI, provider)));

        safeRegister("Cipher.TripleDES (alias of DESede)", () ->
                provider.addAlias("Cipher", "DESede", "TripleDES"));

        // OID alias for DES-EDE3-CBC — a distinct primary with the mode
        // pre-set, because a transformation alias on the bare "DESede" would
        // match JCE form 1 and never call engineSetMode (java-spi.md,
        // "form-1 alias vs form-4 fallback").
        safeRegister("Cipher." + DES_EDE3_CBC_OID + " (OID, CBC-locked)", () ->
                provider.addAlgorithmImplementation("Cipher", DES_EDE3_CBC_OID,
                        DESedeBlockCipherSpi.class.getName(), generalAttributes,
                        (arg) -> new DESedeBlockCipherSpi(FIPSNISelector.BlockCipherNI,
                                OSSLCipher.DES_EDE3, OSSLMode.CBC, provider)));

        // Key bytes come from the module's own approved DRBG (the provider's
        // DEFAULT SecureRandom service) rather than a JDK SecureRandom.
        safeRegister("KeyGenerator.DESede", () ->
                provider.addAlgorithmImplementation("KeyGenerator", "DESede",
                        DESedeKeyGenerator.class.getName(), generalAttributes,
                        (arg) -> new DESedeKeyGenerator(provider.getDefaultSecureRandom())));
        safeRegister("KeyGenerator.TripleDES (alias of DESede)", () ->
                provider.addAlias("KeyGenerator", "DESede", "TripleDES"));
        // IV AlgorithmParameters under the bare family name; BlockCipherSpi
        // resolves it from THIS provider instance, so JSLFIPS serves its own.
        provider.addAlgorithmImplementation("AlgorithmParameters", "DESede",
                IvAlgorithmParameters.class.getName(), generalAttributes, (arg) -> new IvAlgorithmParameters());
    }

    /**
     * Run a single registration call, swallowing and logging any
     * {@link Throwable} so the rest of {@link #configure} continues — see
     * {@code ProvDESede.safeRegister} for why one bad registration must not
     * take the whole provider down.
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
                    "ProvFIPSDESede: skipped " + description + " — " + t.getMessage(),
                    t);
        }
    }
}
