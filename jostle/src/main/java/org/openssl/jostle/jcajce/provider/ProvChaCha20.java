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


import org.openssl.jostle.jcajce.provider.blockcipher.ChaCha20BlockCipherSpi;
import org.openssl.jostle.jcajce.provider.blockcipher.ChaCha20KeyGenerator;
import org.openssl.jostle.jcajce.provider.blockcipher.ChaCha20Poly1305CipherSpi;

import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Registers ChaCha20 (RFC 8439 raw stream cipher), ChaCha20-Poly1305 (RFC 8439
 * AEAD), and the shared 256-bit KeyGenerator with JCE.
 */
class ProvChaCha20
{
    private static final Logger LOG = Logger.getLogger(ProvChaCha20.class.getName());

    private static final Map<String, String> generalAttributes = new HashMap<String, String>();

    static
    {
        generalAttributes.put("SupportedKeyClasses", "javax.crypto.SecretKey");
        generalAttributes.put("SupportedKeyFormats", "RAW");
    }

    /**
     * RFC 8103 {@code id-alg-AEADChaCha20Poly1305} (the S/MIME / CMS OID for
     * ChaCha20-Poly1305). Registered as a Cipher and KeyGenerator alias so
     * OID-driven consumers resolve these implementations. No JOID class hosts
     * it, so it is an inline constant (the ProvDESede precedent).
     */
    private static final String CHACHA20_POLY1305_OID = "1.2.840.113549.1.9.16.3.18";

    private static final String PREFIX = ProvChaCha20.class.getName();

    public void configure(final JostleProvider provider)
    {
        // CLAUDE.md "resilient configure()": wrap each registration so one
        // failure (e.g. a missing native symbol) doesn't take the whole
        // provider down with ExceptionInInitializerError.

        // Raw ChaCha20 stream cipher. Registered as its own primary (form-1
        // exact match) — the SPI pre-locks cipher+mode, so engineSetMode is not
        // involved. "CHACHA7539" is BouncyCastle's name for the same RFC 7539
        // (12-byte-nonce) engine.
        safeRegister("Cipher.ChaCha20", () ->
                provider.addAlgorithmImplementation("Cipher", "ChaCha20",
                        PREFIX + "ChaCha20", generalAttributes, (arg) -> new ChaCha20BlockCipherSpi()));
        safeRegister("Cipher.CHACHA7539 (alias of ChaCha20)", () ->
                provider.addAlias("Cipher", "ChaCha20", "CHACHA7539"));

        // ChaCha20-Poly1305 AEAD. Its OWN primary — NOT a transformation alias
        // of "ChaCha20" (see CLAUDE.md form-1/form-4 note), so the SPI's AEAD
        // engineInit is always used. The dash-name is registered once
        // ("CHACHA20-POLY1305" resolves to it case-insensitively); the RFC 8103
        // OID is a separate alias to avoid a duplicate-key collision at load.
        safeRegister("Cipher.ChaCha20-Poly1305", () ->
                provider.addAlgorithmImplementation("Cipher", "ChaCha20-Poly1305",
                        PREFIX + "ChaCha20Poly1305", generalAttributes, (arg) -> new ChaCha20Poly1305CipherSpi()));
        safeRegister("Cipher." + CHACHA20_POLY1305_OID + " (OID alias)", () ->
                provider.addAlias("Cipher", "ChaCha20-Poly1305", CHACHA20_POLY1305_OID));

        // Shared 256-bit KeyGenerator. ChaCha20-Poly1305 and the OID alias to it
        // (one ChaCha20 key type — the BouncyCastle model).
        safeRegister("KeyGenerator.ChaCha20", () ->
                provider.addAlgorithmImplementation("KeyGenerator", "ChaCha20",
                        PREFIX + "ChaCha20KeyGen", generalAttributes, (arg) -> new ChaCha20KeyGenerator()));
        safeRegister("KeyGenerator.ChaCha20-Poly1305 (alias of ChaCha20)", () ->
                provider.addAlias("KeyGenerator", "ChaCha20", "ChaCha20-Poly1305", CHACHA20_POLY1305_OID));
    }

    /**
     * Run a single registration, swallowing and logging any {@link Throwable}
     * so the rest of {@link #configure} continues — a failed class initializer
     * is never retried for the lifetime of the process.
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
                    "ProvChaCha20: skipped " + description + " — " + t.getMessage(),
                    t);
        }
    }
}
