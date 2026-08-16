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

package org.openssl.jostle.jcajce.spec;

import org.openssl.jostle.util.Arrays;

import java.security.spec.KeySpec;

/**
 * Parameters for an Argon2 (RFC 9106) key derivation.
 *
 * <p>The type constants, version constants, accessor names and units mirror
 * {@code org.bouncycastle.jcajce.spec.Argon2KeySpec} so a caller can move
 * between the two providers without rewriting call sites, and so specs stay
 * structurally interchangeable. In particular {@link #getMemory()} is in
 * <b>kibibytes</b> (BC's {@code withMemoryAsKB}), not bytes and not a power-of-two
 * exponent.</p>
 *
 * <p>The {@code secret} (keyed Argon2) and {@code additional} inputs of RFC 9106
 * are not exposed: OpenSSL supports them, but the JCE surface here covers the
 * password-hashing use they are absent from. They can be added later without
 * breaking this spec's constructors.</p>
 */
public class Argon2KeySpec
    implements KeySpec
{
    /** Argon2d — data-dependent addressing. */
    public static final int ARGON2_d = 0;
    /** Argon2i — data-independent addressing. */
    public static final int ARGON2_i = 1;
    /** Argon2id — hybrid; the RFC 9106 default choice. */
    public static final int ARGON2_id = 2;

    /** Argon2 version 1.0 (0x10). */
    public static final int ARGON2_VERSION_10 = 0x10;
    /** Argon2 version 1.3 (0x13) — the RFC 9106 version. */
    public static final int ARGON2_VERSION_13 = 0x13;

    private final int type;
    private final int version;
    private final char[] password;
    private final byte[] salt;
    private final int iterations;
    private final int memory;
    private final int parallelism;
    private final int keyLength;

    /**
     * Argon2id at version 1.3 — the RFC 9106 recommended defaults.
     *
     * @param password    the password; UTF-8 encoded when derived.
     * @param salt        the salt (RFC 9106 requires at least 8 bytes).
     * @param iterations  time cost, at least 1.
     * @param memory      memory cost in <b>kibibytes</b>, at least {@code 8 * parallelism}.
     * @param parallelism the number of lanes, at least 1.
     * @param keyLength   derived key length in <b>bits</b>.
     */
    public Argon2KeySpec(char[] password, byte[] salt, int iterations, int memory, int parallelism, int keyLength)
    {
        this(ARGON2_id, ARGON2_VERSION_13, password, salt, iterations, memory, parallelism, keyLength);
    }

    /**
     * @param type    one of {@link #ARGON2_d}, {@link #ARGON2_i}, {@link #ARGON2_id}.
     * @param version one of {@link #ARGON2_VERSION_10}, {@link #ARGON2_VERSION_13}.
     * @see #Argon2KeySpec(char[], byte[], int, int, int, int)
     */
    public Argon2KeySpec(int type, int version, char[] password, byte[] salt, int iterations, int memory,
                         int parallelism, int keyLength)
    {
        this.type = type;
        this.version = version;
        this.password = Arrays.clone(password);
        this.salt = Arrays.clone(salt);
        this.iterations = iterations;
        this.memory = memory;
        this.parallelism = parallelism;
        this.keyLength = keyLength;
    }

    public int getType()
    {
        return type;
    }

    public int getVersion()
    {
        return version;
    }

    public char[] getPassword()
    {
        return Arrays.clone(password);
    }

    public byte[] getSalt()
    {
        return Arrays.clone(salt);
    }

    public int getIterations()
    {
        return iterations;
    }

    /**
     * @return the memory cost in kibibytes.
     */
    public int getMemory()
    {
        return memory;
    }

    public int getParallelism()
    {
        return parallelism;
    }

    /**
     * @return the derived key length in bits.
     */
    public int getKeyLength()
    {
        return keyLength;
    }
}
