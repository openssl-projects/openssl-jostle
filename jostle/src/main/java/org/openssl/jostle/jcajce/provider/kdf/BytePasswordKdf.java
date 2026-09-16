/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */
package org.openssl.jostle.jcajce.provider.kdf;

import javax.crypto.interfaces.PBEKey;

/**
 * PBKDF2 / scrypt derivation from an already-computed byte[] password,
 * shared by {@link PBKDF2SecretKeyFactory}, {@link ScryptSecretKeyFactory},
 * and (later) BCFKS. Not part of the public API — every {@code Cipher} /
 * {@code SecretKeyFactory} spec a caller constructs stays a {@code char[]}
 * password; this class exists because BCFKS derives from a byte string that
 * is not the UTF-8 (or 8-bit) encoding of any {@code char[]}.
 *
 * <p>The byte-password scheme is BouncyCastle's, measured from r1rv86:
 * {@code core/src/main/java/org/bouncycastle/crypto/PBEParametersGenerator.java:150}
 * defines {@code PKCS12PasswordToBytes}, and
 * {@code prov/src/main/java/org/bouncycastle/jcajce/provider/keystore/bcfks/BcFKSKeyStoreSpi.java:848-852}
 * is where BCFKS derives a purpose-salted password as
 * {@code PKCS12PasswordToBytes(password) || PKCS12PasswordToBytes(purpose)}
 * (BC's own {@code Arrays.concatenate}, plain concatenation).
 */
public final class BytePasswordKdf
{
    private BytePasswordKdf()
    {
    }

    public static final String PURPOSE_INTEGRITY_CHECK = "INTEGRITY_CHECK";
    public static final String PURPOSE_STORE_ENCRYPTION = "STORE_ENCRYPTION";
    public static final String PURPOSE_PRIVATE_KEY_ENCRYPTION = "PRIVATE_KEY_ENCRYPTION";
    public static final String PURPOSE_SECRET_KEY_ENCRYPTION = "SECRET_KEY_ENCRYPTION";

    /**
     * BouncyCastle's {@code PKCS12PasswordToBytes}: each char as two bytes,
     * big-endian, followed by a two-byte NUL terminator (the standards
     * library does not hold RFC 7292, so this is cited to the BC source
     * above rather than to its s B.1).
     *
     * <p>A null or empty password returns a ZERO-LENGTH array, not a
     * two-byte terminator — measured at
     * {@code PBEParametersGenerator.java:150-165} and by javap of the 1.86
     * jar's {@code PBEParametersGenerator}.
     */
    public static byte[] pkcs12PasswordToBytes(char[] password)
    {
        if (password == null || password.length == 0)
        {
            return new byte[0];
        }
        byte[] bytes = new byte[(password.length + 1) * 2];
        for (int i = 0; i != password.length; i++)
        {
            bytes[i * 2] = (byte) (password[i] >>> 8);
            bytes[i * 2 + 1] = (byte) password[i];
        }
        // The two-byte NUL terminator: bytes[bytes.length - 2] and
        // bytes[bytes.length - 1] are already 0 from the fresh allocation.
        return bytes;
    }

    /**
     * BCFKS's purpose-salted derivation password:
     * {@code pkcs12PasswordToBytes(password) || pkcs12PasswordToBytes(purpose)}.
     * {@code purpose} is one of the {@code PURPOSE_*} constants.
     */
    public static byte[] derivationPassword(char[] password, String purpose)
    {
        byte[] pw = pkcs12PasswordToBytes(password);
        byte[] pur = pkcs12PasswordToBytes(purpose.toCharArray());
        byte[] out = new byte[pw.length + pur.length];
        System.arraycopy(pw, 0, out, 0, pw.length);
        System.arraycopy(pur, 0, out, pw.length, pur.length);
        return out;
    }

    /**
     * PBKDF2 derivation from an already-computed byte[] password. Thin
     * wrapper over {@link KdfNI#pbkdf2} sharing the error-translation
     * {@link PBKDF2SecretKeyFactory} already applied inline — the caller
     * still owns scrubbing {@code passwordBytes} and {@code out}.
     */
    public static void pbkdf2(KdfNI kdfNI, byte[] passwordBytes, byte[] salt, int iterationCount,
                               String digest, byte[] out, int outOffset, int outLen)
    {
        kdfNI.handleErrorCodes(kdfNI.pbkdf2(passwordBytes, salt, iterationCount, digest, out, outOffset, outLen));
    }

    /** scrypt derivation from an already-computed byte[] password; see {@link #pbkdf2}. */
    public static void scrypt(MemoryHardKdfNI kdfNI, byte[] passwordBytes, byte[] salt,
                               int n, int r, int p, byte[] out, int outOffset, int outLen)
    {
        kdfNI.handleErrorCodes(kdfNI.scrypt(passwordBytes, salt, n, r, p, out, outOffset, outLen));
    }

    /**
     * A {@link PBEKey} carrying exactly the given identity -- algorithm,
     * password, salt, iteration count and derived bytes -- with no
     * derivation of its own. {@link JOPBEKey}'s constructor is
     * package-private; this is the one public door into it, for BCFKS's
     * type-5 (PBKDF_KEY) entries, which store and recover a PBEKey's full
     * identity rather than just its derived bytes.
     */
    public static PBEKey pbeKey(String algorithm, char[] password, byte[] salt, int iterationCount, byte[] rawKey)
    {
        return new JOPBEKey(algorithm, password, salt, iterationCount, rawKey);
    }
}
