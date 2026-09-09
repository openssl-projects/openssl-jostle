/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider.kts;

import org.openssl.jostle.util.asn1.oids.NISTObjectIdentifiers;

import java.security.InvalidKeyException;

/**
 * The key wraps the KTS ciphers accept, selected by {@code
 * KTSParameterSpec.getKeyAlgorithmName()}: RFC 3394 (KW) or RFC 5649 (KWP).
 *
 * <p>Shared by {@code RSAKEMCipherSpi} and {@code MLKEMKTSCipherSpi} so the
 * accepted set and the refusal message exist once rather than in four files
 * (each SPI has a {@code java9/} copy), as {@link KtsKdf} is.
 *
 * <p>The accepted set is BouncyCastle's AES vocabulary from
 * {@code WrapUtil.getWrapper}, compared case-insensitively because bcpkix
 * supplies both spellings: {@code AESWRAP} from {@code CMSUtils} on the CMS
 * path and {@code AESWrap} from {@code OperatorHelper} on the RSA-KEM operator
 * path. A null name means KW, which is what existing callers get. BC also
 * accepts ARIA, Camellia and SEED wraps; we serve AES only and refuse those
 * typed, a deliberate divergence pinned by {@code KtsWrapNameTest}.
 *
 * <p>This package is deliberately not exported.
 */
public final class KtsWrap
{
    /** Named in the refusal message so the caller learns what IS accepted. */
    private static final String ACCEPTED = "AESWRAP, AES, AES-KWP";

    private KtsWrap()
    {
    }

    /** Which RFC the key-algorithm name selects. */
    public enum Kind
    {
        /** RFC 3394 AES key wrap. Requires a multiple-of-8 input, at least 16 bytes. */
        KW,
        /** RFC 5649 AES key wrap with padding. Accepts any input from 1 byte up. */
        KWP
    }

    /**
     * @param keyAlgorithmName the spec's key-algorithm name; may be null.
     * @return the wrap the name selects; {@link Kind#KW} for a null name, and
     *         null when the name is non-null and names none of the accepted set.
     */
    public static Kind kindForName(String keyAlgorithmName)
    {
        if (keyAlgorithmName == null)
        {
            return Kind.KW;
        }
        if (keyAlgorithmName.equalsIgnoreCase("AESWRAP") || keyAlgorithmName.equalsIgnoreCase("AES"))
        {
            return Kind.KW;
        }
        if (keyAlgorithmName.equalsIgnoreCase("AES-KWP"))
        {
            return Kind.KWP;
        }
        return null;
    }

    /**
     * @return the message for a name {@link #kindForName} refused. Pinned by
     *         test, so callers must not reword it locally.
     */
    public static String unsupportedNameMessage(String keyAlgorithmName)
    {
        return "unsupported key algorithm name: " + keyAlgorithmName + " (accepted: " + ACCEPTED + ")";
    }

    /**
     * @param kind   the wrap selected by the key-algorithm name.
     * @param kekLen the KEK length in bytes.
     * @return the OID of the AES key-wrap transformation to resolve.
     * @throws InvalidKeyException when the KEK length is not an AES key size.
     */
    public static String oidFor(Kind kind, int kekLen)
        throws InvalidKeyException
    {
        if (kind == null)
        {
            // Refuse rather than default: falling through would wrap with the wrong RFC.
            throw new InvalidKeyException("no key wrap selected");
        }
        if (kind == Kind.KWP)
        {
            switch (kekLen)
            {
            case 16: return NISTObjectIdentifiers.id_aes128_wrap_pad.getId();
            case 24: return NISTObjectIdentifiers.id_aes192_wrap_pad.getId();
            case 32: return NISTObjectIdentifiers.id_aes256_wrap_pad.getId();
            default: throw new InvalidKeyException("unsupported AES-KWP KEK size: " + kekLen);
            }
        }
        switch (kekLen)
        {
        case 16: return NISTObjectIdentifiers.id_aes128_wrap.getId();
        case 24: return NISTObjectIdentifiers.id_aes192_wrap.getId();
        case 32: return NISTObjectIdentifiers.id_aes256_wrap.getId();
        default: throw new InvalidKeyException("unsupported AES-KW KEK size: " + kekLen);
        }
    }
}
