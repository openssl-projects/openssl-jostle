/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider.wrap;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;

/**
 * Resolves the {@link KeyFactory} that reconstructs an asymmetric key from
 * freshly UNWRAPPED material, pinned to the provider INSTANCE that performed
 * the unwrap (MT-10).
 *
 * <h2>The defect this replaces</h2>
 *
 * Every {@code engineUnwrap} in the provider used to call
 * {@code KeyFactory.getInstance(wrappedKeyAlgorithm)} with no provider. JCA
 * resolves that against the installed provider list in order — normally SUN.
 * Two consequences, and the second is caller-visible breakage rather than
 * boundary hygiene:
 *
 * <ol>
 * <li><b>Boundary.</b> A JSLFIPS unwrap produced a key that was not resident
 *     in the FIPS lib ctx at all. Invisible to every functional test: a SUN
 *     RSA key signs the same bytes a module-resident one does.</li>
 * <li><b>Correctness.</b> The returned key was a foreign object, so the very
 *     next Jostle operation on it failed the provider-instance isolation
 *     check introduced by MT-14 — {@code unwrap} handed back something the
 *     unwrapping provider itself would refuse.</li>
 * </ol>
 *
 * <h2>The contract</h2>
 *
 * <ol>
 * <li>{@code Cipher.PUBLIC_KEY} / {@code Cipher.PRIVATE_KEY} come back BOUND
 *     to the unwrapping SPI's provider instance, immediately usable in that
 *     provider's other services. The INSTANCE, not the name: a name is
 *     re-resolvable ({@code removeProvider} + {@code addProvider} swaps what
 *     it points at) and a {@code Cipher} obtained through
 *     {@code getInstance(alg, Provider)} need never have been registered
 *     under a name at all.</li>
 * <li>{@code Cipher.SECRET_KEY} is unaffected and stays a
 *     {@code SecretKeySpec}. It has no native residency, no provider to be
 *     bound to and no isolation check to fail — the same line MT-14 drew.</li>
 * <li>Failure is LOUD and typed. There is no fall-through to JCA order,
 *     because a silent fall-through is exactly what hid the original
 *     defect.</li>
 * </ol>
 *
 * <h2>Why {@link NoSuchAlgorithmException}, given unwrap's
 * {@code InvalidKeyException}-only rule</h2>
 *
 * The rule in java-spi.md ("{@code engineUnwrap} should surface
 * {@code InvalidKeyException} on ALL unwrap failures — never
 * {@code BadPaddingException}") exists to close a Bleichenbacher channel: the
 * caller must not learn WHY a ciphertext failed. It binds failures that depend
 * on the ciphertext. This one does not — its outcome is decided entirely by
 * {@code wrappedKeyAlgorithm} and the SPI's own provider, both fixed before
 * any ciphertext is examined, so it distinguishes nothing about the plaintext.
 *
 * <p>{@code NoSuchAlgorithmException} is also declared on
 * {@code engineUnwrap} and on {@code Cipher.unwrap} precisely for this case,
 * and it is what the JDK itself throws: SunJCE's {@code ConstructKeys} raises
 * {@code NoSuchAlgorithmException("No installed provider can create keys for
 * the ... algorithm")}.
 *
 * <p><b>Callers must resolve BEFORE decrypting.</b> Resolving afterwards would
 * make the exception type depend on whether the decrypt succeeded — a real
 * oracle, since with an unserved algorithm every valid ciphertext would raise
 * {@code NoSuchAlgorithmException} and every invalid one
 * {@code InvalidKeyException}. Resolving first also skips a pointless private
 * key operation on a call that cannot succeed.
 *
 * <p><b>This package is deliberately NOT in {@code module-info.java}.</b> It is
 * provider-internal plumbing with no caller outside the module, so it follows
 * {@code jcajce.provider.kdf} and {@code jcajce.provider.blockcipher} rather
 * than the exported {@code jcajce.provider}. The "add an exports entry when you
 * add a package" rule in java-spi.md governs packages that SHOULD be visible to
 * modular consumers; this one should not be.
 */
public final class UnwrappedKeys
{
    private UnwrappedKeys()
    {
    }

    /**
     * The KeyFactory for {@code wrappedKeyAlgorithm} from {@code ownProvider}.
     *
     * @param ownProvider the provider INSTANCE the unwrapping SPI belongs to;
     *                    null when the SPI was constructed outside any
     *                    provider.
     * @param wrappedKeyAlgorithm the algorithm the caller passed to
     *                    {@code unwrap}.
     */
    public static KeyFactory keyFactory(Provider ownProvider, String wrappedKeyAlgorithm)
            throws NoSuchAlgorithmException
    {
        if (ownProvider == null)
        {
            throw new NoSuchAlgorithmException(
                    "cannot reconstruct an unwrapped " + wrappedKeyAlgorithm + " key: this "
                            + "cipher was constructed outside any provider, so there is no "
                            + "provider instance to bind the key to. Obtain the Cipher from a "
                            + "Jostle provider rather than constructing the SPI directly.");
        }

        try
        {
            return KeyFactory.getInstance(wrappedKeyAlgorithm, ownProvider);
        }
        catch (NoSuchAlgorithmException e)
        {
            throw new NoSuchAlgorithmException(
                    "provider " + ownProvider.getName() + " serves no KeyFactory for "
                            + wrappedKeyAlgorithm + ", so it cannot reconstruct the key it "
                            + "unwrapped; resolving the key through another provider would "
                            + "return a key this provider then refuses", e);
        }
    }
}
