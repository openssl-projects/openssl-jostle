/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.test.provider;

import org.openssl.jostle.jcajce.provider.JostleProvider;

/**
 * A {@code JostleProvider} instance with one service removed, so that "THIS
 * instance cannot do X" is testable while the instance installed under the
 * same NAME still can.
 *
 * <p>That gap is the entire difference between a name pin and an instance pin,
 * and it is what makes MT-16 falsifiable. A pin on the name reads "whatever
 * JSL resolves to right now", so a stripped instance silently borrows the
 * capability from the registered one and the operation succeeds; a pin on the
 * instance fails loudly instead. Without a provider that can be made
 * selectively incapable there is no input that distinguishes the two.
 *
 * <p>A subclass, and it removes the PROPERTY rather than calling
 * {@code Provider.removeService}. {@code JostleProvider.getService} is final
 * and resolves out of the legacy {@code "<type>.<ALG>"} property entries,
 * memoising each {@code Service} it builds — so {@code removeService} would
 * leave the property in place and be ignored, and merely ASKING for the
 * service first would memoise it past any later removal. Removing the property
 * from a provider nobody has queried yet is the only removal that takes
 * effect; the first version of this class did it the other way and every test
 * built on it passed while nothing had been stripped.
 *
 * <p>Aliases go with it: an alias resolves to the primary name and the lookup
 * then finds no class for it. {@code JostleFIPSProvider} is {@code final} and
 * has no counterpart — the FIPS side discriminates on key binding instead.
 */
public class StrippedJostleProvider
        extends JostleProvider
{
    /**
     * @param type      the JCA service type, e.g. {@code "MessageDigest"}.
     * @param algorithm the service to remove. Its aliases go with it.
     */
    public StrippedJostleProvider(String type, String algorithm)
    {
        String upper = algorithm.toUpperCase(java.util.Locale.ROOT);
        // Resolve an alias to its primary exactly as getService does, and
        // remove the PRIMARY: removing an alias would leave the service
        // reachable under its own name. SHA-256, for one, is an alias of
        // SHA2-256 here.
        String realName = (String) get("Alg.Alias." + type + "." + upper);
        String key = type + "." + (realName == null ? upper : realName);
        if (!containsKey(key))
        {
            throw new IllegalStateException(
                    "nothing to strip: " + key + " is not registered on a fresh "
                            + "JostleProvider, so every test built on this instance would pass "
                            + "vacuously");
        }
        remove(key);
        if (getService(type, algorithm) != null)
        {
            throw new IllegalStateException(
                    "stripping " + key + " did not take effect — the provider still serves it, "
                            + "so the instance is not distinguishable from a full one");
        }
    }
}
