/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider.binding;

import java.security.Provider;

/**
 * Which provider an SPI belongs to, held as ONE fact in ONE field.
 *
 * <p>An SPI is bound either to a provider INSTANCE or, in MT-14's unbound
 * realm, to nothing better than a NAME. Both facts were previously stored
 * side by side, and two fields that must agree eventually do not: the
 * instance decides which provider does the work while the name reaches the
 * exception messages and the policy comparisons, so a divergent pair performs
 * the operation in one provider and names another. Nothing reconciled them.
 *
 * <p>Here the pair cannot be formed. The single field holds a {@link Provider}
 * or a {@code String}, never both, and {@link #name()} DERIVES the name from
 * the instance when there is one. A caller cannot supply an instance and a
 * name that disagree because there is no constructor that takes two things.
 */
public final class ProviderBinding
{
    /**
     * A {@link Provider} when bound to an instance, otherwise the provider
     * NAME. One field on purpose: a second field would be a second fact.
     */
    private final Object ref;

    private ProviderBinding(Object ref)
    {
        this.ref = ref;
    }

    /** Bound to a provider instance; the name is derived from it. */
    public static ProviderBinding of(Provider instance)
    {
        if (instance == null)
        {
            throw new IllegalArgumentException(
                    "a provider instance is required; use ofName(...) for the unbound realm");
        }
        return new ProviderBinding(instance);
    }

    /** MT-14's unbound realm: a name is the most that can be pinned. */
    public static ProviderBinding ofName(String name)
    {
        if (name == null)
        {
            throw new IllegalArgumentException("a provider name is required");
        }
        return new ProviderBinding(name);
    }

    /** The instance, or null when this binding is a name only. */
    public Provider instance()
    {
        return (ref instanceof Provider) ? (Provider) ref : null;
    }

    /** Always the name of the bound provider, derived when an instance holds it. */
    public String name()
    {
        return (ref instanceof Provider) ? ((Provider) ref).getName() : (String) ref;
    }

    /**
     * Same provider for binding purposes. IDENTITY when either side holds an
     * instance — two instances of one provider share a name, and a key made
     * by one is refused by the other under MT-14's isolation check — and the
     * name only when neither does.
     */
    public boolean sameAs(ProviderBinding other)
    {
        if (other == null)
        {
            return false;
        }
        if (ref instanceof Provider || other.ref instanceof Provider)
        {
            return ref == other.ref;
        }
        return ref.equals(other.ref);
    }

    @Override
    public String toString()
    {
        return (ref instanceof Provider) ? ("instance " + name()) : ("name " + name());
    }
}
