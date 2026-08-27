/*
 *  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.spec;

import org.openssl.jostle.disposal.NativeDisposer;
import org.openssl.jostle.disposal.NativeReference;
import org.openssl.jostle.jcajce.provider.NISelector;

import java.security.Provider;


/**
 * A Key Spec that wraps an OpenSSL PKEY, anything using a PKEY must keep a reference to this or it's inheritors
 * or it will be collected independently and may result in use after free.
 */
public class PKEYKeySpec
{
    // Instance field, not a NISelector static: the spec is bound to whichever
    // NI backend created the PKEY - NISelector.SpecNI for JSL,
    // FIPSNISelector.SpecNI (the FIPS interface library) for JSLFIPS - so
    // name lookup and disposal go through the library that owns the key.
    protected final SpecNI specNI;
    protected final PKEYReference ref;
    protected final OSSLKeyType type;

    /**
     * The provider INSTANCE that created this key, or null when the spec was
     * built outside any provider ("unbound").
     *
     * <p>Instance, not name and not library. Two facts force it, both
     * measured rather than assumed:
     *
     * <ol>
     * <li>OpenSSL binds a key to its creating provider for life — an
     *     operation on the key is served THERE regardless of which lib ctx
     *     drove it ({@code fips-c-review/probes/xprovider_key_probe.c}).</li>
     * <li>The JCA cannot name an instance stably —
     *     {@code removeProvider} + {@code addProvider} swaps which instance a
     *     name resolves to, so a key can outlive the name that identified its
     *     maker.</li>
     * </ol>
     *
     * <p>So the identity has to be the reference itself: comparable by
     * {@code ==}, impossible to forge or alias, and already what JCA's
     * {@code getInstance(String, Provider)} overloads take.
     *
     * <p>Held strongly, which pins the Provider against GC. Acceptable —
     * Provider objects are effectively application-lifetime — but it is a real
     * lifetime coupling and is stated here rather than discovered later.
     */
    private final Provider providerInstance;


    /**
     * @deprecated Use {@link #PKEYKeySpec(SpecNI, long)} and name the SpecNI
     * explicitly. This overload records {@link NISelector#SpecNI} — the BASE
     * interface library — REGARDLESS of which library allocated the handle,
     * so it is correct only in base-only code.
     *
     * <p>The cautionary tale is MT-15: {@code EdKeyFactorySpi} called the
     * sibling overload as
     * {@code new PKEYKeySpec(specNI.allocate(), type)}, allocating through the
     * FIPS library and recording the base one. Disposal routes through the
     * RECORDED NI, so those keys were freed across libraries — see
     * {@link Disposer}, which states the invariant.
     *
     * <p>Still functional; deprecated to steer callers, not to break them.
     */
    @Deprecated
    public PKEYKeySpec(long ref)
    {
        this(NISelector.SpecNI, ref);
    }

    public PKEYKeySpec(SpecNI specNI, long ref)
    {
        this(specNI, ref, (Provider) null);
    }

    public PKEYKeySpec(SpecNI specNI, long ref, Provider providerInstance)
    {
        this.providerInstance = providerInstance;
        if (ref == 0)
        {
            throw new IllegalArgumentException("'ref' cannot be zero");
        }

        this.specNI = specNI;
        String name = specNI.getName(ref);
        if (name == null)
        {
            throw new IllegalArgumentException("unable to determine algorithm name for ref");
        }
        this.type = OSSLKeyType.forAlias(name);
        if (this.type == null)
        {
            throw new IllegalArgumentException("unknown algorithm: " + name);
        }
        this.ref = new PKEYReference(specNI, ref, type.name());
    }

    /**
     * @deprecated Use {@link #PKEYKeySpec(SpecNI, long, OSSLKeyType)} and name the SpecNI
     * explicitly. This overload records {@link NISelector#SpecNI} — the BASE
     * interface library — REGARDLESS of which library allocated the handle,
     * so it is correct only in base-only code.
     *
     * <p>The cautionary tale is MT-15: {@code EdKeyFactorySpi} called the
     * sibling overload as
     * {@code new PKEYKeySpec(specNI.allocate(), type)}, allocating through the
     * FIPS library and recording the base one. Disposal routes through the
     * RECORDED NI, so those keys were freed across libraries — see
     * {@link Disposer}, which states the invariant.
     *
     * <p>Still functional; deprecated to steer callers, not to break them.
     */
    @Deprecated
    public PKEYKeySpec(long ref, OSSLKeyType type)
    {
        this(NISelector.SpecNI, ref, type);
    }

    public PKEYKeySpec(SpecNI specNI, long ref, OSSLKeyType type)
    {
        this(specNI, ref, type, null);
    }

    public PKEYKeySpec(SpecNI specNI, long ref, OSSLKeyType type, Provider providerInstance)
    {
        this.providerInstance = providerInstance;
        if (ref == 0)
        {
            throw new IllegalArgumentException("'ref' cannot be zero");
        }
        if (type == null)
        {
            throw new IllegalArgumentException("'type' cannot be null");
        }
        this.specNI = specNI;
        this.type = type;
        this.ref = new PKEYReference(specNI, ref, type.name());
    }


    /**
     * The provider instance that created this key, or null when unbound.
     */
    public Provider getProviderInstance()
    {
        return providerInstance;
    }

    /**
     * May a key with this spec be used by {@code user}?
     *
     * <p>The four cells, written out because leaving them to emerge from a
     * null comparison is how the unbound case gets decided by accident:
     *
     * <pre>
     *   bound x bound, same instance        ACCEPT
     *   bound x bound, different instances  refuse  &lt;- the point of MT-14
     *   bound x unbound, either direction   refuse  &lt;- fail closed: an
     *                                                 unbound key is never
     *                                                 silently adopted, JSL
     *                                                 included
     *   unbound x unbound                   ACCEPT  &lt;- documented, tested
     * </pre>
     *
     * <p>The last cell is deliberate and load-bearing. Refusing it would break
     * every direct-SPI consumer — a KeyPairGenerator constructed outside any
     * provider would produce keys its own sibling SPIs reject. The unbound
     * realm has no provider boundary to protect.
     */
    public boolean usableBy(Provider user)
    {
        if (providerInstance == null && user == null)
        {
            return true;
        }
        return providerInstance == user;
    }

    protected static class Disposer
            extends NativeDisposer
    {
        // The NI that allocated the PKEY frees it - a FIPS-allocated key
        // must be disposed through the FIPS interface library.
        private final SpecNI specNI;

        Disposer(SpecNI specNI, long ref)
        {
            super(ref);
            this.specNI = specNI;
        }

        @Override
        protected void dispose(long reference)
        {
            specNI.dispose(reference);
        }
    }

    protected static class PKEYReference extends NativeReference
    {

        public PKEYReference(SpecNI specNI, long reference, String name)
        {
            super(reference, name, new PKEYKeySpec.Disposer(specNI, reference));
        }

    }

    public long getReference()
    {
        return ref.getReference();
    }

    public OSSLKeyType getType()
    {
        return type;
    }

    /**
     * The NI backend that owns this PKEY - FIPS-aware consumers pass it on
     * so every operation on the key stays within the library that created it.
     */
    public SpecNI getSpecNI()
    {
        return specNI;
    }
}
