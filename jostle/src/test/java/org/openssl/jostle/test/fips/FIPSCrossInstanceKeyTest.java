/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.test.fips;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.interfaces.OSSLKey;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;
import org.openssl.jostle.jcajce.spec.PKEYKeySpec;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;

/**
 * MT-14: where does an operation on a foreign key OBJECT actually execute?
 *
 * <p>Written to FAIL before MT-14's instance binding landed — it was the pin
 * that made the fix falsifiable — and it now passes because the crossing is
 * REFUSED. A behavioural test cannot detect the original defect: a signature
 * verified in the base provider is byte-identical to one verified in the
 * module, which is why it survived every agreement and round-trip test in the
 * suite.
 *
 * <p>What it measures, via the key-level accessor added for this item
 * ({@code SpecNI.getKeyProvider}): the OSSL_PROVIDER that owns a key's
 * keymgmt. Measurement in
 * {@code fips-c-review/probes/xprovider_key_probe.c} established that an
 * operation on a key is served by THAT provider regardless of which lib ctx
 * drove it, so the key's provider is the operation's provider.
 *
 * <p>Before instance binding, a foreign public key object was accepted as-is
 * and kept its originating provider, so a JSLFIPS operation handed a JSL key
 * executed in "default". There is now no legal cross-instance object route at
 * all, so these assertions are satisfied because the crossing is refused
 * rather than because the key is re-homed. Either way the invariant asserted
 * here is the one that matters: <b>a key used through a provider must be
 * served by that provider's module.</b>
 */
public class FIPSCrossInstanceKeyTest
{
    private static Provider jsl;
    private static Provider fips;

    @BeforeAll
    static void before()
    {
        fips = FIPSTestUtil.assumeFipsProvider();
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
        jsl = Security.getProvider(JostleProvider.PROVIDER_NAME);
    }

    /**
     * Families offering BOTH a KeyPairGenerator and a KeyFactory under the
     * same name in both providers.
     *
     * <p>The KeyFactory half of the condition matters: {@link #check} treats a
     * typed refusal as a pass, so if a family were missing its factory the
     * resulting {@code NoSuchAlgorithmException} would read as a refusal and
     * the probe would silently pass without ever presenting a key. Requiring
     * the factory up front lets that exception be treated as the fault it is.
     *
     * <p>The candidate list deliberately spans every asymmetric family the two
     * providers can share, not just the classical four plus one PQC each. The
     * Ed / XDH / hybrid entries were absent while Ed was the one family whose
     * public key class did not implement {@code OSSLKey}; a sweep that skips a
     * family cannot report on it. Entries a module does not serve (X25519 is
     * unfetchable on the 3.5.x module) drop out here rather than being
     * special-cased.
     */
    private static List<String> sharedFamilies()
    {
        List<String> out = new ArrayList<String>();
        for (String alg : new String[]{"RSA", "EC", "DSA", "DH",
                "ML-KEM-768", "ML-DSA-65", "SLH-DSA-SHA2-128S",
                "Ed25519", "Ed448", "X25519", "X448",
                "X25519MLKEM768", "SecP256r1MLKEM768"})
        {
            if (jsl.getService("KeyPairGenerator", alg) != null
                    && fips.getService("KeyPairGenerator", alg) != null
                    && jsl.getService("KeyFactory", alg) != null
                    && fips.getService("KeyFactory", alg) != null)
            {
                out.add(alg);
            }
        }
        Assertions.assertFalse(out.isEmpty(),
                "no family is served by both providers — the sweep would be vacuous");
        return out;
    }

    /**
     * Is instance binding ACTIVATED — i.e. has Phase 2 landed?
     *
     * <p>Detected from the tree itself: generate a key through a registered
     * provider and ask whether its spec carries a provider instance. In
     * Phase 1 the checks are all in place but registrations do not yet pass an
     * instance, so every spec is unbound and the cross-provider contract
     * cannot hold yet.
     *
     * <p><b>Why detect rather than disable.</b> {@code @Disabled} rots — it
     * survives the change it was waiting for. Leaving the gate red is worse
     * still: an expected failure is where a real regression hides. Tying the
     * arming to the FLIP ITSELF means nobody has to remember to switch this
     * on, and an accidental PARTIAL flip fails loudly — the armed probe then
     * reports every family that was missed.
     */
    private static boolean bindingActivated() throws Exception
    {
        return !boundFamilies().isEmpty();
    }

    private static List<String> boundCache;

    /**
     * The shared families bound on BOTH providers.
     *
     * <p>Both, not just JSL: an earlier version probed the JSL side only, and
     * a family left unbound on the FIPS side alone was invisible to it. That
     * happened — {@code ProvFIPSXDH} kept calling the four-argument
     * {@code XECKeyPairGenerator} through the flip — and it surfaced instead
     * as a FIPS key refused by FIPS's own KeyAgreement, several files away
     * from the cause. Requiring both sides puts the report where the defect
     * is.
     */
    private static List<String> boundFamilies() throws Exception
    {
        if (boundCache != null)
        {
            return boundCache;
        }
        List<String> bound = new ArrayList<String>();
        for (String alg : sharedFamilies())
        {
            if (instanceOf(keyPair(jsl, alg).getPublic()) != null
                    && instanceOf(keyPair(fips, alg).getPublic()) != null)
            {
                bound.add(alg);
            }
        }
        boundCache = bound;
        return bound;
    }

    private static Provider instanceOf(java.security.Key key)
    {
        return ((OSSLKey) key).getSpec().getProviderInstance();
    }

    /**
     * Every shared family binds its keys to the registered provider INSTANCE,
     * on BOTH providers.
     *
     * <p>Separate from the sweep below, which self-arms and would simply skip
     * if nothing were bound. This one cannot skip: it names the exact
     * (family, provider) pairs that failed to bind, which is the report you
     * want when a registration is missed.
     */
    @Test
    public void everySharedFamilyBindsOnBothProviders() throws Exception
    {
        List<String> unbound = new ArrayList<String>();
        for (String alg : sharedFamilies())
        {
            if (instanceOf(keyPair(jsl, alg).getPublic()) != jsl)
            {
                unbound.add(alg + " (JSL)");
            }
            if (instanceOf(keyPair(fips, alg).getPublic()) != fips)
            {
                unbound.add(alg + " (JSLFIPS)");
            }
        }
        Assertions.assertTrue(unbound.isEmpty(),
                "a registration does not pass its provider instance, so the keys it makes are "
                        + "unbound (or bound to something else). Audit every "
                        + "new <Producer>(...) in the Prov class for an argument naming the "
                        + "provider. Affected: " + unbound);
    }

    private static void requireArmed() throws Exception
    {
        Assumptions.assumeTrue(bindingActivated(),
                "MT-14 instance binding is not activated yet: the acceptance checks are in "
                        + "place (Phase 1) but registrations do not pass a provider instance, "
                        + "so every key spec is unbound and no cross-instance contract can "
                        + "hold. This test arms itself automatically when Phase 2 lands — see "
                        + "the two-phase landing note in reviews/misc-tasks-plan.md.");
    }

    private static String providerOf(java.security.Key key)
    {
        PKEYKeySpec spec = ((OSSLKey) key).getSpec();
        return spec.getSpecNI().getKeyProvider(spec.getReference());
    }

    /**
     * Control: a key generated by a provider is served by that provider's
     * module. Establishes that the accessor discriminates at all, so a failure
     * below is about the crossing and not about the probe.
     */
    @Test
    public void ownKeysAreServedByTheirOwnProvider() throws Exception
    {
        // Deliberately NOT armed: this control is meaningful in both phases —
        // it proves the accessor discriminates, which must hold before and
        // after the flip.
        for (String alg : sharedFamilies())
        {
            Assertions.assertEquals("default", providerOf(keyPair(jsl, alg).getPublic()),
                    alg + ": a JSL key must be served by mainline");
            Assertions.assertEquals("fips", providerOf(keyPair(fips, alg).getPublic()),
                    alg + ": a JSLFIPS key must be served by the module");
        }
    }

    /**
     * The invariant MT-14 exists to establish: a public key OBJECT handed
     * across providers must not end up being operated on by the wrong module.
     *
     * <p>FAILS TODAY, by design, and the failure message names every family so
     * the blast radius is visible rather than stopping at the first.
     */
    /**
     * The invariant MT-14 exists to establish: presenting a public key OBJECT
     * to the other provider must either be REFUSED, or be served by the
     * provider you asked. What must never happen is the middle case —
     * accepted, and quietly executed by the other module.
     *
     * <p><b>The presentation is the test.</b> An earlier version of this
     * method read each key's provider in isolation and never handed it across;
     * that asserts a fact about OpenSSL (a key keeps its creating provider)
     * which stays true after the fix, so it would have been a test that could
     * never go green. It has to attempt the crossing.
     *
     * <p>FAILS TODAY by design: the crossing is accepted and served by the
     * wrong module. After instance binding it is refused, and the refusal
     * satisfies the invariant.
     */
    @Test
    public void foreignPublicKeyObjectIsNotServedByTheWrongModule() throws Exception
    {
        requireArmed();

        // A PARTIAL flip is the failure mode this probe exists to make loud:
        // arming on any-bound (rather than on RSA alone) means a flip that
        // missed a family arms the probe anyway, and the miss is reported here
        // by name instead of skipping the whole test silently.
        List<String> shared = sharedFamilies();
        List<String> unbound = new ArrayList<String>(shared);
        unbound.removeAll(boundFamilies());
        Assertions.assertTrue(unbound.isEmpty(),
                "instance binding is activated for some families but not all — Phase 2 must "
                        + "flip every family in one commit, producers and consumers together. "
                        + "Unbound: " + unbound);

        List<String> leaks = new ArrayList<String>();

        for (String alg : shared)
        {
            check(leaks, alg, keyPair(jsl, alg).getPublic(), fips, "fips");
            check(leaks, alg, keyPair(fips, alg).getPublic(), jsl, "default");
        }

        Assertions.assertTrue(leaks.isEmpty(),
                "a foreign public key OBJECT was accepted and then served by the wrong "
                        + "module. Until MT-14's instance binding lands this is expected to "
                        + "fail; after it lands the crossing is refused instead:\n  "
                        + String.join("\n  ", leaks));
    }

    /**
     * Present {@code foreign} to {@code user} and record a leak only if it is
     * ACCEPTED and then served by something other than {@code wanted}.
     * A typed refusal is a pass — that is the post-fix behaviour.
     */
    private static void check(List<String> leaks, String alg, PublicKey foreign,
                              Provider user, String wanted)
    {
        try
        {
            java.security.KeyFactory kf = java.security.KeyFactory.getInstance(alg, user);
            // engineTranslateKey is the narrowest surface that takes a key
            // object and hands back the one the provider would actually use.
            java.security.Key adopted = kf.translateKey(foreign);
            String served = providerOf(adopted);
            if (!wanted.equals(served))
            {
                leaks.add(alg + ": " + user.getName() + " ACCEPTED a foreign public key object "
                        + "and it is served by \"" + served + "\", not \"" + wanted + "\"");
            }
        }
        catch (java.security.InvalidKeyException e)
        {
            // Refused, typed. That is the post-fix contract and a pass.
        }
        catch (java.security.NoSuchAlgorithmException e)
        {
            // NOT a refusal. sharedFamilies() established that both providers
            // offer this KeyFactory, so this means the probe could not run —
            // recording it as a pass would let the sweep go green having
            // presented nothing.
            leaks.add(alg + ": probe could not run against " + user.getName()
                    + " — KeyFactory.getInstance threw " + e);
        }
    }

    private static KeyPair keyPair(Provider p, String alg) throws Exception
    {
        // DSA GENERATION is refused by the 3.5.x module even though the family
        // is registered — registration is not usability. FIPSTestUtil.dsaKeyPair
        // is the established fixture: it generates through JSL once and decodes
        // the encodings through each provider's own KeyFactory, which is the
        // sanctioned crossing and works on a module that cannot generate.
        // My first version called generateKeyPair() here and the CONTROL test
        // failed, which is the correct way to find this.
        if ("DSA".equals(alg))
        {
            return FIPSTestUtil.dsaKeyPair(p.getName());
        }

        KeyPairGenerator g = KeyPairGenerator.getInstance(alg, p);
        if ("RSA".equals(alg) || "DH".equals(alg) || "DSA".equals(alg))
        {
            g.initialize(2048);
        }
        return g.generateKeyPair();
    }
}
