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

package org.openssl.jostle.test.cert;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.test.certpath.PkitsCertificates;

import java.io.ByteArrayInputStream;
import java.security.InvalidKeyException;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collections;

/**
 * A certificate's public key is decoded by the factory's own provider
 * INSTANCE, not by whatever answers to its name.
 *
 * <p>Asserted on the key's PROVENANCE, never on equality: the wrapper
 * delegates {@code equals}, so an equality assertion is blind to which
 * provider decoded the key — the pre-existing path tests compared equal
 * throughout the defect's life. Provenance is read the way a caller meets it,
 * through MT-14's isolation check: a key is accepted by the instance that made
 * it and refused by any other.
 *
 * <p>Measured before the fix, one PKITS RSA certificate: with the name
 * unregistered the factory handed back {@code sun.security.rsa.RSAPublicKeyImpl}
 * silently, and with a different instance under the name it handed back a key
 * its own provider then refused. That second cell is MT-10's "unwrap returns
 * what its own provider rejects", one surface along.
 */
public class X509CertificateFactoryProviderBindingTest
{
    private static final String EE = "ValidCertificatePathTest1EE.crt";
    private static final String SIG_ALG = "SHA256withRSA";

    /** The MT-14 refusal, pinned so a different refusal cannot read as this one. */
    private static final String FOREIGN_KEY_MESSAGE =
            "public key was created by a different Jostle provider instance; encode it with"
                    + " getEncoded() and decode it through this provider's KeyFactory";

    @BeforeAll
    static void before()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    /**
     * The discriminating cell. The factory is taken from an instance that is
     * NOT the one registered under the name, so a name pin borrows the
     * registered instance's KeyFactory and an instance pin does not.
     */
    @Test
    public void theCertificatesKeyComesFromTheFactorysOwnInstance() throws Exception
    {
        Provider registered = Security.getProvider(JostleProvider.PROVIDER_NAME);
        Provider mine = new JostleProvider();

        Assertions.assertNotNull(registered,
                "vacuity guard: an instance must hold the name, or there is nothing to borrow");
        Assertions.assertNotSame(mine, registered,
                "vacuity guard: the factory's instance must not be the registered one");
        Assertions.assertEquals(registered.getName(), mine.getName(),
                "the two instances share a name — that is what makes this a name-versus-instance test");

        PublicKey key = keyFrom(CertificateFactory.getInstance("X.509", mine));

        assertJostleKey(key);
        assertAcceptedBy(mine, key);
        assertRefusedBy(registered, key);
    }

    /**
     * With the name unregistered entirely, the factory still decodes through
     * its own instance. Before the fix this returned a JDK key, with nothing
     * said.
     */
    @Test
    public void anUnregisteredInstanceDecodesItsOwnKeys() throws Exception
    {
        Provider mine = Security.getProvider(JostleProvider.PROVIDER_NAME);
        CertificateFactory cf = CertificateFactory.getInstance("X.509", mine);

        Security.removeProvider(JostleProvider.PROVIDER_NAME);
        try
        {
            Assertions.assertNull(Security.getProvider(JostleProvider.PROVIDER_NAME),
                    "vacuity guard: the name must actually be unregistered");

            PublicKey key = keyFrom(cf);
            assertJostleKey(key);
            assertAcceptedBy(mine, key);
        }
        finally
        {
            Security.addProvider(mine);
        }
    }

    /**
     * The re-wrap fast path compares provider IDENTITY. A certificate wrapped
     * by one instance, fed to another instance's factory, is re-wrapped — so
     * the second factory's CertPath carries keys the second instance owns. On
     * a name comparison the wrapper passes through and the path carries the
     * first instance's keys, which the second refuses.
     */
    @Test
    public void aWrapperFromAnotherInstanceIsRewrapped() throws Exception
    {
        Provider first = new JostleProvider();
        Provider second = new JostleProvider();
        Assertions.assertNotSame(first, second, "vacuity guard: two distinct instances");

        Certificate wrappedByFirst = CertificateFactory.getInstance("X.509", first)
                .generateCertificate(new ByteArrayInputStream(PkitsCertificates.der(EE)));

        CertPath path = CertificateFactory.getInstance("X.509", second)
                .generateCertPath(Collections.singletonList(wrappedByFirst));

        PublicKey key = path.getCertificates().get(0).getPublicKey();
        assertJostleKey(key);
        assertAcceptedBy(second, key);
        assertRefusedBy(first, key);
    }

    /**
     * The name-only constructor is public API and stays: an out-of-tree caller
     * using it keeps name resolution, which is all it ever had.
     */
    @Test
    public void theNameOnlyFactoryStillResolvesByName() throws Exception
    {
        org.openssl.jostle.jcajce.provider.cert.X509CertificateFactorySpi spi =
                new org.openssl.jostle.jcajce.provider.cert.X509CertificateFactorySpi(
                        JostleProvider.PROVIDER_NAME, false);

        Certificate c = spi.engineGenerateCertificate(
                new ByteArrayInputStream(PkitsCertificates.der(EE)));

        PublicKey key = c.getPublicKey();
        assertJostleKey(key);
        assertAcceptedBy(Security.getProvider(JostleProvider.PROVIDER_NAME), key);
    }

    /**
     * The provider-taking constructor refuses null rather than NPE-ing: it is
     * public API, and there is no unbound realm behind it — the name-only
     * constructor is what a caller without a provider uses.
     */
    @Test
    public void aNullProviderIsRefusedAtConstruction()
    {
        IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class,
                () -> new org.openssl.jostle.jcajce.provider.cert.X509CertificateFactorySpi(
                        (java.security.Provider) null, false));

        Assertions.assertEquals(
                "X509CertificateFactorySpi requires the provider it belongs to;"
                        + " use the name-only constructor when there is none",
                e.getMessage());
    }

    /**
     * ONE FACT, ONE FIELD: none of the classes that carry a provider binding
     * stores the instance and the name side by side, and none has a
     * constructor taking both.
     *
     * <p>Megan, 2026-09-11, on the first version of MT-99: the two fields had
     * "no enforced synchronisation". They did not: the instance decided which
     * provider did the work while the name reached the ProviderException
     * messages and the re-wrap policy comparison, so a divergent pair would
     * have performed the operation in one provider and named another, and
     * every constructor maintained the invariant separately. They now hold a
     * single {@code ProviderBinding} instead, which cannot represent the
     * disagreement.
     *
     * <p>Structural because there is nothing to observe: the instance always
     * won, so a divergent pair changed no output — only the diagnostics, and
     * only on a path no caller reaches today. A behavioural test would pass
     * against the broken shape.
     */
    @Test
    public void noProviderCarryingClassHoldsTheInstanceAndTheNameApart() throws Exception
    {
        String[] classes = {
                "org.openssl.jostle.jcajce.provider.cert.X509CertificateFactorySpi",
                "org.openssl.jostle.jcajce.provider.cert.JSLKeyX509Certificate",
                "org.openssl.jostle.jcajce.provider.dh.DHWithKDFKeyAgreementSpi",
                "org.openssl.jostle.jcajce.provider.ec.ECWithKDFKeyAgreementSpi",
                "org.openssl.jostle.jcajce.provider.ks.KSServiceSPI",
                "org.openssl.jostle.jcajce.provider.certpath.JostleCertPathBuilderSpi",
        };

        java.util.List<String> offenders = new java.util.ArrayList<String>();
        int fieldsSeen = 0;
        int ctorsSeen = 0;

        for (String cn : classes)
        {
            Class<?> c = Class.forName(cn);

            // COUNT the fields that carry a provider identity — a Provider,
            // a ProviderBinding, or a String whose name says it is one — and
            // require at most one.
            //
            // Read from the SOURCE of every multi-release copy, not by
            // reflection. Reflection sees only the copy this JVM loads, and
            // KSServiceSPI has a java9 twin: measured, a `String providerName`
            // added to the BASELINE copy left the reflective check green on
            // JDK 25, because the java9 copy is what ran. A guard that can
            // only see one copy reports "clean" for the others.
            java.util.List<String> carriers = fieldsCarryingAProvider(cn);
            fieldsSeen += carriers.size();
            if (carriers.isEmpty())
            {
                // Per-class vacuity: every one of these carries a provider, so
                // finding none means the scanner is not reading this class and
                // its "clean" verdict is worthless.
                offenders.add(cn + ": no provider-carrying field found at all — the scan is not"
                        + " reading this class");
            }
            else if (carriers.size() > 1)
            {
                offenders.add(cn + ": holds the provider identity in " + carriers.size()
                        + " fields " + carriers + ", so they can disagree");
            }

            // The constructor half reads the SOURCE, not reflection: a
            // parameter list is (Provider, String) whether the String is a
            // provider name or a digest name, and the first version of this
            // cell flagged both agreement SPIs for their `String digest`.
            // Parameter NAMES are only in the source unless -parameters is on.
            for (String params : constructorParameterLists(cn))
            {
                ctorsSeen++;
                if (params.contains("Provider ") && PROVIDER_NAME_PARAM.matcher(params).find())
                {
                    offenders.add(cn + ": constructor takes a provider instance AND a provider"
                            + " name as independent arguments (" + params + ")");
                }
            }
        }

        Assertions.assertTrue(fieldsSeen >= classes.length && ctorsSeen >= 12,
                "vacuity guard: only " + fieldsSeen + " provider-carrying fields and " + ctorsSeen
                        + " constructors read across " + classes.length + " classes");
        Assertions.assertTrue(offenders.isEmpty(),
                "one fact, one field — a value derivable from another must not be stored beside"
                        + " it, and no constructor may take the pair as independent arguments:\n  "
                        + String.join("\n  ", offenders));
    }

    /** A {@code String} parameter whose NAME says it carries a provider. */
    private static final java.util.regex.Pattern PROVIDER_NAME_PARAM =
            java.util.regex.Pattern.compile("\\bString\\s+\\w*[pP]rovider\\w*");

    /**
     * Comment-stripped source of EVERY multi-release copy of the class. Both
     * halves read this rather than reflecting, so neither can be blind to a
     * copy the running JVM does not load.
     */
    private static java.util.List<String> sourcesOf(String className) throws java.io.IOException
    {
        java.util.List<String> out = new java.util.ArrayList<String>();
        for (String base : new String[]{"jostle/src/main", "src/main"})
        {
            for (String level : new String[]{"java", "java9", "java11", "java15", "java17",
                    "java21", "java25"})
            {
                java.nio.file.Path p = java.nio.file.Paths.get(base, level,
                        className.replace('.', '/') + ".java");
                if (java.nio.file.Files.isRegularFile(p))
                {
                    out.add(new String(java.nio.file.Files.readAllBytes(p),
                            java.nio.charset.StandardCharsets.UTF_8)
                            .replaceAll("(?s)/\\*.*?\\*/", " ").replaceAll("//[^\n]*", " "));
                }
            }
        }
        Assertions.assertFalse(out.isEmpty(),
                "no source found for " + className + " — the check would pass vacuously");
        return out;
    }

    /** Declared fields that carry a provider identity, across every copy. */
    private static java.util.List<String> fieldsCarryingAProvider(String className)
            throws java.io.IOException
    {
        java.util.regex.Pattern field = java.util.regex.Pattern.compile(
                "(?m)^\\s*(?:private|protected|public)\\s+(?:static\\s+)?(?:final\\s+)?"
                        + "([\\w.]+)\\s+(\\w+)\\s*[;=]");
        java.util.List<String> out = new java.util.ArrayList<String>();
        for (String code : sourcesOf(className))
        {
            java.util.regex.Matcher m = field.matcher(code);
            while (m.find())
            {
                String type = m.group(1);
                String name = m.group(2);
                String simpleType = type.substring(type.lastIndexOf('.') + 1);
                boolean carries = "Provider".equals(simpleType)
                        || "ProviderBinding".equals(simpleType)
                        || ("String".equals(simpleType)
                            && name.toLowerCase(java.util.Locale.ROOT).contains("provider"));
                if (carries && !out.contains(simpleType + " " + name))
                {
                    out.add(simpleType + " " + name);
                }
            }
        }
        return out;
    }

    /** Parameter lists of every declared constructor, read from the source. */
    private static java.util.List<String> constructorParameterLists(String className)
            throws java.io.IOException
    {
        String simple = className.substring(className.lastIndexOf('.') + 1);
        String code = String.join("\n", sourcesOf(className));

        java.util.List<String> out = new java.util.ArrayList<String>();
        java.util.regex.Matcher m = java.util.regex.Pattern
                .compile("\\b" + simple + "\\s*\\(").matcher(code);
        while (m.find())
        {
            int depth = 1;
            int i = m.end();
            StringBuilder sb = new StringBuilder();
            while (i < code.length() && depth > 0)
            {
                char ch = code.charAt(i);
                if (ch == '(')
                {
                    depth++;
                }
                else if (ch == ')')
                {
                    depth--;
                    if (depth == 0)
                    {
                        break;
                    }
                }
                sb.append(ch);
                i++;
            }
            // Declarations only: a constructor header is followed by "{" or
            // "throws", whereas `new Foo(...)` and `this(...)` are not.
            String after = code.substring(Math.min(i + 1, code.length()),
                    Math.min(i + 30, code.length())).trim();
            if (after.startsWith("{") || after.startsWith("throws"))
            {
                out.add(String.join(" ", sb.toString().trim().split("\\s+")));
            }
        }
        return out;
    }

    private static PublicKey keyFrom(CertificateFactory cf) throws Exception
    {
        X509Certificate c = (X509Certificate) cf.generateCertificate(
                new ByteArrayInputStream(PkitsCertificates.der(EE)));
        return c.getPublicKey();
    }

    /**
     * Without this, a JDK key would be refused by BOTH instances and the
     * refusal half would pass for the wrong reason.
     */
    private static void assertJostleKey(PublicKey key)
    {
        Assertions.assertTrue(key.getClass().getName().startsWith("org.openssl.jostle."),
                "the key must be one this provider decoded; was " + key.getClass().getName());
    }

    private static void assertAcceptedBy(Provider p, PublicKey key) throws Exception
    {
        Signature v = Signature.getInstance(SIG_ALG, p);
        v.initVerify(key);
    }

    private static void assertRefusedBy(Provider p, PublicKey key) throws Exception
    {
        Signature v = Signature.getInstance(SIG_ALG, p);
        InvalidKeyException e = Assertions.assertThrows(InvalidKeyException.class,
                () -> v.initVerify(key),
                "a key made by another instance must be refused, or provenance is not being tested");
        Assertions.assertEquals(FOREIGN_KEY_MESSAGE, e.getMessage());
    }
}
