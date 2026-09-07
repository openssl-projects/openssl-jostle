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

import java.security.MessageDigest;
import java.security.Provider;
import java.util.ArrayList;
import java.util.List;
import java.util.ServiceLoader;

/**
 * Checks that jostle works as a NAMED MODULE. Source-launcher program run
 * against the jar on the module path; nothing here ships inside the jar.
 *
 * <p>Only assertion 1 discriminates a broken descriptor: with the
 * {@code provides} line removed, discovery drops JSL and JSLFIPS (9 providers
 * to 7) while named-module loading, the SHA-256 result and the service count
 * are all unchanged.
 *
 * <p>Exits non-zero naming the failed assertion; an escaping exception is a
 * failure, not a pass.
 */
public class ModulePathCheck
{
    private static final String MODULE = "org.openssl.jostle.prov";
    private static final List<String> FAILURES = new ArrayList<String>();

    private static void check(String assertion, boolean ok, String detail)
    {
        System.out.printf("  [%s] %s%s%n", ok ? "PASS" : "FAIL", assertion,
                detail == null || detail.isEmpty() ? "" : " — " + detail);
        if (!ok)
        {
            FAILURES.add(assertion);
        }
    }

    public static void main(String[] args)
    {
        int rc;
        try
        {
            rc = run();
        }
        catch (Throwable t)
        {
            // Distinct from rc=1 so a CI log can tell an escaping exception
            // apart from a failed assertion.
            System.out.printf("  [FAIL] checker threw: %s: %s%n",
                    t.getClass().getName(), t.getMessage());
            t.printStackTrace(System.out);
            rc = 2;
        }
        System.exit(rc);
    }

    private static int run() throws Exception
    {
        System.out.println("module-path check starting");

        // 1. THE LOAD-BEARING ASSERTION. Everything else below passes against
        //    a jar with no `provides` line; only this sees it.
        Provider jsl = null;
        Provider jslFips = null;
        for (Provider p : ServiceLoader.load(Provider.class))
        {
            if ("JSL".equals(p.getName()))
            {
                jsl = p;
            }
            if ("JSLFIPS".equals(p.getName()))
            {
                jslFips = p;
            }
        }
        check("ServiceLoader discovers JSL", jsl != null,
                jsl == null ? "not found — is `provides java.security.Provider` present?" : null);
        check("ServiceLoader discovers JSLFIPS", jslFips != null,
                jslFips == null ? "not found — is it in the `provides` list?" : null);
        if (jsl == null || jslFips == null)
        {
            return report();
        }

        check("JSL comes from module " + MODULE,
                MODULE.equals(jsl.getClass().getModule().getName()),
                "got " + jsl.getClass().getModule().getName());
        check("JSLFIPS comes from module " + MODULE,
                MODULE.equals(jslFips.getClass().getModule().getName()),
                "got " + jslFips.getClass().getModule().getName());
        check("JSL module is named", jsl.getClass().getModule().isNamed(), null);

        // 2. The base provider must be usable, not merely discoverable.
        int services = jsl.getServices().size();
        check("JSL registers services", services > 0, "count=" + services);

        // ServiceLoader uses the no-arg constructor, so JSLFIPS cannot be
        // configured here and registers nothing; usability is the FIPS suite's.
        int fipsServices = jslFips.getServices().size();
        check("JSLFIPS registers no services (ServiceLoader cannot configure it)",
                fipsServices == 0, "count=" + fipsServices);

        // The bridge name is set only once native init succeeds, so a concrete
        // JNI or FFI proves the library loaded from inside the named module.
        String bridge = org.openssl.jostle.Loader.getInterfaceTypeName();
        check("native bridge resolved to JNI or FFI",
                "JNI".equals(bridge) || "FFI".equals(bridge), "bridge=" + bridge);

        // 5. One operation end to end, so a registered-but-broken service
        //    cannot pass. Digest of a known input, length and content checked.
        MessageDigest md = MessageDigest.getInstance("SHA-256", jsl);
        byte[] d = md.digest("jostle module path".getBytes("UTF-8"));
        check("SHA-256 through JSL returns 32 bytes", d.length == 32, "len=" + d.length);
        boolean allZero = true;
        for (byte b : d)
        {
            if (b != 0)
            {
                allZero = false;
                break;
            }
        }
        check("SHA-256 output is not a zero buffer", !allZero, null);
        byte[] again = MessageDigest.getInstance("SHA-256", jsl)
                .digest("jostle module path!".getBytes("UTF-8"));
        boolean differs = false;
        for (int i = 0; i < d.length; i++)
        {
            if (d[i] != again[i])
            {
                differs = true;
                break;
            }
        }
        check("a changed input changes the digest", differs, null);

        return report();
    }

    private static int report()
    {
        if (FAILURES.isEmpty())
        {
            System.out.println("module-path check: OK");
            return 0;
        }
        System.out.println("module-path check: FAILED (" + FAILURES.size() + ")");
        for (String f : FAILURES)
        {
            System.out.println("  failed: " + f);
        }
        return 1;
    }
}
