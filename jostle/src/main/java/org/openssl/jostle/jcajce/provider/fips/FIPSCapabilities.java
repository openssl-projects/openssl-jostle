/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider.fips;

/**
 * What the FIPS module that is actually loaded can do.
 *
 * <p>JSLFIPS ships ONE build that has to serve two modules which disagree
 * about what they implement — the CMVP-validated 3.1.2 and a 3.5.x once its
 * certificate lands — and they disagree in <i>both</i> directions, so no
 * compiled-in registration list is right for both. Registration is therefore
 * decided by asking the loaded module, not by transcribing a table (the rule
 * in {@code java-spi.md}: <i>OpenSSL is the single source of truth — query and
 * cache, never transcribe</i>).
 *
 * <h2>Scope — read before adding anything here</h2>
 *
 * Probing exists <b>only</b> for capabilities that legitimately differ between
 * <i>supported</i> modules. Everything else is a build-time question, answered
 * by {@code FIPSServedSurfaceSmokeTest} against whichever module CI pins. A
 * blanket probe over every algorithm would add cache and thread-safety
 * machinery to ~145 services that need none, and — worse — would make a
 * genuinely broken module load indistinguishable from a legitimately absent
 * feature. Fail loud, as the rest of this codebase does.
 *
 * <p>Two kinds of question, two mechanisms:
 *
 * <ol>
 *   <li><b>"Should this be registered?"</b> — must be answered at provider
 *       construction, so only a cheap probe can inform it. Where one can,
 *       conditional registration beats a use-time gate:
 *       {@code NoSuchAlgorithmException} from {@code getInstance} is a cleaner
 *       contract than a service that resolves and then refuses, and it lets
 *       the caller fall through to another provider. This class serves that
 *       question. Currently: X25519 / X448, whose keymgmt fetch succeeds on
 *       3.1.2 and fails on 3.5.7.</li>
 *   <li><b>"Will this operation actually work?"</b> — answerable only by doing
 *       it, so it is <b>not</b> here. DSA key generation and PKCS#1 v1.5
 *       encrypt both fetch and init happily on either module; only the real
 *       call refuses. Those are classified where they fail, in C, and surface
 *       as {@link org.openssl.jostle.jcajce.provider.ProviderCapabilityException}
 *       (see {@code classify_dsa_gen_failure} in {@code dsa.c}).</li>
 * </ol>
 *
 * <p>Adding a third entry is a deliberate act: it needs a
 * {@code fips-c-review/probes/capability_probe.c} run showing the two modules
 * genuinely disagree, and the measured evidence recorded at the gate.
 *
 * <p>This is <b>capability</b> filtering, never <b>approval</b> filtering.
 * JSLFIPS deliberately does not filter its surface against the security
 * policy's approved-services tables — that determination belongs to the
 * operator, and hand-maintaining a subset is how working algorithms were
 * removed from callers in the past. A service absent here is absent because
 * the module cannot perform it at all.
 */
final class FIPSCapabilities
{
    private FIPSCapabilities()
    {
    }

    /**
     * Cached {@link OpenSSLFIPSNI#moduleVersion()}. The module cannot change
     * within a JVM ({@code FIPSOpenSSL.initialise} is one-shot and rejects a
     * differing configuration), so one query suffices. A concurrent double
     * probe is benign — both threads compute the same string.
     */
    private static volatile String moduleVersion;

    /**
     * Whether the loaded module resolves {@code name} as a key-management
     * algorithm.
     *
     * <p>Any answer other than a definite "no" registers. A probe that fails
     * for its own reasons (a negative JO_* code) must not silently drop a
     * service — register, and let the operation fail typed if it truly cannot
     * run.
     */
    static boolean canFetchKeyMgmt(String name)
    {
        return FIPSNISelector.OpenSSLFIPSNI.canFetch(OpenSSLFIPSNI.OP_KEYMGMT, name) != 0;
    }

    /**
     * The loaded module's self-reported name and version — e.g.
     * {@code "OpenSSL FIPS Provider 3.1.2"} — or {@code "unknown FIPS module"}
     * when it cannot be queried.
     *
     * <p><b>For messages and diagnostics only.</b> Never branch on this: a
     * version names the build, not the capability (redistributors ship their
     * own modules, and an operator can re-enable a gated operation through the
     * module config), and a version-keyed branch is exactly the transcribed
     * table this class exists to avoid.
     */
    static String describeModule()
    {
        String v = moduleVersion;
        if (v == null)
        {
            v = FIPSNISelector.OpenSSLFIPSNI.moduleVersion();
            if (v == null || v.isEmpty())
            {
                v = "unknown FIPS module";
            }
            moduleVersion = v;
        }
        return v;
    }
}
