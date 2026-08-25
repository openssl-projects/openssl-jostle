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
 *       3.1.2 and fails on 3.5.7; and ML-KEM / ML-DSA / SLH-DSA, the other way
 *       round - 3.5.x implements all three and 3.1.2 implements none. For PQC
 *       the fetch is a COMPLETE answer, verified by running real operations
 *       under both the -pedantic and the default fipsinstall config
 *       ({@code fips-c-review/probes/pqc_op_probe.c}): unlike DSA signing, no
 *       config switch gates it, so no failure classifier is needed. Also
 *       Ed25519 / Ed448 — the inverse of X25519/X448, absent on 3.1.2 and
 *       present on 3.5.7 — which additionally need
 *       {@link #canFetchSignature} because that family is not
 *       all-or-nothing. And Triple-DES, whose cipher fetch is refused on 3.1.2
 *       and served on 3.5.7 - see {@link #canFetchCipher}, and note that only
 *       the REGISTRATION half is decided here: whether the module will
 *       ENCRYPT with it is a fipsinstall switch no fetch can see, classified
 *       in C like DSA signing.</li>
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
     * Whether the loaded module registers {@code name} as a signature
     * algorithm. Same "any answer other than a definite no registers" rule as
     * {@link #canFetchKeyMgmt}.
     *
     * <p>Needed because the Ed family is not all-or-nothing the way XDH and
     * PQC are: the 3.5.x module registers ED25519, ED25519PH, ED448 and
     * ED448PH but <b>not</b> ED25519CTX, so the keymgmt fetch (which answers
     * only "is there an Ed25519 key type?") cannot decide which Signature
     * names to register. Measured across all three supported configurations by
     * {@code fips-c-review/probes/ed_gate_probe.c}:
     *
     * <pre>
     *   3.1.2               : every Ed name REFUSED (fips=no on that module)
     *   3.5.7 default       : ED25519 ok, ED25519PH ok, ED448 ok, ED448PH ok,
     *                         ED25519CTX REFUSED
     *   3.5.7 -pedantic     : identical to default — no cnf switch gates Ed
     * </pre>
     *
     * <p>The probe verified that the fetch answer tracks reality: driving
     * {@code EVP_DigestSignInit_ex} with {@code instance="Ed25519ctx"} on
     * 3.5.7 fails with "invalid eddsa instance for attempted operation", while
     * every name that fetches signs and verifies. Registering ED25519CTX would
     * therefore be the "registration is not usability" trap —
     * {@code EdSignatureSpi} passes that instance unconditionally for the
     * forced type, so every init would fail.
     */
    static boolean canFetchSignature(String name)
    {
        return FIPSNISelector.OpenSSLFIPSNI.canFetch(OpenSSLFIPSNI.OP_SIGNATURE, name) != 0;
    }

    /**
     * Whether the loaded module resolves {@code name} as a symmetric cipher.
     * Same "any answer other than a definite no registers" rule as
     * {@link #canFetchKeyMgmt}.
     *
     * <p>Needed for Triple-DES, the third straight family flip: DES-EDE3 is
     * {@code fips=no} on 3.1.2 and {@code fips=yes} on 3.5.x. Measured across
     * all three supported configurations by
     * {@code fips-c-review/probes/tdes_gate_probe.c}:
     *
     * <pre>
     *   3.1.2               : DES-EDE3-CBC / -ECB / DES-EDE3 all REFUSED
     *   3.5.7 default       : all three fetch, provider=fips, both directions run
     *   3.5.7 -pedantic     : all three fetch — but ENCRYPTION is refused
     * </pre>
     *
     * <p>The fetch is therefore the complete answer to <i>registration</i>, and
     * deliberately not to <i>usability</i>: the {@code tdes-encrypt-disabled}
     * fipsinstall switch refuses the encrypt direction at operation time, which
     * no fetch can see. That half is classified where it fails, in C, and
     * surfaces as {@code ProviderCapabilityException} via
     * {@code JO_TDES_ENCRYPT_UNAVAILABLE} — decryption keeps working on every
     * configuration, so the family stays registered.
     */
    static boolean canFetchCipher(String name)
    {
        return FIPSNISelector.OpenSSLFIPSNI.canFetch(OpenSSLFIPSNI.OP_CIPHER, name) != 0;
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
