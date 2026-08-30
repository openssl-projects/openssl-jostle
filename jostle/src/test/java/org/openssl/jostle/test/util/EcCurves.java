/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.test.util;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 * The named curves the loaded OpenSSL build serves, shared by the EC tests.
 *
 * <p>Shared rather than duplicated per class: two copies of an 82-entry list
 * drift, and a curve added to one and not the other is exactly the silent gap
 * the agreement classes exist to catch.
 */
public final class EcCurves
{
    private EcCurves()
    {
    }

    /**
     * Every curve name the build's EC KeyPairGenerator accepts. Sourced from
     * OpenSSL's builtin curve table.
     */
    public static final String[] BUILTIN = {
            "secp112r1", "secp112r2", "secp128r1", "secp128r2", "secp160k1",
            "secp160r1", "secp160r2", "secp192k1", "secp224k1", "secp224r1",
            "secp256k1", "secp384r1", "secp521r1", "prime192v1", "prime192v2",
            "prime192v3", "prime239v1", "prime239v2", "prime239v3", "prime256v1",
            "sect113r1", "sect113r2", "sect131r1", "sect131r2", "sect163k1",
            "sect163r1", "sect163r2", "sect193r1", "sect193r2", "sect233k1",
            "sect233r1", "sect239k1", "sect283k1", "sect283r1", "sect409k1",
            "sect409r1", "sect571k1", "sect571r1", "c2pnb163v1", "c2pnb163v2",
            "c2pnb163v3", "c2pnb176v1", "c2tnb191v1", "c2tnb191v2", "c2tnb191v3",
            "c2pnb208w1", "c2tnb239v1", "c2tnb239v2", "c2tnb239v3", "c2pnb272w1",
            "c2pnb304w1", "c2tnb359v1", "c2pnb368w1", "c2tnb431r1",
            "wap-wsg-idm-ecid-wtls1", "wap-wsg-idm-ecid-wtls3",
            "wap-wsg-idm-ecid-wtls4", "wap-wsg-idm-ecid-wtls5",
            "wap-wsg-idm-ecid-wtls6", "wap-wsg-idm-ecid-wtls7",
            "wap-wsg-idm-ecid-wtls8", "wap-wsg-idm-ecid-wtls9",
            "wap-wsg-idm-ecid-wtls10", "wap-wsg-idm-ecid-wtls11",
            "wap-wsg-idm-ecid-wtls12", "Oakley-EC2N-3", "Oakley-EC2N-4",
            "brainpoolP160r1", "brainpoolP160t1", "brainpoolP192r1",
            "brainpoolP192t1", "brainpoolP224r1", "brainpoolP224t1",
            "brainpoolP256r1", "brainpoolP256t1", "brainpoolP320r1",
            "brainpoolP320t1", "brainpoolP384r1", "brainpoolP384t1",
            "brainpoolP512r1", "brainpoolP512t1", "SM2"
    };

    /**
     * The 15 curves of {@link #BUILTIN} that BouncyCastle's KeyPairGenerator
     * does NOT accept, measured against the pinned BC release. Named rather
     * than silently intersected away, so a completeness guard can account for
     * them and so a curve BC gains later shows up as a stale entry.
     *
     * <p>Every one is a legacy or regional curve: the WAP/WTLS set, the two
     * Oakley EC2N groups, {@code c2pnb176v1}, and {@code SM2} — which BC does
     * serve, but under its own {@code sm2p256v1} spelling rather than this one.
     */
    public static final Set<String> NOT_IN_BOUNCYCASTLE =
            Collections.unmodifiableSet(new HashSet<String>(Arrays.asList(
                    "c2pnb176v1",
                    "wap-wsg-idm-ecid-wtls1", "wap-wsg-idm-ecid-wtls3",
                    "wap-wsg-idm-ecid-wtls4", "wap-wsg-idm-ecid-wtls5",
                    "wap-wsg-idm-ecid-wtls6", "wap-wsg-idm-ecid-wtls7",
                    "wap-wsg-idm-ecid-wtls8", "wap-wsg-idm-ecid-wtls9",
                    "wap-wsg-idm-ecid-wtls10", "wap-wsg-idm-ecid-wtls11",
                    "wap-wsg-idm-ecid-wtls12",
                    "Oakley-EC2N-3", "Oakley-EC2N-4",
                    "SM2")));

    /**
     * The curves that do ECDH but on which OpenSSL refuses ECDSA SIGNING —
     * every registered {@code *withECDSA} name, the raw one included.
     *
     * <p>The two Oakley EC2N groups are RFC 2409 key-agreement groups, not
     * signature curves; {@code ecdsa_sign_setup} rejects them with a BN-lib
     * error. Measured: signing fails on all ten registered names for these two
     * and succeeds on all ten for every other curve the build serves,
     * including the 112-bit ones — so this is about these groups, not about
     * small orders.
     *
     * <p>Named rather than skipped so the refusal is asserted; see
     * {@code ECAgreementTest.oakleyCurvesDoEcdhButRefuseEcdsaSigning}.
     */
    public static final Set<String> NO_ECDSA_SIGNING =
            Collections.unmodifiableSet(new HashSet<String>(Arrays.asList(
                    "Oakley-EC2N-3", "Oakley-EC2N-4")));
}
