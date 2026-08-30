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

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.util.asn1.Der;

import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.Security;

/**
 * Tier-1 type ceilings in {@link Der}: an OCTET STRING or INTEGER whose
 * content exceeds the configured ceiling is refused even when the call site
 * declares no field cap of its own.
 *
 * <p>Measured before the ceilings existed, with the bytes GENUINELY PRESENT
 * (so this is not a claimed-length trick and not a free OOM primitive — an
 * attacker must send 8 MiB to get 8 MiB): the IV codec accepted an
 * 8,388,608-byte IV, GCM an 8 MiB nonce, and DSA and DH a 67,108,857-bit p.
 * The cost is not the single allocation but what follows it — the value is
 * held in SPI state and copied again on every {@code getIV()} /
 * {@code getEncoded()}.
 *
 * <p>Each ceiling is pinned at BOTH sides of its boundary: the exact ceiling
 * must be accepted and one byte more refused. A one-sided test would pass
 * against a ceiling set anywhere below the value it happens to try.
 */
public class DerTypeCeilingTest
{
    @BeforeAll
    static void before()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    @AfterEach
    void clearOverrides()
    {
        System.clearProperty(Der.MAX_OCTET_STRING_PROPERTY);
        System.clearProperty(Der.MAX_INTEGER_PROPERTY);
    }

    /** DER TLV, definite length, long form where needed. */
    private static byte[] tlv(int tag, byte[] content)
    {
        int n = content.length;
        byte[] len;
        if (n < 128)
        {
            len = new byte[]{(byte) n};
        }
        else
        {
            int count = 0;
            for (int t = n; t != 0; t >>>= 8)
            {
                count++;
            }
            len = new byte[1 + count];
            len[0] = (byte) (0x80 | count);
            for (int i = 0; i < count; i++)
            {
                len[1 + count - 1 - i] = (byte) (n >>> (8 * i));
            }
        }
        byte[] out = new byte[1 + len.length + n];
        out[0] = (byte) tag;
        System.arraycopy(len, 0, out, 1, len.length);
        System.arraycopy(content, 0, out, 1 + len.length, n);
        return out;
    }

    private static byte[] octetStringOf(int n)
    {
        return tlv(Der.OCTET_STRING, new byte[n]);
    }

    /** A DSA Dss-Parms SEQUENCE whose p has {@code n} content octets. */
    private static byte[] dsaWithPOf(int n)
    {
        byte[] p = new byte[n];
        p[0] = 0x01;                       // non-zero leading octet: minimal, positive
        byte[] inner = new byte[0];
        inner = concat(inner, tlv(Der.INTEGER, p));
        inner = concat(inner, tlv(Der.INTEGER, new byte[]{0x03}));
        inner = concat(inner, tlv(Der.INTEGER, new byte[]{0x02}));
        return tlv(Der.SEQUENCE, inner);
    }

    private static byte[] concat(byte[] a, byte[] b)
    {
        byte[] o = new byte[a.length + b.length];
        System.arraycopy(a, 0, o, 0, a.length);
        System.arraycopy(b, 0, o, a.length, b.length);
        return o;
    }

    private static void init(String alg, byte[] enc) throws Exception
    {
        AlgorithmParameters p = AlgorithmParameters.getInstance(alg, JostleProvider.PROVIDER_NAME);
        p.init(enc);
    }

    @Test
    public void octetStringCeilingIsPinnedAtBothSides() throws Exception
    {
        int ceiling = Der.DEFAULT_MAX_OCTET_STRING_BYTES;

        // AT the ceiling: accepted. The IV codec applies no field cap of its
        // own (it serves families with different block sizes), so the type
        // ceiling is the only bound and this is what it must still allow.
        init("AES", octetStringOf(ceiling));

        IOException e = Assertions.assertThrows(IOException.class,
                () -> init("AES", octetStringOf(ceiling + 1)),
                "one byte past the ceiling must be refused");
        Assertions.assertTrue(e.getMessage().contains("ceiling"),
                "message should name the ceiling, got: " + e.getMessage());
    }

    @Test
    public void integerCeilingIsPinnedAtBothSides() throws Exception
    {
        int ceiling = Der.DEFAULT_MAX_INTEGER_BYTES;

        // AT the ceiling the INTEGER is read; DSA then rejects it on its own
        // semantics, which is a DIFFERENT refusal and must not be mistaken for
        // the ceiling firing — so assert on the message, not merely on throwing.
        try
        {
            init("DSA", dsaWithPOf(ceiling));
        }
        catch (IOException at)
        {
            Assertions.assertFalse(at.getMessage() != null && at.getMessage().contains("ceiling"),
                    "the ceiling must NOT fire at exactly the ceiling: " + at.getMessage());
        }

        IOException e = Assertions.assertThrows(IOException.class,
                () -> init("DSA", dsaWithPOf(ceiling + 1)),
                "one byte past the ceiling must be refused");
        Assertions.assertTrue(e.getMessage().contains("ceiling"),
                "message should name the ceiling, got: " + e.getMessage());
    }

    @Test
    public void theOctetStringCeilingIsSettable() throws Exception
    {
        // Below the default: a value the default would accept is now refused.
        System.setProperty(Der.MAX_OCTET_STRING_PROPERTY, "64");
        init("AES", octetStringOf(64));
        IOException e = Assertions.assertThrows(IOException.class,
                () -> init("AES", octetStringOf(65)),
                "the lowered ceiling must be in force");
        Assertions.assertTrue(e.getMessage().contains("64-byte ceiling"),
                "message should quote the configured ceiling, got: " + e.getMessage());

        // Above the default: a value the default would refuse is now accepted,
        // which is what makes this a genuine override rather than a floor.
        System.setProperty(Der.MAX_OCTET_STRING_PROPERTY,
                Integer.toString(Der.DEFAULT_MAX_OCTET_STRING_BYTES * 2));
        init("AES", octetStringOf(Der.DEFAULT_MAX_OCTET_STRING_BYTES + 1));
    }

    /**
     * The fail-open fallback, pinned as behaviour rather than left as a
     * comment. {@code Properties.asInteger} throws on a non-numeric value and
     * a value of zero or less would refuse every field, so an unusable setting
     * is ignored and the DEFAULT applies.
     *
     * <p>Both halves are asserted deliberately. A test that only showed a
     * moderate field being accepted would pass equally against a fallback that
     * removed the ceiling ALTOGETHER — which is the one outcome that would
     * matter, since it turns a configuration typo into an unbounded decoder.
     * So each case also requires the default's own boundary to still bite.
     */
    @Test
    public void anUnusableOverrideFallsBackToTheDefaultAndTheDefaultStillBites() throws Exception
    {
        int ceiling = Der.DEFAULT_MAX_OCTET_STRING_BYTES;
        for (String bad : new String[]{"0", "-1", "not-a-number", "", "9999999999999"})
        {
            System.setProperty(Der.MAX_OCTET_STRING_PROPERTY, bad);

            // The default is in force, so a field inside it is accepted...
            init("AES", octetStringOf(1024));
            init("AES", octetStringOf(ceiling));

            // ...and, crucially, one byte past the DEFAULT is still refused.
            // Without this, a fallback that disabled the ceiling would pass.
            IOException e = Assertions.assertThrows(IOException.class,
                    () -> init("AES", octetStringOf(ceiling + 1)),
                    "property=\"" + bad + "\": the default ceiling must still apply");
            Assertions.assertTrue(e.getMessage().contains(ceiling + "-byte ceiling"),
                    "property=\"" + bad + "\": expected the default ceiling in the message, got: "
                            + e.getMessage());
        }
    }

    /**
     * The INTEGER knob, tested the same way as the octet-string one: a valid
     * value must observably take effect in BOTH directions. Testing only the
     * tightening direction would not distinguish a working override from a
     * ceiling that merely got smaller for some other reason.
     */
    @Test
    public void theIntegerCeilingIsSettable() throws Exception
    {
        // Tighten: a p the default would admit is now refused.
        System.setProperty(Der.MAX_INTEGER_PROPERTY, "128");
        IOException e = Assertions.assertThrows(IOException.class,
                () -> init("DSA", dsaWithPOf(129)),
                "the lowered INTEGER ceiling must be in force");
        Assertions.assertTrue(e.getMessage().contains("128-byte ceiling"),
                "message should quote the configured ceiling, got: " + e.getMessage());

        // Widen: a p the default would refuse must now get past the ceiling.
        // DSA may still reject it on its own semantics, so the assertion is
        // that the CEILING is no longer what stops it.
        System.setProperty(Der.MAX_INTEGER_PROPERTY,
                Integer.toString(Der.DEFAULT_MAX_INTEGER_BYTES * 4));
        try
        {
            init("DSA", dsaWithPOf(Der.DEFAULT_MAX_INTEGER_BYTES + 1));
        }
        catch (IOException widened)
        {
            Assertions.assertFalse(widened.getMessage().contains("ceiling"),
                    "the widened ceiling must no longer be the refusal: " + widened.getMessage());
        }
    }

    @Test
    public void theEightMebibyteShapesThatMotivatedTheCeilingAreRefused()
    {
        int big = 8 * 1024 * 1024;
        for (String alg : new String[]{"AES", "GCM"})
        {
            byte[] enc = "AES".equals(alg)
                    ? octetStringOf(big)
                    : tlv(Der.SEQUENCE, octetStringOf(big));
            Assertions.assertThrows(IOException.class, () -> init(alg, enc),
                    alg + " must refuse an 8 MiB octet string");
        }
        Assertions.assertThrows(IOException.class, () -> init("DSA", dsaWithPOf(big)),
                "DSA must refuse an 8 MiB p");
    }

    @Test
    public void theObjectIdentifierCeilingIsNotSettable() throws Exception
    {
        // Spec-bounded, so it stays a hard constant: configurability is for
        // open-endedness, not for permitting a spec violation. Setting either
        // octet-string or integer property must not move it.
        System.setProperty(Der.MAX_OCTET_STRING_PROPERTY, "1000000");
        System.setProperty(Der.MAX_INTEGER_PROPERTY, "1000000");
        byte[] oversizedOid = tlv(Der.OBJECT_IDENTIFIER, new byte[Der.MAX_OID_CONTENT_BYTES + 1]);
        Assertions.assertThrows(IOException.class, () -> init("EC", oversizedOid),
                "the OID ceiling must hold regardless of the other properties");
    }
}
