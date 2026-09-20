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

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cms.CCMParameters;
import org.bouncycastle.asn1.cms.GCMParameters;
import org.bouncycastle.asn1.pkcs.DHParameter;
import org.bouncycastle.asn1.x509.DSAParameter;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X962Parameters;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.test.util.AlgorithmParametersSurfaceDriver;
import org.openssl.jostle.test.util.ProviderSurfaceGuard;
import org.openssl.jostle.util.Arrays;

import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.io.IOException;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.spec.InvalidParameterSpecException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.DSAParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.List;

/**
 * BouncyCastle as a SECOND reference for every bespoke ASN.1 codec, alongside
 * the SunJCE parity in {@code AlgorithmParametersWireTest}. The two answer
 * different questions: SunJCE pins well-formed-data parity on the codecs it
 * implements, BC's ASN.1 layer carries decades of CVE-driven hardening and
 * covers the codecs SunJCE has no implementation for at all.
 *
 * <p><b>What this class is for.</b> Measured while designing it, every codec
 * ALREADY agreed with BC byte for byte — so these are regression pins, not a
 * bug hunt, and saying so is the honest description. The value is that
 * {@code CCMAlgorithmParameters} had no external reference of any kind (it
 * does not even use {@link org.openssl.jostle.util.asn1.Der} — it hand-rolls
 * its own writer and reader), so its RFC 5084 conformance rested entirely on
 * the implementation being right, with nothing pinning it.
 *
 * <p><b>Import discipline.</b> {@code CCMParameters} and {@code GCMParameters}
 * are taken from <b>bcutil</b>'s {@code org.bouncycastle.asn1.cms}. bcprov
 * carries same-named classes under {@code org.bouncycastle.internal.asn1.cms}
 * — an INTERNAL package with no API stability promise, which must not be used
 * here however conveniently the IDE offers it.
 *
 * <p><b>Sanctioning note.</b> These tests deliberately put BouncyCastle on the
 * test classpath, which is the masking risk that once hid a production
 * delegation to a foreign provider. {@code UnpinnedServiceResolutionParityTest}
 * is the compensating control and must stay: a source lint cannot be masked by
 * a test-classpath dependency, which is exactly why it is a source lint.
 */
public class AlgorithmParametersAgreementTest
{
    private static final String JSL = JostleProvider.PROVIDER_NAME;
    private static final SecureRandom RANDOM = new SecureRandom();

    @BeforeAll
    static void before()
    {
        if (Security.getProvider(JSL) == null)
        {
            Security.addProvider(new JostleProvider());
        }
        // The cells below this compare against BouncyCastle's LIGHTWEIGHT
        // ASN.1 classes, which need no provider. The discovery guard compares
        // against BC's JCE codecs, which do.
        if (Security.getProvider("BC") == null)
        {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        }
    }

    private static byte[] encodedOf(String alg, java.security.spec.AlgorithmParameterSpec spec)
        throws Exception
    {
        AlgorithmParameters p = AlgorithmParameters.getInstance(alg, JSL);
        p.init(spec);
        return p.getEncoded();
    }

    private static byte[] nonce(int n)
    {
        byte[] b = new byte[n];
        RANDOM.nextBytes(b);
        return b;
    }

    // ----------------------------------------------------------------
    // (a) byte equality, and (b) cross-decode in both directions
    // ----------------------------------------------------------------

    /**
     * CCM tops the priority: it is the only codec with no external reference
     * at all, and the only one that does not ride {@code Der}.
     *
     * <p>Kept: reads back through BouncyCastle's lightweight CCMParameters, a
     * different source from the JCE codec the guard uses.
     */
    @Test
    public void ccmMatchesBouncyCastleAndCrossDecodes() throws Exception
    {
        int[][] cases = {{12, 12}, {12, 16}, {12, 8}, {7, 4}, {13, 16}, {8, 6}, {11, 10}, {13, 14}};
        for (int[] c : cases)
        {
            byte[] n = nonce(c[0]);
            int icv = c[1];
            byte[] jostle = encodedOf("CCM", new GCMParameterSpec(icv * 8, n));
            byte[] bc = new CCMParameters(n, icv).toASN1Primitive().getEncoded("DER");
            Assertions.assertArrayEquals(bc, jostle,
                    "CCM nonce=" + c[0] + " icv=" + icv + " diverged from BouncyCastle");

            // BC bytes -> Jostle
            AlgorithmParameters back = AlgorithmParameters.getInstance("CCM", JSL);
            back.init(bc);
            GCMParameterSpec got = back.getParameterSpec(GCMParameterSpec.class);
            Assertions.assertTrue(Arrays.areEqual(n, got.getIV()), "CCM nonce lost decoding BC bytes");
            Assertions.assertEquals(icv * 8, got.getTLen(), "CCM ICV lost decoding BC bytes");

            // Jostle bytes -> BC
            CCMParameters bcBack = CCMParameters.getInstance(ASN1Primitive.fromByteArray(jostle));
            Assertions.assertTrue(Arrays.areEqual(n, bcBack.getNonce()), "BC read a different CCM nonce");
            Assertions.assertEquals(icv, bcBack.getIcvLen(), "BC read a different CCM ICV length");
        }
    }

    /*
     * Kept: reads back through BouncyCastle's lightweight GCMParameters, a
     * different source from the JCE codec the guard uses.
     */
    @Test
    public void gcmMatchesBouncyCastleAndCrossDecodes() throws Exception
    {
        for (int icv : new int[]{12, 13, 14, 15, 16})
        {
            byte[] n = nonce(12);
            byte[] jostle = encodedOf("GCM", new GCMParameterSpec(icv * 8, n));
            byte[] bc = new GCMParameters(n, icv).toASN1Primitive().getEncoded("DER");
            Assertions.assertArrayEquals(bc, jostle, "GCM icv=" + icv + " diverged from BouncyCastle");

            AlgorithmParameters back = AlgorithmParameters.getInstance("GCM", JSL);
            back.init(bc);
            GCMParameterSpec got = back.getParameterSpec(GCMParameterSpec.class);
            Assertions.assertTrue(Arrays.areEqual(n, got.getIV()), "GCM nonce lost decoding BC bytes");
            Assertions.assertEquals(icv * 8, got.getTLen(), "GCM ICV lost decoding BC bytes");

            GCMParameters bcBack = GCMParameters.getInstance(ASN1Primitive.fromByteArray(jostle));
            Assertions.assertTrue(Arrays.areEqual(n, bcBack.getNonce()), "BC read a different GCM nonce");
            Assertions.assertEquals(icv, bcBack.getIcvLen(), "BC read a different GCM ICV length");
        }
    }

    /**
     * <b>Corpus entry, and a correction to how it was first reported.</b>
     * The design-phase probe recorded this as a DIVERGENCE — BC accepting an
     * ICV length of 8 where Jostle refuses it. That was wrong, and wrong in an
     * instructive way: the probe called Jostle first in the same loop body, so
     * the exception it caught was Jostle's own refusal, and BC's line never
     * ran. Measured directly afterwards, BC enforces the same 12..16 range on
     * BOTH construction and parsing.
     *
     * <p>So the verdict is PARITY, not divergence, and the test asserts what is
     * actually true: both implementations refuse an out-of-range ICV, at both
     * ends of the range. RFC 5084 §3.2 fixes the CMS AES-GCM ICVlen at 12..16
     * and neither side permits otherwise.
     */
    @Test
    public void bothProvidersRefuseAnIcvLengthOutsideRfc5084() throws Exception
    {
        byte[] n = nonce(12);
        for (int icv : new int[]{4, 8, 11, 17, 32})
        {
            Assertions.assertThrows(IllegalArgumentException.class,
                    () -> new GCMParameters(n, icv),
                    "BC must refuse ICVlen " + icv);

            byte[] der = tlv(0x30, concat(tlv(0x04, n), tlv(0x02, new byte[]{(byte) icv})));
            IOException e = Assertions.assertThrows(IOException.class, () ->
                    {
                        AlgorithmParameters p = AlgorithmParameters.getInstance("GCM", JSL);
                        p.init(der);
                    },
                    "Jostle must refuse ICVlen " + icv);
            // The DECODE path has its own message, distinct from the one the
            // spec-init path emits ("must be 12..16 bytes"); pin the text that
            // actually reaches a caller decoding wire bytes.
            Assertions.assertEquals("GCM ICV length out of range: " + icv, e.getMessage());
        }

        // Control: the range itself is not refused wholesale.
        for (int icv : new int[]{12, 16})
        {
            byte[] der = tlv(0x30, concat(tlv(0x04, n), tlv(0x02, new byte[]{(byte) icv})));
            AlgorithmParameters p = AlgorithmParameters.getInstance("GCM", JSL);
            p.init(der);
        }
    }

    /*
     * Kept: compares against BouncyCastle's lightweight DSAParameter, not its
     * JCE codec.
     */
    @Test
    public void dsaMatchesBouncyCastle() throws Exception
    {
        AlgorithmParameterGenerator g = AlgorithmParameterGenerator.getInstance("DSA", JSL);
        g.init(2048);
        AlgorithmParameters p = g.generateParameters();
        DSAParameterSpec s = p.getParameterSpec(DSAParameterSpec.class);
        Assertions.assertArrayEquals(
                new DSAParameter(s.getP(), s.getQ(), s.getG()).toASN1Primitive().getEncoded("DER"),
                p.getEncoded(), "DSA parameters diverged from BouncyCastle");
    }

    /*
     * Kept: compares against BouncyCastle's lightweight DHParameter, not its
     * JCE codec.
     */
    @Test
    public void dhPkcs3MatchesBouncyCastle() throws Exception
    {
        AlgorithmParameterGenerator g = AlgorithmParameterGenerator.getInstance("DH", JSL);
        g.init(1024);
        AlgorithmParameters p = g.generateParameters();
        DHParameterSpec s = p.getParameterSpec(DHParameterSpec.class);
        Assertions.assertArrayEquals(
                new DHParameter(s.getP(), s.getG(), s.getL()).toASN1Primitive().getEncoded("DER"),
                p.getEncoded(), "DH PKCS#3 parameters diverged from BouncyCastle");
    }

    /*
     * Kept: drives several named curves; the guard drives one.
     */
    @Test
    public void ecNamedCurvesMatchBouncyCastle() throws Exception
    {
        String[][] curves = {
                {"P-256", "secp256r1"}, {"secp384r1", "secp384r1"}, {"P-521", "secp521r1"},
                {"secp256k1", "secp256k1"}, {"brainpoolP256r1", "brainpoolP256r1"},
                {"P-384", "secp384r1"}, {"secp224r1", "secp224r1"},
        };
        int compared = 0;
        for (String[] c : curves)
        {
            ASN1ObjectIdentifier oid = ECNamedCurveTable.getOID(c[1]);
            if (oid == null)
            {
                continue;
            }
            byte[] jostle = encodedOf("EC", new ECGenParameterSpec(c[0]));
            Assertions.assertArrayEquals(new X962Parameters(oid).toASN1Primitive().getEncoded("DER"),
                    jostle, "EC " + c[0] + " diverged from BouncyCastle");
            compared++;
        }
        Assertions.assertTrue(compared >= 5,
                "only " + compared + " curves compared — the fixture has gone vacuous");
    }

    /*
     * Kept: drives three IV lengths against a from-spec DEROctetString; the
     * guard drives one against BouncyCastle's JCE codec.
     */
    @Test
    public void ivCodecMatchesBouncyCastle() throws Exception
    {
        for (int n : new int[]{8, 12, 16})
        {
            byte[] iv = nonce(n);
            Assertions.assertArrayEquals(new DEROctetString(iv).getEncoded("DER"),
                    encodedOf("AES", new IvParameterSpec(iv)),
                    "IV codec diverged from BouncyCastle at " + n + " bytes");
        }
    }

    // ----------------------------------------------------------------
    // (b) negative corpus, including the non-exhausted-sequence shapes
    // ----------------------------------------------------------------

    private static byte[] tlv(int tag, byte[] content)
    {
        int n = content.length;
        byte[] len = n < 128 ? new byte[]{(byte) n} : new byte[]{(byte) 0x81, (byte) n};
        byte[] out = new byte[1 + len.length + n];
        out[0] = (byte) tag;
        System.arraycopy(len, 0, out, 1, len.length);
        System.arraycopy(content, 0, out, 1 + len.length, n);
        return out;
    }

    private static byte[] concat(byte[]... parts)
    {
        int n = 0;
        for (byte[] p : parts)
        {
            n += p.length;
        }
        byte[] o = new byte[n];
        int at = 0;
        for (byte[] p : parts)
        {
            System.arraycopy(p, 0, o, at, p.length);
            at += p.length;
        }
        return o;
    }

    /**
     * Every registered name with a valid encoding, discovered. A hand list
     * here would cover whatever was remembered on the day and its floor would
     * rot the first time a name was added.
     */
    private static List<String[]> codecsWithValidEncodings() throws Exception
    {
        List<String[]> out = new ArrayList<String[]>();
        for (String entry : surfaceNames())
        {
            out.add(new String[]{entry, hex(
                    AlgorithmParametersSurfaceDriver.encodeThrough(JSL, entry))});
        }
        return out;
    }

    /** The registered AlgorithmParameters names, aliases included. */
    private static java.util.SortedSet<String> surfaceNames()
    {
        java.util.SortedSet<String> out = new java.util.TreeSet<String>();
        for (String entry : ProviderSurfaceGuard.registeredSurface(
                Security.getProvider(JSL), AlgorithmParametersSurfaceDriver.PREFIX,
                new String[]{"AlgorithmParameters"}))
        {
            out.add(entry.substring("AlgorithmParameters.".length()));
        }
        return out;
    }

    private static String hex(byte[] b)
    {
        StringBuilder s = new StringBuilder();
        for (byte x : b)
        {
            s.append(String.format("%02x", x));
        }
        return s.toString();
    }

    private static byte[] unhex(String s)
    {
        byte[] o = new byte[s.length() / 2];
        for (int i = 0; i < o.length; i++)
        {
            o[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
        }
        return o;
    }

    /**
     * The EXHAUSTION audit, behaviourally: every decode path must end in
     * {@code requireEnd} or an explicit refusal, so trailing bytes after a
     * complete structure are rejected by every codec. Counting {@code
     * requireEnd} occurrences in the source proves it is present, not that it
     * is on the path — driving each codec proves the latter.
     */
    @Test
    public void everyCodecRefusesTrailingBytes() throws Exception
    {
        List<String[]> codecs = codecsWithValidEncodings();
        Assertions.assertFalse(codecs.isEmpty(),
                "no codec was discovered, so this sweep asserted nothing");
        List<String> accepted = new ArrayList<String>();
        for (String[] c : codecs)
        {
            byte[] valid = unhex(c[1]);
            for (int extra : new int[]{1, 5, 64})
            {
                byte[] junk = new byte[extra];
                RANDOM.nextBytes(junk);
                byte[] withJunk = concat(valid, junk);
                try
                {
                    AlgorithmParameters p = AlgorithmParameters.getInstance(c[0], JSL);
                    p.init(withJunk);
                    accepted.add(c[0] + " +" + extra + " trailing bytes");
                }
                catch (IOException expected)
                {
                    // the contract
                }
            }
            // Exact-length control: the same decoder must accept the
            // untampered encoding, or "rejects everything" would pass above.
            AlgorithmParameters ok = AlgorithmParameters.getInstance(c[0], JSL);
            ok.init(valid);
        }
        Assertions.assertTrue(accepted.isEmpty(),
                "codecs accepted trailing bytes after a complete structure: " + accepted);
    }

    /**
     * The NON-EXHAUSTED-SEQUENCE shape: an extra element INSIDE the SEQUENCE,
     * which trailing-byte tests cannot reach because the outer TLV length still
     * covers it. A codec that reads the elements its schema names and never
     * asserts the sequence is spent accepts this silently.
     */
    @Test
    public void everySequenceCodecRefusesAnExtraElementInside() throws Exception
    {
        // Which names have an inside comes from the SPI CLASS: the CBC and
        // plain-IV codecs are an OCTET STRING and have none.
        List<String[]> cases = new ArrayList<String[]>();
        for (String alg : surfaceNames())
        {
            String spi = AlgorithmParametersSurfaceDriver.spiClassOf(JSL, alg);
            if ("GCMAlgorithmParameters".equals(spi) || "CCMAlgorithmParameters".equals(spi))
            {
                cases.add(new String[]{alg, spi.substring(0, 3) + " parameters"});
            }
            else if ("DSAAlgorithmParameters".equals(spi))
            {
                cases.add(new String[]{alg, "Dss-Parms"});
            }
            else if ("DHAlgorithmParameters".equals(spi))
            {
                cases.add(new String[]{alg, "DHParameter"});
            }
        }
        Assertions.assertFalse(cases.isEmpty(), "no SEQUENCE-shaped codec was discovered");

        List<String> accepted = new ArrayList<String>();
        for (String[] c : cases)
        {
            byte[] valid = AlgorithmParametersSurfaceDriver.encodeThrough(JSL, c[0]);
            // Unwrap the outer SEQUENCE, append one more INTEGER, rewrap.
            Assertions.assertEquals(0x30, valid[0] & 0xFF, c[0] + ": expected an outer SEQUENCE");
            int hdr = (valid[1] & 0x80) == 0 ? 2 : 2 + (valid[1] & 0x7F);
            byte[] inner = new byte[valid.length - hdr];
            System.arraycopy(valid, hdr, inner, 0, inner.length);
            // An extra INTEGER is NOT the right probe: DHParameter's third
            // element is the optional l, and X9.42 adds q and j, so an INTEGER
            // appended to a two-element PKCS#3 structure is a LEGAL three-element
            // one. Measured — DH accepted it, correctly, and the first version of
            // this test reported that as a defect. An OCTET STRING is permitted
            // at no position in any of these schemas, so it probes exhaustion
            // rather than optionality.
            byte[] extended = tlv(0x30, concat(inner, tlv(0x04, new byte[]{0x2A})));
            try
            {
                AlgorithmParameters p = AlgorithmParameters.getInstance(c[0], JSL);
                p.init(extended);
                accepted.add(c[0] + " (" + c[1] + ")");
            }
            catch (IOException expected)
            {
                // the contract
            }
        }
        Assertions.assertTrue(accepted.isEmpty(),
                "codecs accepted an unexhausted SEQUENCE (extra element inside): " + accepted);
    }

    /**
     * The IV and nonce length rules, probed at the boundary and one either
     * side, with BouncyCastle's answer at the same points beside ours.
     *
     * <p>We are the conforming side and BC accepts every length, so each is
     * pinned in both halves: a bcprov bump that makes BC start refusing fails
     * here rather than leaving our half reading as parity.
     */
    @Test
    public void theIvLengthRulesDivergeFromBouncyCastleInOurFavour() throws Exception
    {
        String cbc = "2.16.840.1.101.3.4.1.42";

        Assertions.assertNotNull(encodedOf(cbc, new IvParameterSpec(nonce(16))),
                "CBC must accept the one length it specifies");

        for (int bad : new int[]{15, 17, 12, 32})
        {
            Assertions.assertThrows(InvalidParameterSpecException.class,
                    () -> encodedOf(cbc, new IvParameterSpec(nonce(bad))),
                    "CBC at " + bad + " bytes must be refused");
            assertBouncyCastleStillAccepts(cbc, new IvParameterSpec(nonce(bad)),
                    "CBC at " + bad + " bytes");
        }

        for (int ok : new int[]{7, 13})
        {
            Assertions.assertNotNull(encodedOf("CCM", new GCMParameterSpec(128, nonce(ok))),
                    "CCM must accept " + ok + ", a boundary of RFC 5084's range");
        }

        for (int bad : new int[]{6, 14, 16, 32})
        {
            Assertions.assertThrows(InvalidParameterSpecException.class,
                    () -> encodedOf("CCM", new GCMParameterSpec(128, nonce(bad))),
                    "CCM at a " + bad + "-byte nonce must be refused");
            assertBouncyCastleStillAccepts("CCM", new GCMParameterSpec(128, nonce(bad)),
                    "CCM at a " + bad + "-byte nonce");
        }
    }

    /**
     * The third divergence, asserted rather than described: BouncyCastle's CCM
     * codec refuses an {@code IvParameterSpec} at every length; ours accepts
     * one across RFC 5084's range.
     */
    @Test
    public void bouncyCastlesCcmCodecRefusesAnIvParameterSpecAndOursDoesNot() throws Exception
    {
        for (int len : new int[]{7, 12, 13})
        {
            Assertions.assertNotNull(encodedOf("CCM", new IvParameterSpec(nonce(len))),
                    "our CCM codec must accept an IvParameterSpec at " + len + " bytes");

            AlgorithmParameters theirs = AlgorithmParameters.getInstance("CCM", "BC");
            Assertions.assertThrows(InvalidParameterSpecException.class,
                    () -> theirs.init(new IvParameterSpec(nonce(len))),
                    "BouncyCastle now accepts an IvParameterSpec for CCM at " + len
                            + " bytes. The divergence has moved — re-measure it.");
        }
    }

    /** BC's half of a length divergence: it must still accept what we refuse. */
    private static void assertBouncyCastleStillAccepts(String alg, java.security.spec.AlgorithmParameterSpec spec,
                                                       String what)
        throws Exception
    {
        AlgorithmParameters theirs = AlgorithmParameters.getInstance(alg, "BC");
        theirs.init(spec);
        Assertions.assertNotNull(theirs.getEncoded(),
                what + ": BouncyCastle no longer accepts it, so the divergence has moved —"
                        + " re-measure both halves before changing this pin.");
    }

    // ----------------------------------------------------------------
    // (c) the whole registered surface, by discovery
    // ----------------------------------------------------------------

    /**
     * Every {@code AlgorithmParameters} name JSL registers is DRIVEN,
     * discovered rather than listed, aliases included.
     *
     * <p>The cells above drive a handful of names by hand; every other
     * registered spelling reached nothing before this.
     *
     * <p>One prefix reaches all eight SPI classes, so there is no package list
     * to keep in step.
     */
    @Test
    public void everyRegisteredAlgorithmParametersIsDriven()
    {
        ProviderSurfaceGuard.assertEveryServiceDriven(
                Security.getProvider(JostleProvider.PROVIDER_NAME),
                AlgorithmParametersSurfaceDriver.PREFIX, "AlgorithmParameters (JSL)",
                new String[]{"AlgorithmParameters"},
                AlgorithmParametersSurfaceDriver.forProvider(JostleProvider.PROVIDER_NAME));
    }

    /**
     * The reverse direction: every row of the driver's SPI-class table is
     * reached by a registered name.
     *
     * <p>"Every registered name is driven" is structural here — the driven set
     * IS the discovered set, so no hand-written covered list exists to go
     * stale. What CAN go stale is the spec table, and a row for a class nothing
     * registers any more is the same defect as a dead entry in a covered list:
     * it reads as coverage and exercises nothing.
     */
    @Test
    public void everySpecTableRowIsReachedByARegisteredName()
    {
        java.security.Provider jsl = Security.getProvider(JSL);
        java.util.SortedSet<String> reached = new java.util.TreeSet<String>();

        for (String entry : ProviderSurfaceGuard.registeredSurface(
                jsl, AlgorithmParametersSurfaceDriver.PREFIX,
                new String[]{"AlgorithmParameters"}))
        {
            String alg = entry.substring("AlgorithmParameters.".length());
            String cn = jsl.getService("AlgorithmParameters", alg).getClassName();
            reached.add(cn.substring(cn.lastIndexOf('.') + 1));
        }

        java.util.SortedSet<String> unreached =
                new java.util.TreeSet<String>(java.util.Arrays.asList(
                        AlgorithmParametersSurfaceDriver.KNOWN_SPI_CLASSES));
        unreached.removeAll(reached);

        Assertions.assertTrue(unreached.isEmpty(),
                "the driver carries spec rows for SPI classes no registered name resolves to, so"
                        + " those rows read as coverage and exercise nothing: " + unreached);
    }
}
