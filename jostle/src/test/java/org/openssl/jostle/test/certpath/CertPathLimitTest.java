package org.openssl.jostle.test.certpath;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.jcajce.provider.certpath.CertPathNI;

import java.io.IOException;
import java.security.Security;
import java.util.Arrays;

/**
 * NI-surface limit tests for {@code ni_verify}, driven directly so the bridge
 * checks are reached rather than the SPI's.
 *
 * <p>The subject is phase 2's new surface: the {@code crlCount} parameter and
 * the {@code sizes} array, which is now {@code count + crlCount} long. A
 * bridge that kept iterating {@code count} entries would read a correct answer
 * out of a short array and silently ignore every CRL, and no PKITS case could
 * tell that apart from a CRL that simply did not apply.
 *
 * <p>Range probes sit at exactly {@code boundary + 1}, each with the
 * positive-side companion at the boundary, per the limit-test rule: an
 * arbitrary large value passes a check written with an off-by-100.
 *
 * <p>Runs on both bridges — the JNI and FFM halves validate separately and
 * must return identical codes for identical inputs.
 */
public class CertPathLimitTest
{
    @BeforeAll
    static void before()
    {
        // The Loader runs on PROVIDER construction, not on a static read of
        // NISelector, so touching the NI alone would leave no native library
        // loaded and every call below would UnsatisfiedLinkError.
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    /** anchor, CA, EE — a path that validates, as the positive control. */
    private static byte[][] goodCerts() throws Exception
    {
        return new byte[][]{
                PkitsCertificates.der(PkitsCertificates.ANCHOR),
                PkitsCertificates.der("GoodCACert.crt"),
                PkitsCertificates.der("ValidCertificatePathTest1EE.crt")};
    }

    private static byte[][] goodCrls() throws Exception
    {
        return new byte[][]{
                PkitsCertificates.crlDer("TrustAnchorRootCRL.crl"),
                PkitsCertificates.crlDer("GoodCACRL.crl")};
    }

    /** One call: concatenate everything, size the arrays, return the code. */
    private static int drive(byte[][] certs, byte[][] crls, int count, int crlCount,
                             int anchorCount, int[] sizesOverride, int[] outInfoOverride,
                             int revocation)
    {
        return drive(certs, crls, count, crlCount, anchorCount, sizesOverride, outInfoOverride,
                revocation, CertPathNI.POLICY_NONE, null, 0);
    }

    private static int drive(byte[][] certs, byte[][] crls, int count, int crlCount,
                             int anchorCount, int[] sizesOverride, int[] outInfoOverride,
                             int revocation, int policyFlags, byte[] policies, int policyCount)
    {
        int total = 0;
        for (byte[] b : certs)
        {
            total += b.length;
        }
        for (byte[] b : crls)
        {
            total += b.length;
        }
        byte[] der = new byte[total];
        int[] sizes = new int[certs.length + crls.length];
        int off = 0;
        int i = 0;
        for (byte[] b : certs)
        {
            System.arraycopy(b, 0, der, off, b.length);
            sizes[i++] = b.length;
            off += b.length;
        }
        for (byte[] b : crls)
        {
            System.arraycopy(b, 0, der, off, b.length);
            sizes[i++] = b.length;
            off += b.length;
        }
        int[] outInfo = outInfoOverride != null
                ? outInfoOverride : new int[count + CertPathNI.OUT_INFO_HEADER];
        return NISelector.CertPathNI.ni_verify(der,
                sizesOverride != null ? sizesOverride : sizes,
                count, crlCount, anchorCount,
                CertPathNI.TIME_NOW, 1, revocation, policyFlags, policies, policyCount,
                new byte[der.length], outInfo);
    }

    /**
     * The control this whole file rests on: the same inputs, correctly sized,
     * must RUN. A file of refusals proves nothing if the accepted shape is
     * also refused.
     */
    @Test
    public void theWellFormedCallWithCrlsRuns() throws Exception
    {
        int[] outInfo = new int[3 + CertPathNI.OUT_INFO_HEADER];
        int rc = drive(goodCerts(), goodCrls(), 3, 2, 1, null, outInfo, 1);
        Assertions.assertEquals(0, rc, "JO_SUCCESS: the verification must have RUN");
        Assertions.assertEquals(0, outInfo[0],
                "and its verdict must be X509_V_OK — the path and its CRLs are sound");
    }

    /** A negative CRL count is a caller error, refused typed. */
    @Test
    public void negativeCrlCountIsRefused() throws Exception
    {
        Assertions.assertEquals(-28, drive(goodCerts(), goodCrls(), 3, -1, 1, null, null, 1),
                "JO_INPUT_OUT_OF_RANGE");
    }

    /** Integer.MIN_VALUE: negation and abs both leave it negative. */
    @Test
    public void minValueCrlCountIsRefused() throws Exception
    {
        Assertions.assertEquals(-28,
                drive(goodCerts(), goodCrls(), 3, Integer.MIN_VALUE, 1, null, null, 1),
                "JO_INPUT_OUT_OF_RANGE");
    }

    /**
     * MAX_CRLS is 256, so 257 is the smallest refused value. Probing at the
     * boundary + 1 rather than at some large number is what catches a check
     * written against the wrong constant.
     */
    @Test
    public void crlCountOneAboveTheMaximumIsRefused() throws Exception
    {
        int[] sizes = new int[3 + 257];
        Assertions.assertEquals(-19, drive(goodCerts(), goodCrls(), 3, 257, 1, sizes, null, 1),
                "JO_INPUT_TOO_LONG_INT32");
    }

    /**
     * The sizes array must hold count + crlCount entries. One short is the
     * smallest failure, and the boundary itself is the companion above
     * ({@link #theWellFormedCallWithCrlsRuns} passes exactly 5).
     */
    @Test
    public void aSizesArrayOneShortOfCountPlusCrlCountIsRefused() throws Exception
    {
        byte[][] certs = goodCerts();
        byte[][] crls = goodCrls();
        int[] shortSizes = new int[4];   // 3 certs + 2 CRLs needs 5
        shortSizes[0] = certs[0].length;
        shortSizes[1] = certs[1].length;
        shortSizes[2] = certs[2].length;
        shortSizes[3] = crls[0].length;
        Assertions.assertEquals(-28, drive(certs, crls, 3, 2, 1, shortSizes, null, 1),
                "JO_INPUT_OUT_OF_RANGE");
    }

    /** A zero-length CRL entry: zero is meaningless, not merely empty. */
    @Test
    public void aZeroLengthCrlEntryIsRefused() throws Exception
    {
        byte[][] certs = goodCerts();
        byte[][] crls = goodCrls();
        int[] sizes = {certs[0].length, certs[1].length, certs[2].length, 0, crls[1].length};
        Assertions.assertEquals(-24, drive(certs, crls, 3, 2, 1, sizes, null, 1),
                "JO_INPUT_LEN_IS_NEGATIVE");
    }

    /** A CRL entry running past the buffer is refused before any decode. */
    @Test
    public void aCrlEntryPastTheEndOfTheBufferIsRefused() throws Exception
    {
        byte[][] certs = goodCerts();
        byte[][] crls = goodCrls();
        int[] sizes = {certs[0].length, certs[1].length, certs[2].length,
                crls[0].length, crls[1].length + 1};
        Assertions.assertEquals(-28, drive(certs, crls, 3, 2, 1, sizes, null, 1),
                "JO_INPUT_OUT_OF_RANGE");
    }

    /**
     * Bytes that are not a CRL are refused with the CRL's own code and its
     * index AMONG THE CRLS — a shared code with the certificate path would
     * name the wrong file.
     */
    @Test
    public void anUndecodableCrlIsRefusedWithItsIndex() throws Exception
    {
        byte[][] certs = goodCerts();
        byte[][] crls = goodCrls();
        crls[1] = crls[1].clone();
        for (int i = 8; i < Math.min(40, crls[1].length); i++)
        {
            crls[1][i] ^= (byte) 0xFF;
        }
        int[] outInfo = new int[3 + CertPathNI.OUT_INFO_HEADER];
        int rc = drive(certs, crls, 3, 2, 1, null, outInfo, 1);

        Assertions.assertEquals(-176, rc, "JO_CRL_DECODE_FAILED");
        Assertions.assertEquals(-176, outInfo[0], "the code must be reported in outInfo too");
        Assertions.assertEquals(1, outInfo[1], "outInfo[1] must name WHICH CRL failed");
    }

    /**
     * Zero CRLs is legal and is what every non-revocation caller sends, so
     * the new parameter must not have made it an error.
     */
    @Test
    public void zeroCrlsWithRevocationOffStillRuns() throws Exception
    {
        int[] outInfo = new int[3 + CertPathNI.OUT_INFO_HEADER];
        int rc = drive(goodCerts(), new byte[0][], 3, 0, 1, null, outInfo, 0);
        Assertions.assertEquals(0, rc, "JO_SUCCESS");
        Assertions.assertEquals(0, outInfo[0], "X509_V_OK");
    }

    /**
     * The discriminator between "the flag was set" and "the CRLs were read":
     * the same path with revocation ON and no CRLs must NOT be X509_V_OK.
     * Without this, a bridge that dropped the flag would pass every test
     * above.
     */
    @Test
    public void revocationOnWithNoCrlsIsRefusedByOpenssl() throws Exception
    {
        int[] outInfo = new int[3 + CertPathNI.OUT_INFO_HEADER];
        int rc = drive(goodCerts(), new byte[0][], 3, 0, 1, null, outInfo, 1);
        Assertions.assertEquals(0, rc, "the verification RAN");
        Assertions.assertEquals(3, outInfo[0],
                "X509_V_ERR_UNABLE_TO_GET_CRL: revocation was genuinely on");
    }

    /** A null DER buffer, per the null-rejection rule for every input array. */
    @Test
    public void nullDerIsRefused()
    {
        Assertions.assertEquals(-16, NISelector.CertPathNI.ni_verify(
                null, new int[5], 3, 2, 1, CertPathNI.TIME_NOW, 1, 1, CertPathNI.POLICY_NONE, null, 0,
                new byte[16], new int[6]),
                "JO_INPUT_IS_NULL");
    }

    /** A null sizes array is a null INPUT, as the der buffer is. */
    @Test
    public void nullSizesIsRefused() throws IOException
    {
        Assertions.assertEquals(-16, NISelector.CertPathNI.ni_verify(
                new byte[16], null, 3, 2, 1, CertPathNI.TIME_NOW, 1, 1, CertPathNI.POLICY_NONE, null, 0,
                new byte[16], new int[6]),
                "JO_INPUT_IS_NULL");
    }

    /**
     * Inputs that fail more than one check: both bridges check in one order, so
     * the first failing check names the code on both.
     */
    @Test
    public void inputsFailingTwoChecksGetTheSameCodeOnBothBridges() throws Exception
    {
        byte[] der = new byte[64];
        Assertions.assertAll(
                () -> Assertions.assertEquals(-19, NISelector.CertPathNI.ni_verify(der, new int[300], 300, 0, 0,
                        CertPathNI.TIME_NOW, 1, 0, CertPathNI.POLICY_NONE, null, 0, new byte[64], new int[303]),
                        "count over 256 before the anchor range"),
                () -> Assertions.assertEquals(-24, NISelector.CertPathNI.ni_verify(new byte[0], new int[3], 1, 0, 1,
                        CertPathNI.TIME_NOW, 1, 0, CertPathNI.POLICY_NONE, null, 0, new byte[64], new int[6]),
                        "empty der before the count range"),
                () -> Assertions.assertEquals(-24, NISelector.CertPathNI.ni_verify(new byte[0], new int[3], 3, 0, 1,
                        CertPathNI.TIME_NOW, 1, 0, CertPathNI.POLICY_NONE, null, 0, new byte[64], new int[0]),
                        "empty der before the outInfo length"),
                () -> Assertions.assertEquals(-24, NISelector.CertPathNI.ni_verify(new byte[0], new int[3], 257, 0, 1,
                        CertPathNI.TIME_NOW, 1, 0, CertPathNI.POLICY_NONE, null, 0, new byte[64], new int[6]),
                        "empty der before the 256 bound"),
                () -> Assertions.assertEquals(-16, NISelector.CertPathNI.ni_verify(der, null, 257, 0, 1,
                        CertPathNI.TIME_NOW, 1, 0, CertPathNI.POLICY_NONE, null, 0, null, null),
                        "null sizes before every other check"));
    }

    /**
     * outInfo is written on success and on a decode failure only: a refusal
     * leaves the caller's values, and a success leaves the entries past the
     * chain, on both bridges.
     */
    @Test
    public void outInfoIsWrittenOnlyWhereTheContractSays() throws Exception
    {
        int[] refused = new int[6];
        Arrays.fill(refused, 99);
        Assertions.assertEquals(-19, drive(goodCerts(), goodCrls(), 300, 2, 1, null, refused, 1));
        Assertions.assertArrayEquals(new int[]{99, 99, 99, 99, 99, 99}, refused, "a refusal leaves outInfo alone");

        int[] success = new int[10];
        Arrays.fill(success, 99);
        Assertions.assertEquals(0, drive(goodCerts(), goodCrls(), 3, 2, 1, null, success, 1));
        Assertions.assertEquals(3, success[2], "a chain of three");
        Assertions.assertArrayEquals(new int[]{99, 99, 99, 99}, Arrays.copyOfRange(success, 6, 10),
                "a success leaves the entries past the chain alone");

        byte[][] certs = goodCerts();
        certs[1] = Arrays.copyOf(certs[1], certs[1].length);
        certs[1][0] = 0x31;
        int[] decode = new int[7];
        Arrays.fill(decode, 99);
        Assertions.assertEquals(-175, drive(certs, goodCrls(), 3, 2, 1, null, decode, 1));
        Assertions.assertArrayEquals(new int[]{-175, 1, 0, 99, 99, 99, 99}, decode,
                "a decode failure writes [code, index, 0] and nothing else");
    }

    /** outInfo must hold the header plus one size per certificate. */
    @Test
    public void anOutInfoOneShortIsRefused() throws Exception
    {
        Assertions.assertEquals(-29,
                drive(goodCerts(), goodCrls(), 3, 2, 1, null, new int[5], 1),
                "JO_OUTPUT_OUT_OF_RANGE: 3 certificates need 3 + 3 entries");
    }

    /** NIST-test-policy-1 as a DER OBJECT IDENTIFIER TLV. */
    private static final byte[] POLICY_1 = {
            0x06, 0x0a, 0x60, (byte) 0x86, 0x48, 0x01, 0x65, 0x03, 0x02, 0x01, 0x30, 0x01};

    /** The path asserts NIST-test-policy-1, so every accepted policy input validates it. */
    private static int drivePolicies(int flags, byte[] policies, int count) throws Exception
    {
        int[] outInfo = new int[3 + CertPathNI.OUT_INFO_HEADER];
        int rc = drive(goodCerts(), new byte[0][], 3, 0, 1, null, outInfo, 0, flags, policies, count);
        if (rc == 0)
        {
            Assertions.assertEquals(0, outInfo[0], "the accepted policy input must validate the path");
        }
        return rc;
    }

    private static byte[] concat(byte[]... parts)
    {
        int n = 0;
        for (byte[] p : parts)
        {
            n += p.length;
        }
        byte[] out = new byte[n];
        int off = 0;
        for (byte[] p : parts)
        {
            System.arraycopy(p, 0, out, off, p.length);
            off += p.length;
        }
        return out;
    }

    /** The accepted shapes: none, any number up to the ceiling, every flag, the long length form. */
    @Test
    public void wellFormedPolicyInputsRun() throws Exception
    {
        Assertions.assertEquals(0, drivePolicies(CertPathNI.POLICY_NONE, null, 0), "no policies, null");
        Assertions.assertEquals(0, drivePolicies(CertPathNI.POLICY_NONE, new byte[0], 0), "no policies, empty");
        Assertions.assertEquals(0, drivePolicies(CertPathNI.POLICY_NONE, POLICY_1, 1), "one policy");
        int all = CertPathNI.POLICY_EXPLICIT | CertPathNI.POLICY_INHIBIT_ANY | CertPathNI.POLICY_INHIBIT_MAP;
        Assertions.assertEquals(0, drivePolicies(all, POLICY_1, 1), "every flag");

        byte[][] many = new byte[256][];
        for (int i = 0; i < many.length; i++)
        {
            many[i] = POLICY_1;
        }
        Assertions.assertEquals(0, drivePolicies(CertPathNI.POLICY_NONE, concat(many), 256),
                "256 policies, the ceiling");

        // 128 content octets need the long length form, 0x81 0x80.
        byte[] longOid = new byte[3 + 128];
        longOid[0] = 0x06;
        longOid[1] = (byte) 0x81;
        longOid[2] = (byte) 0x80;
        longOid[3] = 0x2b;
        for (int i = 4; i < longOid.length; i++)
        {
            longOid[i] = 0x01;
        }
        Assertions.assertEquals(0, drivePolicies(CertPathNI.POLICY_NONE, concat(POLICY_1, longOid), 2),
                "a long-form OID beside the path's policy");
    }

    @Test
    public void anUnknownPolicyFlagIsRefused() throws Exception
    {
        Assertions.assertEquals(-28, drivePolicies(8, null, 0), "JO_INPUT_OUT_OF_RANGE");
        Assertions.assertEquals(-28, drivePolicies(Integer.MIN_VALUE, null, 0), "JO_INPUT_OUT_OF_RANGE");
    }

    @Test
    public void aPolicyCountOutOfRangeIsRefused() throws Exception
    {
        Assertions.assertEquals(-28, drivePolicies(CertPathNI.POLICY_NONE, POLICY_1, -1), "JO_INPUT_OUT_OF_RANGE");
        Assertions.assertEquals(-28, drivePolicies(CertPathNI.POLICY_NONE, POLICY_1, Integer.MIN_VALUE),
                "JO_INPUT_OUT_OF_RANGE");
        Assertions.assertEquals(-19, drivePolicies(CertPathNI.POLICY_NONE, POLICY_1, 257),
                "JO_INPUT_TOO_LONG_INT32: one over the ceiling");
    }

    @Test
    public void nullPoliciesWithACountAreRefused() throws Exception
    {
        Assertions.assertEquals(-16, drivePolicies(CertPathNI.POLICY_NONE, null, 1), "JO_INPUT_IS_NULL");
    }

    /** Every malformed list is the same code on both bridges. */
    @Test
    public void malformedPolicyListsAreRefused() throws Exception
    {
        byte[][] lists = {
                POLICY_1,                                                       // count 0 with bytes
                {0x06, 0x05, 0x2b, 0x06},                                       // truncated
                {0x04, 0x03, 0x2b, 0x06, 0x01},                                 // not an OBJECT IDENTIFIER
                {0x06, 0x00},                                                   // empty content
                {0x06, (byte) 0x81, 0x05, 0x2b, 0x06, 0x01, 0x05, 0x05},        // long form, not minimal
                {0x06, (byte) 0x80, 0x2b, 0x06, 0x00, 0x00},                    // indefinite length
                {0x06, (byte) 0x82, 0x00, 0x03, 0x2b, 0x06, 0x01},              // two length octets
                concat(POLICY_1, new byte[]{0x00}),                            // a trailing byte
                {0x06, 0x01, (byte) 0x80},                                      // content OpenSSL refuses
                {0x06}};                                                        // a tag alone
        int[] counts = {0, 1, 1, 1, 1, 1, 1, 1, 1, 1};
        for (int i = 0; i < lists.length; i++)
        {
            Assertions.assertEquals(-28, drivePolicies(CertPathNI.POLICY_NONE, lists[i], counts[i]),
                    "JO_INPUT_OUT_OF_RANGE for malformed list " + i);
        }
        Assertions.assertEquals(-28, drivePolicies(CertPathNI.POLICY_NONE, POLICY_1, 2),
                "JO_INPUT_OUT_OF_RANGE: two counted, one present");
    }

    /** The policy checks come after the existing ones, on both bridges. */
    @Test
    public void thePolicyChecksFollowTheOutInfoCheck() throws Exception
    {
        Assertions.assertEquals(-29,
                drive(goodCerts(), goodCrls(), 3, 2, 1, null, new int[5], 1, 8, null, 1),
                "JO_OUTPUT_OUT_OF_RANGE before any policy check");
    }
}
