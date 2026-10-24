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

package org.openssl.jostle.probe;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.jcajce.provider.cert.X509NI;
import org.openssl.jostle.jcajce.provider.dh.DHServiceNI;
import org.openssl.jostle.jcajce.provider.dsa.DSAServiceNI;
import org.openssl.jostle.jcajce.provider.rsa.RSAOAEPCipherNI;
import org.openssl.jostle.jcajce.provider.fips.FIPSNISelector;
import org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;
import org.openssl.jostle.jcajce.provider.ks.KSServiceNI;
import org.openssl.jostle.jcajce.provider.md.MDServiceNI;
import org.openssl.jostle.jcajce.provider.rand.RandServiceNI;
import org.openssl.jostle.jcajce.provider.rsa.RSAServiceNI;
import org.openssl.jostle.rand.RandSource;
import org.openssl.jostle.test.TestUtil;
import org.openssl.jostle.test.certpath.PkitsCertificates;

/**
 * Hand-run utility that pins the controlled-parameter aborts at the NI surface.
 * <p>
 * A jostle-owned out-array that is null or too short aborts the process; an
 * abort therefore cannot be an in-suite cell, because it takes the whole leg
 * with it. Each row runs in a CHILD JVM and is judged on the child's exit code
 * together with the assert text and source file it named. Exit 134 alone is not
 * enough: it says the process aborted, not that it aborted where this row
 * meant.
 * <p>
 * This class carries no JUnit annotation and its fully-qualified name matches
 * no {@code includeTestsMatching} or {@code excludeTestsMatching} pattern in
 * {@code jostle/build.gradle}, so no test leg selects it. That is deliberate
 * and must survive edits: check any rename against every pattern in that file,
 * including the package-wide {@code org.openssl.jostle.test.fips.*} include,
 * which no class-name argument would catch.
 * <p>
 * An OPS build is not a valid host for these rows: the fault-injection macros
 * change which branch is reached. The gate runs this only against a plain
 * build.
 * <p>
 * The certificate fixture is {@code ValidCertificatePathTest1EE.crt} from the
 * committed PKITS set. Its file name contains "Test", which is a resource name
 * and not a class name, so no test filter can reach it.
 * <p>
 * Usage: {@code NativeAbortProbeRunner <classpath> [fipsModulePath]}. The
 * classpath is supplied by the caller rather than reconstructed here, because a
 * runner that guesses its own classpath can silently measure nothing.
 */
public final class NativeAbortProbeRunner
{
    private static final String CELL = "--cell";
    private static final String OK = "CONTROL-OK";
    private static final String CERT = "ValidCertificatePathTest1EE.crt";
    private static final String CRL = "indirectCRLCA5CRL.crl";
    // The native keystore serves PKCS#12 only; BCFKS is implemented in Java
    // and never reaches this NI. The abort rows would pass with any string,
    // since the assert precedes the type check — the control would not.
    private static final String KS_TYPE = "PKCS12";
    // JO_KS_CTX_WRONG_KIND.
    private static final int KS_CTX_WRONG_KIND = -210;
    private static final byte[] RSA_F4 = {0x01, 0x00, 0x01};
    private static final String[] DH_NULL_ERR_CELLS = {"dh-allocatekex-null-err", "dh-bygroup-null-err",
            "dh-paramgen-null-err", "dh-makeparams-null-err", "dh-generate-null-err", "dh-makeprivate-null-err",
            "dh-makepublic-null-err"};
    private static final String[] DSA_NULL_ERR_CELLS = {"dsa-allocate-null-err", "dsa-paramgen-null-err",
            "dsa-makeparams-null-err", "dsa-generate-null-err", "dsa-makeprivate-null-err", "dsa-makepublic-null-err"};
    private static final RandSource RND = TestUtil.RNDSrc;

    private static final String NONFIPS_JNI = "interface/nonfips/jni/";
    private static final String NONFIPS_FFM = "interface/nonfips/ffm/";
    private static final String FIPS_JNI = "interface/fips/jni/";
    private static final String FIPS_FFM = "interface/fips/ffm/";

    private NativeAbortProbeRunner()
    {
    }

    /** One measured cell: a case driven on one bridge, with its expectation. */
    private static final class Row
    {
        final String id;
        final String bridge;
        final int expectedExit;
        final String expectedAssert;
        final String expectedFile;
        /* The language does not fix the outcome: a typed refusal (exit 0) or a crash (exit 134) both pass. */
        final boolean either;

        Row(String id, String bridge, int expectedExit, String expectedAssert, String expectedFile)
        {
            this(id, bridge, expectedExit, expectedAssert, expectedFile, false);
        }

        Row(String id, String bridge, int expectedExit, String expectedAssert, String expectedFile, boolean either)
        {
            this.id = id;
            this.bridge = bridge;
            this.expectedExit = expectedExit;
            this.expectedAssert = expectedAssert;
            this.expectedFile = expectedFile;
            this.either = either;
        }
    }

    // ---------------------------------------------------------------- rows

    private static void abortRow(List<Row> rows, String id,
                                 String jniAssert, String jniFile,
                                 String ffmAssert, String ffmFile)
    {
        rows.add(new Row(id, "jni", 134, jniAssert, jniFile));
        rows.add(new Row(id, "ffm", 134, ffmAssert, ffmFile));
    }

    /** A read of freed memory: the typed control line, or an abort, and the run says which. */
    private static void typedOrAbortRow(List<Row> rows, String id)
    {
        rows.add(new Row(id, "jni", 0, OK, null, true));
        rows.add(new Row(id, "ffm", 0, OK, null, true));
    }

    /**
     * JNI aborts on the assert; FFM writes the err slot in Java, so a null array throws there and the child
     * exits 1 naming the null store.
     */
    private static void jniAbortFfmThrowsRow(List<Row> rows, String id, String jniAssert, String jniFile)
    {
        rows.add(new Row(id, "jni", 134, jniAssert, jniFile));
        rows.add(new Row(id, "ffm", 1, "Cannot store to int array because \"err\" is null", null));
    }

    private static void controlRow(List<Row> rows, String id)
    {
        rows.add(new Row(id, "jni", 0, OK, null));
        rows.add(new Row(id, "ffm", 0, OK, null));
    }

    private static List<Row> rows(boolean fips)
    {
        List<Row> rows = new ArrayList<Row>();

        String jniDir = fips ? FIPS_JNI : NONFIPS_JNI;
        String ffmDir = fips ? FIPS_FFM : NONFIPS_FFM;
        String p = fips ? "fips-" : "";

        String lenJni = "GetArrayLength(env, _err) >= 1";
        String consumedJni = "_consumed != NULL";
        String consumedFfm = "out_consumed != NULL && consumed_len >= 1";

        abortRow(rows, p + "x509-null-err",
                "_err != NULL", jniDir + "x509_ni_jni.c",
                "err_len >= 1", ffmDir + "x509_ni_ffm.c");
        abortRow(rows, p + "x509-empty-err",
                lenJni, jniDir + "x509_ni_jni.c",
                "err_len >= 1", ffmDir + "x509_ni_ffm.c");
        abortRow(rows, p + "x509-null-consumed",
                consumedJni, jniDir + "x509_ni_jni.c",
                consumedFfm, ffmDir + "x509_ni_ffm.c");
        // A one-byte input fails the decode first, so only a decodable
        // certificate proves the assert sits ABOVE the decode.
        abortRow(rows, p + "x509-null-consumed-validcert",
                consumedJni, jniDir + "x509_ni_jni.c",
                consumedFfm, ffmDir + "x509_ni_ffm.c");
        controlRow(rows, p + "x509-control");
        // A dispose of the other kind is a jostle fault: it aborts on the free's
        // result rather than freeing nothing in silence. Zero stays a no-op.
        abortRow(rows, p + "x509-dispose-crl-handle",
                "rc == JO_SUCCESS", jniDir + "x509_ni_jni.c",
                "rc == JO_SUCCESS", ffmDir + "x509_ni_ffm.c");
        abortRow(rows, p + "x509-disposecrl-cert-handle",
                "rc == JO_SUCCESS", jniDir + "x509_ni_jni.c",
                "rc == JO_SUCCESS", ffmDir + "x509_ni_ffm.c");
        controlRow(rows, p + "x509-dispose-zero");

        abortRow(rows, p + "md-null-err",
                "_err != NULL", jniDir + "md_jni.c",
                "err != NULL", ffmDir + "md_ffm.c");
        abortRow(rows, p + "md-empty-err",
                lenJni, jniDir + "md_jni.c",
                "err_len >= 1", ffmDir + "md_ffm.c");
        controlRow(rows, p + "md-control");

        abortRow(rows, p + "rand-null-err",
                "_err != NULL", jniDir + "rand_jni.c",
                "err != NULL", ffmDir + "rand_ffm.c");
        abortRow(rows, p + "rand-empty-err",
                lenJni, jniDir + "rand_jni.c",
                "err_len >= 1", ffmDir + "rand_ffm.c");
        controlRow(rows, p + "rand-control");

        jniAbortFfmThrowsRow(rows, p + "rsa-allocate-null-err", "err != NULL", jniDir + "rsa_ni_jni.c");
        jniAbortFfmThrowsRow(rows, p + "rsa-generate-null-err", "err_out != NULL", jniDir + "rsa_ni_jni.c");
        controlRow(rows, p + "rsa-control");

        for (String c : DH_NULL_ERR_CELLS)
        {
            jniAbortFfmThrowsRow(rows, p + c, c.equals("dh-allocatekex-null-err") ? "err != NULL" : "err_out != NULL",
                    jniDir + "dh_ni_jni.c");
        }
        controlRow(rows, p + "dh-control");

        for (String c : DSA_NULL_ERR_CELLS)
        {
            jniAbortFfmThrowsRow(rows, p + c, c.equals("dsa-allocate-null-err") ? "err != NULL" : "err_out != NULL",
                    jniDir + "dsa_ni_jni.c");
        }
        controlRow(rows, p + "dsa-control");

        jniAbortFfmThrowsRow(rows, p + "oaep-allocate-null-err", "err != NULL", jniDir + "rsa_oaep_ni_jni.c");
        controlRow(rows, p + "oaep-control");

        // The keystore and certification-path families have no FIPS twin under
        // interface/fips, so they contribute base rows only. Their absence from
        // the FIPS block is a fact about the tree, not an omission.
        if (!fips)
        {
            abortRow(rows, "ks-null-err",
                    "_err != NULL", jniDir + "ks_jni.c",
                    "err != NULL", ffmDir + "ks_ffm.c");
            abortRow(rows, "ks-empty-err",
                    lenJni, jniDir + "ks_jni.c",
                    "err_len >= 1", ffmDir + "ks_ffm.c");
            controlRow(rows, "ks-control");
            // A dispose of another family's handle is a jostle fault: it aborts on the
            // free's result rather than freeing nothing in silence. Zero stays a no-op.
            abortRow(rows, "ks-dispose-foreign-handle",
                    "rc == JO_SUCCESS", jniDir + "ks_jni.c",
                    "rc == JO_SUCCESS", ffmDir + "ks_ffm.c");
            controlRow(rows, "ks-dispose-zero");
            // A disposed handle reads freed memory, so it never runs in-suite, and the
            // language fixes no outcome: a typed refusal or an abort both pass, and
            // the run prints which one it saw.
            typedOrAbortRow(rows, "ks-disposed-handle");
        }
        return rows;
    }

    // -------------------------------------------------------------- parent

    public static void main(String[] args) throws Exception
    {
        if (args.length > 0 && CELL.equals(args[0]))
        {
            cell(args[1], args.length > 2 ? args[2] : null);
            return;
        }
        if (args.length < 1)
        {
            System.err.println("usage: NativeAbortProbeRunner <classpath> [fipsModulePath]");
            System.exit(2);
        }
        System.exit(run(args[0], args.length > 1 ? args[1] : null));
    }

    private static int run(String classpath, String fipsModule) throws Exception
    {
        List<Row> rows = rows(false);
        if (fipsModule != null)
        {
            rows.addAll(rows(true));
        }
        else
        {
            System.out.println("FIPS rows SKIPPED: no module path given");
        }

        int failed = 0;
        for (Row row : rows)
        {
            String out = drive(classpath, row, fipsModule);
            int exit = Integer.parseInt(out.substring(0, out.indexOf('\n')));
            String log = out.substring(out.indexOf('\n') + 1);

            boolean ok = exit == row.expectedExit
                    && log.contains(row.expectedAssert)
                    && (row.expectedFile == null || log.contains(row.expectedFile));
            if (row.either && !ok && exit == 134)
            {
                ok = true;
                System.out.println("     " + row.id + " aborted rather than refusing typed");
            }
            if (!ok)
            {
                failed++;
            }
            System.out.printf("%-4s %-34s rc=%-4d %-8s %s%n", row.bridge, row.id, exit,
                    ok ? "OK" : "MISMATCH", ok ? row.expectedAssert : firstLine(log));
        }
        System.out.printf("%n%d rows, %d mismatched%n", rows.size(), failed);
        return failed == 0 ? 0 : 1;
    }

    private static String firstLine(String log)
    {
        for (String line : log.split("\n"))
        {
            if (line.contains("Assertion failed") || line.contains(OK) || line.contains("NO-ABORT"))
            {
                return line.trim();
            }
        }
        return "(no assert line, no control line)";
    }

    private static String drive(String classpath, Row row, String fipsModule) throws Exception
    {
        List<String> cmd = new ArrayList<String>();
        cmd.add(System.getProperty("java.home") + "/bin/java");
        cmd.add("-cp");
        cmd.add(classpath);
        cmd.add("-Dorg.openssl.jostle.loader.interface=" + row.bridge);
        cmd.add(NativeAbortProbeRunner.class.getName());
        cmd.add(CELL);
        cmd.add(row.id);
        if (fipsModule != null)
        {
            cmd.add(fipsModule);
        }

        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.redirectErrorStream(true);
        Process proc = pb.start();

        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        InputStream in = proc.getInputStream();
        byte[] chunk = new byte[4096];
        int n;
        while ((n = in.read(chunk)) > 0)
        {
            buf.write(chunk, 0, n);
        }
        int exit = proc.waitFor();
        return exit + "\n" + new String(buf.toByteArray(), "UTF-8");
    }

    // --------------------------------------------------------------- child

    private static void cell(String id, String fipsModule) throws Exception
    {
        boolean fips = id.startsWith("fips-");
        String c = fips ? id.substring("fips-".length()) : id;

        X509NI x509;
        MDServiceNI md;
        RandServiceNI rand;
        RSAServiceNI rsa;
        DHServiceNI dh;
        DSAServiceNI dsa;
        RSAOAEPCipherNI oaep;
        if (fips)
        {
            new JostleProvider();
            new JostleFIPSProvider("fips_module='" + fipsModule + "'");
            x509 = FIPSNISelector.X509NI;
            md = FIPSNISelector.MDServiceNI;
            rand = FIPSNISelector.RandServiceNI;
            rsa = FIPSNISelector.RSAServiceNI;
            dh = FIPSNISelector.DHServiceNI;
            dsa = FIPSNISelector.DSAServiceNI;
            oaep = FIPSNISelector.RSAOAEPCipherNI;
        }
        else
        {
            new JostleProvider();
            x509 = NISelector.X509NI;
            md = NISelector.MDServiceNI;
            rand = NISelector.RandServiceNI;
            rsa = NISelector.RSAServiceNI;
            dh = NISelector.DHServiceNI;
            dsa = NISelector.DSAServiceNI;
            oaep = NISelector.RSAOAEPCipherNI;
        }
        KSServiceNI ks = NISelector.KSServiceNI;

        if ("x509-null-err".equals(c))
        {
            x509.ni_allocate(new byte[1], 0, 1, 1024, new int[1], null);
        }
        else if ("x509-empty-err".equals(c))
        {
            x509.ni_allocate(new byte[1], 0, 1, 1024, new int[1], new int[0]);
        }
        else if ("x509-null-consumed".equals(c))
        {
            x509.ni_allocate(new byte[1], 0, 1, 1024, null, new int[1]);
        }
        else if ("x509-null-consumed-validcert".equals(c))
        {
            byte[] der = PkitsCertificates.der(CERT);
            x509.ni_allocate(der, 0, der.length, 1 << 20, null, new int[1]);
        }
        else if ("x509-control".equals(c))
        {
            byte[] der = PkitsCertificates.der(CERT);
            int[] err = new int[1];
            int[] consumed = new int[1];
            long ref = x509.ni_allocate(der, 0, der.length, 1 << 20, consumed, err);
            report(ref != 0 && err[0] == 0, "x509 ref=" + (ref != 0) + " err=" + err[0]);
        }
        else if ("x509-dispose-crl-handle".equals(c))
        {
            x509.ni_dispose(crlRef(x509));
        }
        else if ("x509-disposecrl-cert-handle".equals(c))
        {
            byte[] der = PkitsCertificates.der(CERT);
            int[] err = new int[1];
            x509.ni_disposeCrl(x509.ni_allocate(der, 0, der.length, 1 << 20, new int[1], err));
        }
        else if ("x509-dispose-zero".equals(c))
        {
            x509.ni_dispose(0);
            x509.ni_disposeCrl(0);
            report(true, "x509 dispose(0) and disposeCrl(0) returned");
        }
        else if ("md-null-err".equals(c))
        {
            md.ni_allocateDigest("SHA-256", 0, null);
        }
        else if ("md-empty-err".equals(c))
        {
            md.ni_allocateDigest("SHA-256", 0, new int[0]);
        }
        else if ("md-control".equals(c))
        {
            int[] err = new int[1];
            long ref = md.ni_allocateDigest("SHA-256", 0, err);
            report(ref != 0 && err[0] == 0, "md ref=" + (ref != 0) + " err=" + err[0]);
        }
        else if ("rand-null-err".equals(c))
        {
            rand.ni_createContext("CTR-DRBG", "AES-256-CTR", true, 0, false, null, null);
        }
        else if ("rand-empty-err".equals(c))
        {
            rand.ni_createContext("CTR-DRBG", "AES-256-CTR", true, 0, false, null, new int[0]);
        }
        else if ("rand-control".equals(c))
        {
            int[] err = new int[1];
            long ref = rand.ni_createContext("CTR-DRBG", "AES-256-CTR", true, 0, false, null, err);
            report(ref != 0 && err[0] == 0, "rand ref=" + (ref != 0) + " err=" + err[0]);
        }
        else if ("rsa-allocate-null-err".equals(c))
        {
            rsa.ni_allocateSigner(null);
        }
        else if ("rsa-generate-null-err".equals(c))
        {
            rsa.ni_generateKeyPair(2048, RSA_F4, null, RND);
        }
        else if ("rsa-control".equals(c))
        {
            int[] err = new int[1];
            long ref = rsa.ni_allocateSigner(err);
            report(ref != 0 && err[0] == 0, "rsa ref=" + (ref != 0) + " err=" + err[0]);
        }
        else if ("dh-allocatekex-null-err".equals(c))
        {
            dh.ni_allocateKex(null);
        }
        else if ("dh-bygroup-null-err".equals(c))
        {
            dh.ni_generateKeyPairByGroup("ffdhe2048", null, RND);
        }
        else if ("dh-paramgen-null-err".equals(c))
        {
            dh.ni_generateParameters(512, null, RND);
        }
        else if ("dh-makeparams-null-err".equals(c))
        {
            dh.ni_makeParamsFromComponents(new byte[]{23}, null, new byte[]{5}, null);
        }
        else if ("dh-generate-null-err".equals(c))
        {
            dh.ni_generateKeyPair(0L, 0, null, RND);
        }
        else if ("dh-makeprivate-null-err".equals(c))
        {
            dh.ni_makePrivateFromComponents(new byte[]{23}, null, new byte[]{5}, new byte[]{3}, null, RND);
        }
        else if ("dh-makepublic-null-err".equals(c))
        {
            dh.ni_makePublicFromComponents(new byte[]{23}, null, new byte[]{5}, new byte[]{3}, null);
        }
        else if ("dh-control".equals(c))
        {
            int[] err = new int[1];
            long ref = dh.ni_allocateKex(err);
            report(ref != 0 && err[0] == 0, "dh ref=" + (ref != 0) + " err=" + err[0]);
        }
        else if ("dsa-allocate-null-err".equals(c))
        {
            dsa.ni_allocateSigner(null);
        }
        else if ("dsa-paramgen-null-err".equals(c))
        {
            dsa.ni_generateParameters(512, 160, null, RND);
        }
        else if ("dsa-makeparams-null-err".equals(c))
        {
            dsa.ni_makeParamsFromComponents(new byte[]{23}, new byte[]{11}, new byte[]{4}, null);
        }
        else if ("dsa-generate-null-err".equals(c))
        {
            dsa.ni_generateKeyPair(0L, null, RND);
        }
        else if ("dsa-makeprivate-null-err".equals(c))
        {
            dsa.ni_makePrivateFromComponents(new byte[]{23}, new byte[]{11}, new byte[]{4}, new byte[]{3}, null, RND);
        }
        else if ("dsa-makepublic-null-err".equals(c))
        {
            dsa.ni_makePublicFromComponents(new byte[]{23}, new byte[]{11}, new byte[]{4}, new byte[]{3}, null);
        }
        else if ("dsa-control".equals(c))
        {
            int[] err = new int[1];
            long ref = dsa.ni_allocateSigner(err);
            report(ref != 0 && err[0] == 0, "dsa ref=" + (ref != 0) + " err=" + err[0]);
        }
        else if ("oaep-allocate-null-err".equals(c))
        {
            oaep.ni_allocateCipher(null);
        }
        else if ("oaep-control".equals(c))
        {
            int[] err = new int[1];
            long ref = oaep.ni_allocateCipher(err);
            report(ref != 0 && err[0] == 0, "oaep ref=" + (ref != 0) + " err=" + err[0]);
        }
        else if ("ks-null-err".equals(c))
        {
            ks.ni_allocateKeyStore(KS_TYPE, null);
        }
        else if ("ks-empty-err".equals(c))
        {
            ks.ni_allocateKeyStore(KS_TYPE, new int[0]);
        }
        else if ("ks-control".equals(c))
        {
            int[] err = new int[1];
            long ref = ks.ni_allocateKeyStore(KS_TYPE, err);
            report(ref != 0 && err[0] == 0, "ks ref=" + (ref != 0) + " err=" + err[0]);
        }
        else if ("ks-dispose-foreign-handle".equals(c))
        {
            int[] err = new int[1];
            ks.ni_dispose(md.ni_allocateDigest("SHA-256", 0, err));
        }
        else if ("ks-dispose-zero".equals(c))
        {
            ks.ni_dispose(0);
            report(true, "ks dispose(0) returned");
        }
        else if ("ks-disposed-handle".equals(c))
        {
            int[] err = new int[1];
            long ref = ks.ni_allocateKeyStore(KS_TYPE, err);
            ks.ni_dispose(ref);
            int rc = ks.ni_containsAlias(ref, "a");
            report(rc == KS_CTX_WRONG_KIND, "ks containsAlias on a disposed handle rc=" + rc);
        }
        else
        {
            System.out.println("unknown cell " + id);
            System.exit(2);
        }
        // Reached only when the row did NOT abort. The parent judges on the
        // exit code and the text, so say plainly that nothing aborted.
        System.out.println("NO-ABORT: returned normally");
    }

    private static long crlRef(X509NI x509) throws Exception
    {
        byte[] der = PkitsCertificates.crlDer(CRL);
        int[] err = new int[1];
        long ref = x509.ni_allocateCrl(der, 0, der.length, 1 << 26, new int[1], err);
        if (ref == 0)
        {
            System.out.println("CONTROL-FAILED: crl err=" + err[0]);
            System.exit(3);
        }
        return ref;
    }

    private static void report(boolean ok, String detail)
    {
        if (ok)
        {
            System.out.println(OK + ": " + detail);
        }
        else
        {
            System.out.println("CONTROL-FAILED: " + detail);
        }
    }
}
