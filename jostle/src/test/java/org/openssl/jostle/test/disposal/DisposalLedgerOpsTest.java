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

package org.openssl.jostle.test.disposal;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.disposal.DisposalDaemon;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.NISelector;
import org.openssl.jostle.test.certpath.PkitsCertificates;
import org.openssl.jostle.util.ops.OperationsTestNI;
import org.openssl.jostle.util.ops.OperationsTestNI.LedgerType;
import org.openssl.jostle.util.ops.OperationsTestNI.OpsTestFlag;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.lang.ref.WeakReference;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumMap;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.BooleanSupplier;

/**
 * The C side of the disposal reconciliation: in an operations-test build every
 * native context type counts its creates and destroys, and after a forced
 * collection the two must agree for EVERY type in the library under test.
 *
 * <p>The Java ledger says the disposer was called; this says the native
 * destroy for that type ran, in the library that allocated it. A create counts
 * only on success, so a leak inside a failed create is not visible here.
 */
public class DisposalLedgerOpsTest
{
    /** Instances per family, as the Java reconciliation. */
    static final int K = 4;

    /** The family whose wrapper owns each type; the rest come from the extra drivers. */
    static final Map<String, LedgerType> TYPE_OF_FAMILY = new LinkedHashMap<String, LedgerType>();

    static
    {
        TYPE_OF_FAMILY.put("MDServiceSPI", LedgerType.MD_CTX);
        TYPE_OF_FAMILY.put("MacServiceSPI", LedgerType.MAC_CTX);
        TYPE_OF_FAMILY.put("RandServiceSPI", LedgerType.RAND_CTX);
        TYPE_OF_FAMILY.put("BlockCipherSpi", LedgerType.BLOCK_CIPHER_CTX);
        TYPE_OF_FAMILY.put("CCMCipherSpi", LedgerType.CCM_CTX);
        TYPE_OF_FAMILY.put("RSASignatureSpiBase", LedgerType.RSA_CTX);
        TYPE_OF_FAMILY.put("ECDSASignatureSpi", LedgerType.EC_CTX);
        TYPE_OF_FAMILY.put("DSASignatureSpi", LedgerType.DSA_CTX);
        TYPE_OF_FAMILY.put("EdSignatureSpi", LedgerType.EDEC_CTX);
        TYPE_OF_FAMILY.put("MLDSASignatureSpi", LedgerType.MLDSA_CTX);
        TYPE_OF_FAMILY.put("SLHDSASignatureSpi", LedgerType.SLH_DSA_CTX);
        TYPE_OF_FAMILY.put("ECDHKeyAgreementSpi", LedgerType.EC_KEX_CTX);
        // XDH disposes through the EC NI, so its context is an ec_kex_ctx.
        TYPE_OF_FAMILY.put("XDHKeyAgreementSpi", LedgerType.EC_KEX_CTX);
        TYPE_OF_FAMILY.put("DHKeyAgreementSpi", LedgerType.DH_KEX_CTX);
        TYPE_OF_FAMILY.put("RSAOAEPCipherSpi", LedgerType.RSA_OAEP_CTX);
        TYPE_OF_FAMILY.put("RSAPKCS1CipherSpi", LedgerType.RSA_PKCS1_CTX);
        TYPE_OF_FAMILY.put("KSServiceSPI", LedgerType.KS_CTX);
        TYPE_OF_FAMILY.put("PKEYKeySpec", LedgerType.KEY_SPEC);
    }

    /** Types no family owns: freed inside the call that made them, driven separately. */
    static final EnumSet<LedgerType> EXTRA_TYPES =
            EnumSet.of(LedgerType.ASN1_CTX, LedgerType.X509_CERT, LedgerType.X509_CRL);

    private DisposalRecorder recorder;

    @BeforeAll
    public static void beforeAll()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    protected Provider provider()
    {
        return Security.getProvider(JostleProvider.PROVIDER_NAME);
    }

    /** The ledger of the library this provider drives. */
    protected OperationsTestNI ops()
    {
        return NISelector.OperationsTestNI;
    }

    /**
     * Every cell starts from a settled process: every family driven once so
     * lazily populated caches exist, then collections until no disposal event
     * arrives for several cycles, so handles from before the reset cannot be
     * destroyed inside the measured window. Only then is the ledger zeroed.
     */
    @BeforeEach
    public void settleAndReset() throws Exception
    {
        Assumptions.assumeTrue(ops().opsTestAvailable(), "not an operations-test build");
        ops().resetFlags();
        warm(provider());
        settle();
        ops().ledgerReset();
        recorder = new DisposalRecorder();
        DisposalDaemon.addListener(recorder);
    }

    private static void warm(Provider provider) throws Exception
    {
        for (DisposalFamilies.Driver d : DisposalFamilies.drivers(provider))
        {
            try
            {
                d.driveOnce();
            }
            catch (Throwable ignored)
            {
                // A family that cannot be driven is reported by the measured cell.
            }
        }
        driveExtras(provider);
    }

    /** Quiet cycles before the process counts as settled. */
    private static final int QUIET_CYCLES = 5;

    /** Collects until no disposal has arrived for QUIET_CYCLES cycles, or the cap. */
    static void settle() throws InterruptedException
    {
        DisposalRecorder watch = new DisposalRecorder();
        DisposalDaemon.addListener(watch);
        try
        {
            final int[] last = {watch.disposedCount(), 0};
            DisposalDrain.drain(new BooleanSupplier()
            {
                public boolean getAsBoolean()
                {
                    int now = watch.disposedCount();
                    last[1] = now == last[0] ? last[1] + 1 : 0;
                    last[0] = now;
                    return last[1] >= QUIET_CYCLES;
                }
            });
        }
        finally
        {
            DisposalDaemon.removeListener(watch);
        }
    }

    @AfterEach
    public void cleanUp()
    {
        if (ops().opsTestAvailable())
        {
            ops().resetFlags();
        }
        if (recorder != null)
        {
            DisposalDaemon.removeListener(recorder);
            recorder = null;
        }
    }

    /** The mapping must name every type, or a new type is silently unmeasured. */
    @Test
    public void everyLedgerTypeIsOwnedByAFamilyOrAnExtraDriver()
    {
        EnumSet<LedgerType> owned = EnumSet.copyOf(TYPE_OF_FAMILY.values());
        owned.addAll(EXTRA_TYPES);
        EnumSet<LedgerType> missing = EnumSet.complementOf(owned);
        Assertions.assertTrue(missing.isEmpty(), "ledger types no driver produces: " + missing);
    }

    /** Snapshot of created / destroyed per type. */
    protected static Map<LedgerType, int[]> snapshot(OperationsTestNI ni)
    {
        Map<LedgerType, int[]> out = new EnumMap<LedgerType, int[]>(LedgerType.class);
        for (LedgerType t : LedgerType.values())
        {
            out.put(t, new int[]{ni.ledgerCreated(t), ni.ledgerDestroyed(t)});
        }
        return out;
    }

    protected static String table(Map<LedgerType, int[]> counts)
    {
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<LedgerType, int[]> e : counts.entrySet())
        {
            sb.append("\n  ").append(e.getKey()).append(" created=").append(e.getValue()[0])
                    .append(" destroyed=").append(e.getValue()[1]);
        }
        return sb.toString();
    }

    protected static List<LedgerType> unbalanced(Map<LedgerType, int[]> counts)
    {
        List<LedgerType> out = new ArrayList<LedgerType>();
        for (Map.Entry<LedgerType, int[]> e : counts.entrySet())
        {
            if (e.getValue()[0] != e.getValue()[1])
            {
                out.add(e.getKey());
            }
        }
        return out;
    }

    /**
     * Drives K instances of every family plus the extra types, in its OWN frame
     * so nothing in the caller's frame roots the drivers during the drain.
     */
    private List<String> driveEverything(Provider provider, List<String> families, List<String> modes)
            throws Exception
    {
        List<String> broken = new ArrayList<String>();
        for (DisposalFamilies.Driver d : DisposalFamilies.drivers(provider))
        {
            families.add(d.family());
            for (int i = 0; i < K; i++)
            {
                try
                {
                    d.driveOnce();
                }
                catch (Throwable t)
                {
                    broken.add(d + ": " + t);
                    break;
                }
            }
            modes.add(d.family() + "=" + (d.detail().isEmpty() ? "-" : d.detail()));
        }
        for (int i = 0; i < K; i++)
        {
            driveExtras(provider);
        }
        return broken;
    }

    /** An encoding (asn1_ctx), a certificate and a CRL (x509 handles), each freed inside its call. */
    static void driveExtras(Provider provider) throws Exception
    {
        KeyPair kp = KeyPairGenerator.getInstance("EC", provider).generateKeyPair();
        Assertions.assertNotNull(kp.getPublic().getEncoded());
        CertificateFactory cf = CertificateFactory.getInstance("X.509", provider);
        cf.generateCertificate(new ByteArrayInputStream(PkitsCertificates.der(PkitsCertificates.ANCHOR)));
        cf.generateCRL(new ByteArrayInputStream(PkitsCertificates.crlDer("TrustAnchorRootCRL.crl")));
    }

    private int drain(final WeakReference<Object> sentinel) throws InterruptedException
    {
        return DisposalDrain.drain(new BooleanSupplier()
        {
            public boolean getAsBoolean()
            {
                return sentinel.get() == null && recorder.isDrained();
            }
        });
    }

    @Test
    public void everyTypeBalancesAfterADrain() throws Exception
    {
        Provider provider = provider();

        Object[] holder = new Object[]{new Object()};
        final WeakReference<Object> sentinel = new WeakReference<Object>(holder[0]);

        beforeDriving();
        List<String> families = new ArrayList<String>();
        List<String> modes = new ArrayList<String>();
        List<String> broken = driveEverything(provider, families, modes);
        Assertions.assertTrue(broken.isEmpty(), "drivers failed:\n  " + String.join("\n  ", broken));
        holder[0] = null;

        int cycles = drain(sentinel);
        Assumptions.assumeTrue(sentinel.get() == null, "the sentinel never cleared");
        Assertions.assertTrue(recorder.isDrained(),
                "the Java ledger did not drain in " + cycles + " cycles: "
                        + recorder.describe(recorder.missing()));
        Assertions.assertEquals(0, recorder.failedCount(), "disposers failed: " + recorder.failures());

        Map<LedgerType, int[]> counts = snapshot(ops());
        System.out.println("[ledger] provider=" + provider.getName() + " cycles=" + cycles
                + " modes=" + modes + table(counts));
        afterDraining(modes);

        List<LedgerType> off = unbalanced(counts);
        Assertions.assertTrue(off.isEmpty(), "types whose native destroy count differs from its create count: "
                + off + table(counts));

        // Every type a driven family or extra produces must have been counted.
        EnumSet<LedgerType> expected = EnumSet.copyOf(EXTRA_TYPES);
        for (String family : families)
        {
            LedgerType t = TYPE_OF_FAMILY.get(family);
            Assertions.assertNotNull(t, "no ledger type mapped for driven family " + family);
            expected.add(t);
        }
        List<LedgerType> silent = new ArrayList<LedgerType>();
        for (LedgerType t : expected)
        {
            if (counts.get(t)[0] == 0)
            {
                silent.add(t);
            }
        }
        Assertions.assertTrue(silent.isEmpty(), "types driven but never counted as created: " + silent + table(counts));
        Assertions.assertTrue(expected.size() >= minimumTypesExpected(),
                "only " + expected.size() + " types expected on " + provider.getName() + ": " + expected);
    }

    /** Called before the families are driven; the FIPS twin snapshots the other library here. */
    protected void beforeDriving()
    {
    }

    /** Called after the drain, before the balance assertions, with each driver's family=mode. */
    protected void afterDraining(List<String> modes)
    {
    }

    /** JSL drives all 20; the FIPS twin lowers this to what its modules register. */
    protected int minimumTypesExpected()
    {
        return LedgerType.values().length;
    }

    /**
     * The positive control: with the free skipped on one digest, the ledger
     * must show that type, and only that type, off by exactly one.
     */
    @Test
    public void aSkippedFreeShowsOnExactlyThatType() throws Exception
    {
        Provider provider = provider();

        Object[] holder = new Object[]{new Object()};
        final WeakReference<Object> sentinel = new WeakReference<Object>(holder[0]);

        ops().setFlag(OpsTestFlag.OPS_LEDGER_SKIP_FREE_1);
        makeAndDropOneDigest(provider);
        holder[0] = null;
        drain(sentinel);
        ops().resetFlags();
        Assumptions.assumeTrue(sentinel.get() == null, "the sentinel never cleared");
        Assertions.assertTrue(recorder.isDrained(), "the Java side did not report the digest disposed");

        Map<LedgerType, int[]> counts = snapshot(ops());
        int[] md = counts.get(LedgerType.MD_CTX);
        Assertions.assertEquals(1, md[0] - md[1],
                "with the free skipped MD_CTX must be off by exactly one" + table(counts));
        List<LedgerType> off = unbalanced(counts);
        Assertions.assertEquals(Arrays.asList(LedgerType.MD_CTX), off,
                "only MD_CTX may be unbalanced" + table(counts));
    }

    private static void makeAndDropOneDigest(Provider provider) throws Exception
    {
        MessageDigest md = MessageDigest.getInstance(
                DisposalFamilies.familiesOf(provider).get("MDServiceSPI"), provider);
        md.update(new byte[16]);
        md.digest();
    }

    /** One fault-injected create path. */
    private static final class Fault
    {
        final OpsTestFlag flag;
        final String site;
        final String[] families;
        final Runnable[] extras;

        Fault(OpsTestFlag flag, String site, String[] families, Runnable... extras)
        {
            this.flag = flag;
            this.site = site;
            this.families = families;
            this.extras = extras;
        }
    }

    /**
     * Every create-path OPS flag, run with the ledger watching: a create that
     * fails must leave created equal to destroyed for every type, so a counted
     * create that then fails, or a cleanup that counts a destroy the create
     * never counted, shows here. One row per flag, read from the C sites.
     */
    @Test
    public void everyCreatePathFaultLeavesTheLedgerBalanced() throws Exception
    {
        final Provider provider = provider();

        // Keys and encodings first, with no flag set, so a row fails at its create and not at keygen;
        // then settle, so what that pass dropped is destroyed before any row's window opens.
        Map<String, DisposalFamilies.Driver> byFamily = new LinkedHashMap<String, DisposalFamilies.Driver>();
        for (DisposalFamilies.Driver d : DisposalFamilies.drivers(provider))
        {
            d.driveOnce();
            byFamily.put(d.family(), d);
        }
        final byte[] encodedKey = KeyPairGenerator.getInstance("EC", provider).generateKeyPair()
                .getPublic().getEncoded();
        final byte[] certDer = PkitsCertificates.der(PkitsCertificates.ANCHOR);
        final String mdAlg = DisposalFamilies.familiesOf(provider).get("MDServiceSPI");
        final String macAlg = DisposalFamilies.familiesOf(provider).get("MacServiceSPI");
        settle();

        Runnable cloneDigest = new Runnable()
        {
            public void run()
            {
                try
                {
                    MessageDigest md = MessageDigest.getInstance(mdAlg, provider);
                    md.update(new byte[8]);
                    md.clone();
                }
                catch (Exception e)
                {
                    throw new RuntimeException(e);
                }
            }
        };
        Runnable cloneMac = new Runnable()
        {
            public void run()
            {
                try
                {
                    Mac mac = Mac.getInstance(macAlg, provider);
                    mac.init(new SecretKeySpec(new byte[32], macAlg));
                    mac.update(new byte[8]);
                    mac.clone();
                }
                catch (Exception e)
                {
                    throw new RuntimeException(e);
                }
            }
        };
        Runnable decodeKey = new Runnable()
        {
            public void run()
            {
                try
                {
                    KeyFactory.getInstance("EC", provider).generatePublic(new X509EncodedKeySpec(encodedKey));
                }
                catch (Exception e)
                {
                    throw new RuntimeException(e);
                }
            }
        };
        Runnable decodeCert = new Runnable()
        {
            public void run()
            {
                try
                {
                    CertificateFactory.getInstance("X.509", provider)
                            .generateCertificate(new ByteArrayInputStream(certDer));
                }
                catch (Exception e)
                {
                    throw new RuntimeException(e);
                }
            }
        };

        String[] none = new String[0];
        Fault[] faults = new Fault[]{
                new Fault(OpsTestFlag.OPS_FAILED_CREATE_1, "md.c md_ctx_create", new String[]{"MDServiceSPI"}),
                new Fault(OpsTestFlag.OPS_FAILED_INIT_1, "md.c md_ctx_create", new String[]{"MDServiceSPI"}),
                new Fault(OpsTestFlag.OPS_FAILED_CREATE_2, "md.c md_ctx_copy; ccm_ctx.c ccm_ctx_create",
                        new String[]{"CCMCipherSpi"}, cloneDigest),
                new Fault(OpsTestFlag.OPS_OPENSSL_ERROR_11, "md.c md_ctx_copy; rand.c", none, cloneDigest),
                new Fault(OpsTestFlag.OPS_OPENSSL_ERROR_12, "md.c md_ctx_copy", none, cloneDigest),
                new Fault(OpsTestFlag.OPS_OPENSSL_ERROR_1, "mac.c allocate_mac; edec.c; rand.c; x509.c",
                        new String[]{"MacServiceSPI", "EdSignatureSpi", "RandServiceSPI"}, decodeCert),
                new Fault(OpsTestFlag.OPS_OPENSSL_ERROR_2, "mac.c allocate_mac; x509.c",
                        new String[]{"MacServiceSPI"}, decodeCert),
                new Fault(OpsTestFlag.OPS_OPENSSL_ERROR_8, "mac.c mac_copy", none, cloneMac),
                new Fault(OpsTestFlag.OPS_OPENSSL_ERROR_9, "mac.c mac_copy; rand.c",
                        new String[]{"RandServiceSPI"}, cloneMac),
                new Fault(OpsTestFlag.OPS_OPENSSL_ERROR_10, "rand.c rand_ctx_create_with_parent",
                        new String[]{"RandServiceSPI"}),
                new Fault(OpsTestFlag.OPS_INT32_OVERFLOW_1, "asn1_util.c decode", none, decodeKey),
                new Fault(OpsTestFlag.OPS_POINTER_CHANGE, "asn1_util.c decode", none, decodeKey),
        };

        List<String> report = new ArrayList<String>();
        List<String> problems = new ArrayList<String>();
        for (Fault f : faults)
        {
            ops().ledgerReset();
            int refusals = 0;
            int actions = 0;
            ops().setFlag(f.flag);
            try
            {
                for (String family : f.families)
                {
                    DisposalFamilies.Driver d = byFamily.get(family);
                    if (d == null)
                    {
                        continue;
                    }
                    actions++;
                    refusals += refuses(new Callable(d));
                }
                for (Runnable r : f.extras)
                {
                    actions++;
                    refusals += refuses(r);
                }
            }
            finally
            {
                ops().resetFlags();
            }
            Object[] holder = new Object[]{new Object()};
            WeakReference<Object> sentinel = new WeakReference<Object>(holder[0]);
            holder[0] = null;
            drain(sentinel);
            settle();

            Map<LedgerType, int[]> counts = snapshot(ops());
            List<LedgerType> off = unbalanced(counts);
            report.add(f.flag + " (" + f.site + "): actions=" + actions + " refused=" + refusals
                    + " unbalanced=" + off);
            if (actions == 0)
            {
                problems.add(f.flag + ": no driver on this provider reaches its create");
            }
            else if (refusals == 0)
            {
                problems.add(f.flag + ": nothing failed, so the flag reached no create");
            }
            if (!off.isEmpty())
            {
                problems.add(f.flag + ": unbalanced " + off + table(counts));
            }
        }
        System.out.println("[ledger-faults] provider=" + provider.getName() + "\n  " + String.join("\n  ", report));
        Assertions.assertTrue(problems.isEmpty(), String.join("\n", problems));
    }

    private static final class Callable implements Runnable
    {
        private final DisposalFamilies.Driver driver;

        Callable(DisposalFamilies.Driver driver)
        {
            this.driver = driver;
        }

        public void run()
        {
            try
            {
                driver.driveOnce();
            }
            catch (Exception e)
            {
                throw new RuntimeException(e);
            }
        }
    }

    /** 1 when the action threw, 0 when it succeeded; a fault row needs at least one refusal. */
    private static int refuses(Runnable action)
    {
        try
        {
            action.run();
            return 0;
        }
        catch (Throwable t)
        {
            return 1;
        }
    }
}
