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

package org.openssl.jostle.test.loader;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.Loader;
import org.openssl.jostle.test.JvmProbe;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * Covers the loader system properties documented in README.md "Available properties":
 * {@code install_dir}, {@code load_lib_NN}, {@code load_name_NN}, {@code interface} and
 * {@code extract_openssl}.
 * <p>
 * Every one of them is read exactly once, inside {@code Loader.loadImpl()}, behind the
 * {@code loadAttempted} latch that {@code Loader.load()} sets on first call. By the time any
 * test body runs the provider has already initialised, so {@code System.setProperty} is a
 * no-op for these - the property has to be present at JVM start-up. Each test therefore
 * launches {@link LoaderProbeMain} in a fresh JVM with the properties under test on the
 * command line and asserts against the {@code Loader} state it reports back.
 * <p>
 * The child inherits this JVM's classpath but none of its {@code -D} flags, so the
 * {@code -Dorg.openssl.jostle.loader.interface} that the gradle test tasks set does not leak
 * in; every test states the strategy it needs.
 * <p>
 * Named {@code *IntegrationTest} so it runs in the sequential task - each case forks a JVM
 * that extracts native libraries, which should not happen concurrently.
 */
public class LoaderPropertyIntegrationTest
{
    private static final String P_INSTALL_DIR = "org.openssl.jostle.loader.install_dir";
    private static final String P_INTERFACE = "org.openssl.jostle.loader.interface";
    private static final String P_EXTRACT_OPENSSL = "org.openssl.jostle.loader.extract_openssl";
    //
    // Both spellings are accepted: the un-padded "_0" the format strings render, and the
    // zero-padded "_00" documented in README.md. Mirrored here as literals rather than
    // referenced from Loader, so a change to any format constant fails these tests instead
    // of silently moving the property the tests set.
    //
    private static final String P_LOAD_LIB = "org.openssl.jostle.loader.load_lib_%d";
    private static final String P_LOAD_NAME = "org.openssl.jostle.loader.load_name_%d";
    //
    // Native library names differ per platform: posix builds carry a "lib" prefix
    // (libinterface_jni.dylib / .so) while Windows does not (interface_jni.dll), and OpenSSL
    // ships as libcrypto.3.dylib / libcrypto.so.3 / libcrypto-3-x64.dll. Match on the
    // platform-neutral stem so an assertion means the same thing everywhere - and so the
    // negative assertions below cannot pass vacuously on a platform whose names never
    // contained the fragment being searched for.
    //
    private static final String JNI_LIB = "interface_jni";
    private static final String FFM_LIB = "interface_ffm";
    private static final String ANY_INTERFACE_LIB = "interface_";
    private static final String OPENSSL_LIB = "crypto";

    private static final String P_LOAD_LIB_PADDED = "org.openssl.jostle.loader.load_lib_%02d";
    private static final String P_LOAD_NAME_PADDED = "org.openssl.jostle.loader.load_name_%02d";

    //
    // ---------------------------------------------------------------- install_dir
    //

    /**
     * A fixed install dir must be honoured verbatim and must actually receive the extracted
     * libraries - not merely be reported back by the accessor.
     */
    @Test
    public void installDir_whenSet_isFixedAndReceivesTheExtractedLibraries() throws Exception
    {
        File installDir = createInstallDir("fixed");
        try
        {
            Probe probe = runProbe(props(
                    P_INSTALL_DIR, installDir.getAbsolutePath(),
                    P_INTERFACE, "jni"));

            probe.assertLoadSucceeded();
            Assertions.assertEquals("true", probe.get("fixedInstallDir"));
            Assertions.assertEquals(installDir.getAbsolutePath(), probe.get("installDir"));

            List<File> extracted = filesUnder(installDir);
            Assertions.assertFalse(extracted.isEmpty(),
                    "fixed install dir received no files: " + installDir);
            Assertions.assertTrue(namesOf(extracted).toString().contains(OPENSSL_LIB),
                    "expected the OpenSSL library under the fixed install dir, found: "
                            + namesOf(extracted));

            // The fixed dir holds one subdirectory named for the build version, without the leading "v".
            String version = System.getProperty("jostle.test.project.version");
            Assertions.assertNotNull(version, "jostle.test.project.version is not set by the build");
            Assertions.assertTrue(new File(installDir, version).isDirectory(),
                    "expected a versioned directory " + version + " under " + installDir);
        }
        finally
        {
            deleteBestEffort(installDir);
        }
    }

    /**
     * With no install dir set the loader falls back to java.io.tmpdir and reports the
     * directory as not fixed. Pinning java.io.tmpdir in the child makes the fallback
     * observable rather than machine dependent.
     */
    @Test
    public void installDir_whenUnset_fallsBackToJavaIoTmpdir() throws Exception
    {
        File tmpDir = createInstallDir("tmpdir");
        try
        {
            Probe probe = runProbe(props(
                    "java.io.tmpdir", tmpDir.getAbsolutePath(),
                    P_INTERFACE, "jni"));

            probe.assertLoadSucceeded();
            Assertions.assertEquals("false", probe.get("fixedInstallDir"));
            Assertions.assertEquals(tmpDir.getAbsolutePath(), probe.get("installDir"));
        }
        finally
        {
            deleteBestEffort(tmpDir);
        }
    }

    //
    // ---------------------------------------------------------------- interface
    //

    @Test
    public void interface_jni_selectsJniAndExtractsOnlyTheJniLibrary() throws Exception
    {
        Probe probe = runProbe(props(P_INTERFACE, "jni"));

        probe.assertLoadSucceeded();
        Assertions.assertEquals("JNI", probe.get("interfaceType"));
        Assertions.assertEquals("false", probe.get("isFFM"));
        Assertions.assertTrue(probe.anyLibContains(JNI_LIB),
                "JNI interface library not extracted: " + probe.libs());
        Assertions.assertFalse(probe.anyLibContains(FFM_LIB),
                "FFM interface library extracted under strategy 'jni': " + probe.libs());
    }

    @Test
    public void interface_ffm_selectsFfmAndExtractsOnlyTheFfmLibrary() throws Exception
    {
        Probe probe = runProbe(props(P_INTERFACE, "ffm"));

        probe.assertLoadSucceeded();
        Assertions.assertEquals("FFM", probe.get("interfaceType"));
        Assertions.assertEquals("true", probe.get("isFFM"));
        Assertions.assertTrue(probe.anyLibContains(FFM_LIB),
                "FFM interface library not extracted: " + probe.libs());
        Assertions.assertFalse(probe.anyLibContains(JNI_LIB),
                "JNI interface library extracted under strategy 'ffm': " + probe.libs());
    }

    /**
     * The documented "none" value: OpenSSL still comes out of the jar, but no interface
     * library is extracted and the caller is expected to supply one via load_lib/load_name.
     * Nothing in the test matrix exercises this value.
     */
    @Test
    public void interface_none_extractsOpenSslButNoInterfaceLibrary() throws Exception
    {
        Probe probe = runProbe(props(P_INTERFACE, "none"));

        probe.assertLoadSucceeded();
        Assertions.assertEquals("none", probe.get("interfaceType"));
        Assertions.assertEquals("false", probe.get("isFFM"));
        Assertions.assertTrue(probe.anyLibContains(OPENSSL_LIB),
                "OpenSSL should still be extracted under strategy 'none': " + probe.libs());
        Assertions.assertFalse(probe.anyLibContains(ANY_INTERFACE_LIB),
                "no interface library may be extracted under strategy 'none': " + probe.libs());
    }

    /**
     * The strategy is lower-cased before comparison, so the documented values are accepted in
     * any case. A regression here would reject "JNI" as an unsupported strategy.
     */
    @Test
    public void interface_valueIsCaseInsensitive() throws Exception
    {
        Probe probe = runProbe(props(P_INTERFACE, "JNI"));

        probe.assertLoadSucceeded();
        Assertions.assertEquals("JNI", probe.get("interfaceType"));
        Assertions.assertEquals("jni", probe.get("interfaceStrategy"));
    }

    /**
     * An unrecognised strategy must fail the load with a named message rather than silently
     * degrading to a default.
     */
    @Test
    public void interface_unsupportedValue_failsLoadWithNamedMessage() throws Exception
    {
        Probe probe = runProbe(props(P_INTERFACE, "sideways"));

        Assertions.assertEquals("false", probe.get("loadSuccessful"),
                "an unsupported strategy must not load: " + probe.get("message"));
        Assertions.assertEquals("Unsupported interface resolution 'sideways'", probe.get("message"));
        // The strategy is resolved before anything is extracted, so OpenSSL is not loaded either.
        Assertions.assertEquals("0", probe.get("libCount"), "nothing may be loaded: " + probe.libs());
        Assertions.assertEquals("none", probe.get("interfaceType"));
    }

    //
    // ---------------------------------------------------------------- extract_openssl
    //

    /**
     * extract_openssl=false under the default "auto" strategy: the bundled OpenSSL is not
     * extracted, the detected interface library is, and the first load is the path the caller
     * names in load_lib. The supplied copy lives outside the install dir, so the install dir is
     * not what satisfies the interface library's OpenSSL dependency.
     */
    @Test
    public void extractOpenssl_false_underAutoStrategy_extractsOnlyTheInterfaceLibrary() throws Exception
    {
        File seedDir = createInstallDir("autossl-seed");
        File suppliedDir = createInstallDir("autossl-supplied");
        File installDir = createInstallDir("autossl");
        try
        {
            File library = copyInto(extractOnceAndFind(seedDir, OPENSSL_LIB), suppliedDir);

            Probe probe = runProbe(props(
                    P_INSTALL_DIR, installDir.getAbsolutePath(),
                    P_EXTRACT_OPENSSL, "false",
                    String.format(P_LOAD_LIB, 0), library.getAbsolutePath()));

            probe.assertLoadSucceeded();
            Assertions.assertNotEquals("none", probe.get("interfaceType"));
            assertOnlyTheSuppliedOpenSsl(probe, library);
            Assertions.assertTrue(probe.anyLibContains(ANY_INTERFACE_LIB),
                    "the detected interface library must still be extracted: " + probe.libs());
            assertNoOpenSslUnder(installDir);
        }
        finally
        {
            deleteBestEffort(installDir);
            deleteBestEffort(suppliedDir);
            deleteBestEffort(seedDir);
        }
    }

    /**
     * The same with an explicit strategy: the bundled OpenSSL is not extracted, the named
     * interface library is, and the first load is the path the caller names in load_lib, which
     * lives outside the install dir.
     */
    @Test
    public void extractOpenssl_false_withExplicitStrategy_extractsOnlyTheInterfaceLibrary() throws Exception
    {
        File seedDir = createInstallDir("suppliedossl-seed");
        File suppliedDir = createInstallDir("suppliedossl-supplied");
        File installDir = createInstallDir("suppliedossl");
        try
        {
            File library = copyInto(extractOnceAndFind(seedDir, OPENSSL_LIB), suppliedDir);

            Probe probe = runProbe(props(
                    P_INSTALL_DIR, installDir.getAbsolutePath(),
                    P_EXTRACT_OPENSSL, "false",
                    P_INTERFACE, "jni",
                    String.format(P_LOAD_LIB, 0), library.getAbsolutePath()));

            probe.assertLoadSucceeded();
            Assertions.assertEquals("JNI", probe.get("interfaceType"));
            assertOnlyTheSuppliedOpenSsl(probe, library);
            Assertions.assertTrue(probe.anyLibContains(JNI_LIB),
                    "the JNI interface library must still be extracted: " + probe.libs());
            assertNoOpenSslUnder(installDir);
        }
        finally
        {
            deleteBestEffort(installDir);
            deleteBestEffort(suppliedDir);
            deleteBestEffort(seedDir);
        }
    }

    /**
     * With extract_openssl=false and the "none" strategy nothing is extracted; the caller
     * supplies both OpenSSL and the interface library.
     */
    @Test
    public void extractOpenssl_false_withNoneStrategy_extractsNothing() throws Exception
    {
        Probe probe = runProbe(props(
                P_EXTRACT_OPENSSL, "false",
                P_INTERFACE, "none"));

        probe.assertLoadSucceeded();
        Assertions.assertEquals("0", probe.get("libCount"),
                "nothing may be extracted: " + probe.libs());
        Assertions.assertEquals("none", probe.get("interfaceType"));
    }

    /**
     * Only the exact string "true" (any case) counts as true, so a non-boolean value reads as
     * false rather than falling back to the default.
     */
    @Test
    public void extractOpenssl_nonBooleanValue_readsAsFalse() throws Exception
    {
        Probe probe = runProbe(props(
                P_EXTRACT_OPENSSL, "yes",
                P_INTERFACE, "none"));

        probe.assertLoadSucceeded();
        Assertions.assertEquals("0", probe.get("libCount"),
                "'yes' is not 'true' and must read as false: " + probe.libs());
    }

    //
    // ---------------------------------------------------------------- load_lib_NN
    //

    /**
     * An absolute path in load_lib_00 is loaded and reported. The library is sourced by
     * running the loader once to extract it, which keeps the test free of any platform
     * specific library name or path.
     */
    @Test
    public void loadLib_absolutePath_isLoadedAndReported() throws Exception
    {
        File installDir = createInstallDir("loadlib");
        try
        {
            File library = extractOnceAndFind(installDir, OPENSSL_LIB);

            //
            // "none" + extract_openssl=false extracts nothing, so the only library the child
            // loads is the one named here.
            //
            Probe probe = runProbe(props(
                    P_EXTRACT_OPENSSL, "false",
                    P_INTERFACE, "none",
                    String.format(P_LOAD_LIB, 0), library.getAbsolutePath()));

            probe.assertLoadSucceeded();
            Assertions.assertEquals("1", probe.get("libCount"),
                    "expected exactly one load: " + probe.libs());
            Assertions.assertEquals("Path: " + library.getAbsolutePath(), probe.get("lib.0"));
        }
        finally
        {
            deleteBestEffort(installDir);
        }
    }

    @Test
    public void loadLib_unresolvablePath_failsLoad() throws Exception
    {
        Probe probe = runProbe(props(
                P_EXTRACT_OPENSSL, "false",
                String.format(P_LOAD_LIB, 0), "/no/such/directory/libnothing.so"));

        Assertions.assertEquals("false", probe.get("loadSuccessful"),
                "an unresolvable load_lib path must fail the load");
        Assertions.assertNotEquals("null", probe.get("message"), "a failure must carry a message");
    }

    /**
     * The scan starts at 00 and stops at the first missing index. With 00 absent the
     * unresolvable path parked at 01 must never be attempted, so the load still succeeds.
     */
    @Test
    public void loadLib_scanStopsAtFirstGap() throws Exception
    {
        Probe probe = runProbe(props(
                P_EXTRACT_OPENSSL, "false",
                P_INTERFACE, "none",
                String.format(P_LOAD_LIB, 1), "/no/such/directory/libnothing.so"));

        probe.assertLoadSucceeded();
        Assertions.assertEquals("0", probe.get("libCount"),
                "the scan must stop at the 00 gap and never reach 01: " + probe.libs());
    }

    //
    // ---------------------------------------------------------------- load_name_NN
    //

    @Test
    public void loadName_unresolvableName_failsLoad() throws Exception
    {
        Probe probe = runProbe(props(
                P_EXTRACT_OPENSSL, "false",
                String.format(P_LOAD_NAME, 0), "jostle_no_such_library"));

        Assertions.assertEquals("false", probe.get("loadSuccessful"),
                "an unresolvable load_name must fail the load");
        Assertions.assertNotEquals("null", probe.get("message"), "a failure must carry a message");
    }

    /**
     * Same gap semantics as load_lib: an unresolvable name at 01 is unreachable while 00 is
     * absent.
     */
    @Test
    public void loadName_scanStopsAtFirstGap() throws Exception
    {
        Probe probe = runProbe(props(
                P_EXTRACT_OPENSSL, "false",
                P_INTERFACE, "none",
                String.format(P_LOAD_NAME, 1), "jostle_no_such_library"));

        probe.assertLoadSucceeded();
        Assertions.assertEquals("0", probe.get("libCount"),
                "the scan must stop at the 00 gap and never reach 01: " + probe.libs());
    }

    /**
     * The zero-padded spelling README.md documents is accepted for the low indices where it
     * differs from the un-padded one. Before this was supported a config copied verbatim out
     * of the README loaded nothing at all, silently - the scan broke at the unset "_0" and
     * never looked at "_00".
     */
    @Test
    public void loadLib_zeroPaddedIndex_isAlsoAccepted() throws Exception
    {
        File installDir = createInstallDir("padded");
        try
        {
            File library = extractOnceAndFind(installDir, OPENSSL_LIB);

            Probe probe = runProbe(props(
                    P_EXTRACT_OPENSSL, "false",
                    P_INTERFACE, "none",
                    String.format(P_LOAD_LIB_PADDED, 0), library.getAbsolutePath()));

            probe.assertLoadSucceeded();
            Assertions.assertEquals("1", probe.get("libCount"),
                    "expected exactly one load: " + probe.libs());
            Assertions.assertEquals("Path: " + library.getAbsolutePath(), probe.get("lib.0"));
        }
        finally
        {
            deleteBestEffort(installDir);
        }
    }

    @Test
    public void loadName_zeroPaddedIndex_isAlsoAccepted() throws Exception
    {
        Probe probe = runProbe(props(
                P_EXTRACT_OPENSSL, "false",
                String.format(P_LOAD_NAME_PADDED, 0), "jostle_no_such_library"));

        //
        // Reaching the failure proves the padded name was read at all - an ignored property
        // would have broken the scan at index 0 and loaded successfully.
        //
        Assertions.assertEquals("false", probe.get("loadSuccessful"),
                "the zero-padded load_name must be read");
        Assertions.assertNotEquals("null", probe.get("message"), "a failure must carry a message");
    }

    /**
     * When a slot is set both ways the un-padded spelling wins. Pinning the precedence stops
     * it drifting: the fallback must stay a fallback.
     */
    @Test
    public void loadLib_unPaddedTakesPrecedenceOverZeroPadded() throws Exception
    {
        File installDir = createInstallDir("precedence");
        try
        {
            File library = extractOnceAndFind(installDir, OPENSSL_LIB);

            Probe probe = runProbe(props(
                    P_EXTRACT_OPENSSL, "false",
                    P_INTERFACE, "none",
                    String.format(P_LOAD_LIB, 0), library.getAbsolutePath(),
                    String.format(P_LOAD_LIB_PADDED, 0), "/no/such/directory/libnothing.so"));

            probe.assertLoadSucceeded();
            Assertions.assertEquals("1", probe.get("libCount"),
                    "expected exactly one load: " + probe.libs());
            Assertions.assertEquals("Path: " + library.getAbsolutePath(), probe.get("lib.0"),
                    "the un-padded value must win over the zero-padded one");
        }
        finally
        {
            deleteBestEffort(installDir);
        }
    }

    /**
     * The indexed property names are mirrored as literals above so the child JVM can be given
     * them on the command line. This pins the mirror to the loader's own constants - without
     * it, a change to any format string would move the real property and leave every indexed
     * test above setting one nothing reads, which is a silent pass.
     * <p>
     * From index ten up the padded and un-padded formats coincide, which is what lets the
     * loader skip the second lookup there; that is asserted rather than assumed.
     */
    @Test
    public void loadLibAndLoadName_mirroredNamesMatchTheLoaderConstants()
    {
        for (int t = 0; t != 12; t++)
        {
            Assertions.assertEquals(
                    String.format(Loader.LOAD_NATIVE_LIBS_FORMAT, t),
                    String.format(P_LOAD_LIB, t),
                    "load_lib property name drifted from Loader.LOAD_NATIVE_LIBS_FORMAT");
            Assertions.assertEquals(
                    String.format(Loader.LOAD_LIBS_BY_NAME_FORMAT, t),
                    String.format(P_LOAD_NAME, t),
                    "load_name property name drifted from Loader.LOAD_LIBS_BY_NAME_FORMAT");
            Assertions.assertEquals(
                    String.format(Loader.LOAD_NATIVE_LIBS_PADDED_FORMAT, t),
                    String.format(P_LOAD_LIB_PADDED, t),
                    "padded load_lib name drifted from Loader.LOAD_NATIVE_LIBS_PADDED_FORMAT");
            Assertions.assertEquals(
                    String.format(Loader.LOAD_LIBS_BY_NAME_PADDED_FORMAT, t),
                    String.format(P_LOAD_NAME_PADDED, t),
                    "padded load_name name drifted from Loader.LOAD_LIBS_BY_NAME_PADDED_FORMAT");

            boolean coincide = String.format(P_LOAD_LIB, t).equals(String.format(P_LOAD_LIB_PADDED, t));
            Assertions.assertEquals(t >= 10, coincide,
                    "padded and un-padded names must differ below ten and coincide from ten up");
        }
    }

    //
    // ---------------------------------------------------------------- absent libraries
    //

    /**
     * A jar built for another architecture carries this platform's deps file but not its libraries. The load
     * fails with one plain WARNING line naming the os, arch and absent path, and extracts nothing.
     */
    @Test
    public void absentLibraries_namesThePlatformAndPathAndExtractsNothing() throws Exception
    {
        Platform p = libraryLessPlatform();
        File installDir = createInstallDir("absent");
        try
        {
            // English log levels, so the WARNING count cannot change with the host locale.
            Probe probe = runProbe(props(
                    "os.name", p.os,
                    "os.arch", p.arch,
                    "user.language", "en",
                    P_INSTALL_DIR, installDir.getAbsolutePath()));

            Assertions.assertEquals("false", probe.get("loadSuccessful"));
            Assertions.assertEquals(absentMessage(p, p.root + "/" + p.ossl), probe.get("message"));
            Assertions.assertEquals("0", probe.get("libCount"), "nothing may be loaded: " + probe.libs());
            Assertions.assertEquals("none", probe.get("interfaceType"));
            Assertions.assertEquals(Collections.emptyList(), namesOf(filesUnder(installDir)),
                    "no install directory and no lock file may be created");
            Assertions.assertArrayEquals(new String[0], installDir.list(),
                    "no versioned directory may be created");
            assertOneWarningWithoutStackTrace(probe.raw(), probe.get("message"));
        }
        finally
        {
            deleteBestEffort(installDir);
        }
    }

    /**
     * An unsupported strategy is refused before anything is extracted: no versioned directory, no lock file.
     */
    @Test
    public void interface_unsupportedValue_leavesTheInstallDirEmpty() throws Exception
    {
        File installDir = createInstallDir("sideways");
        try
        {
            Probe probe = runProbe(props(
                    P_INSTALL_DIR, installDir.getAbsolutePath(),
                    P_INTERFACE, "sideways"));

            Assertions.assertEquals("false", probe.get("loadSuccessful"));
            Assertions.assertEquals("Unsupported interface resolution 'sideways'", probe.get("message"));
            Assertions.assertEquals("0", probe.get("libCount"), "nothing may be loaded: " + probe.libs());
            Assertions.assertArrayEquals(new String[0], installDir.list(),
                    "no versioned directory and no lock file may be created");
        }
        finally
        {
            deleteBestEffort(installDir);
        }
    }

    /**
     * With OpenSSL supplied by the caller the interface library is the one checked, and it is named.
     */
    @Test
    public void absentLibraries_withExtractOpensslFalse_namesTheInterfaceLibrary() throws Exception
    {
        Platform p = libraryLessPlatform();
        Probe probe = runProbe(props(
                "os.name", p.os,
                "os.arch", p.arch,
                P_EXTRACT_OPENSSL, "false",
                P_INTERFACE, "jni"));

        Assertions.assertEquals("false", probe.get("loadSuccessful"));
        Assertions.assertEquals(absentMessage(p, p.root + "/" + p.jni), probe.get("message"));
        Assertions.assertEquals("0", probe.get("libCount"), "nothing may be loaded: " + probe.libs());
    }

    /**
     * extract_openssl=false with the "none" strategy extracts nothing, so nothing is checked: unchanged.
     */
    @Test
    public void absentLibraries_withNothingToExtract_loadsAsBefore() throws Exception
    {
        Platform p = libraryLessPlatform();
        Probe probe = runProbe(props(
                "os.name", p.os,
                "os.arch", p.arch,
                P_EXTRACT_OPENSSL, "false",
                P_INTERFACE, "none"));

        probe.assertLoadSucceeded();
        Assertions.assertEquals("Loader Finished Successfully", probe.get("message"));
        Assertions.assertEquals("0", probe.get("libCount"), "nothing may be extracted: " + probe.libs());
        Assertions.assertEquals("none", probe.get("interfaceType"));
    }

    /**
     * The caller of the provider is told the loader's reason, after the leading text callers match on.
     */
    @Test
    public void absentLibraries_providerConstructionCarriesTheLoaderMessage() throws Exception
    {
        Platform p = libraryLessPlatform();
        JvmProbe.Result r = JvmProbe.run(ProviderConstructionProbeMain.class, props(
                "os.name", p.os,
                "os.arch", p.arch));

        Assertions.assertEquals("false", r.get("constructed"));
        Assertions.assertEquals(IllegalStateException.class.getName(), r.get("exceptionType"));
        Assertions.assertEquals("no access to native library: " + absentMessage(p, p.root + "/" + p.ossl),
                r.get("exceptionMessage"));
        Assertions.assertEquals(absentMessage(p, p.root + "/" + p.ossl), r.get("loaderMessage"));
    }

    /**
     * A platform no resolution line matches keeps its message, which now reaches the caller too.
     */
    @Test
    public void unmatchedPlatform_providerConstructionCarriesTheLoaderMessage() throws Exception
    {
        String os = System.getProperty("os.name");
        JvmProbe.Result r = JvmProbe.run(ProviderConstructionProbeMain.class, props(
                "os.name", os,
                "os.arch", "sparc"));

        Assertions.assertEquals("false", r.get("constructed"));
        Assertions.assertEquals(IllegalStateException.class.getName(), r.get("exceptionType"));
        Assertions.assertEquals(
                "no access to native library: no native support for os: '" + os + "' and arch: 'sparc'",
                r.get("exceptionMessage"));
    }

    /**
     * Strategy "none" binds the JNI interface. With no interface library supplied the caller is told which one
     * to supply, and no UnsatisfiedLinkError escapes.
     */
    @Test
    public void interface_none_withoutAnInterfaceLibrary_namesTheJniLibrary() throws Exception
    {
        JvmProbe.Result r = JvmProbe.run(ProviderConstructionProbeMain.class, props(
                P_EXTRACT_OPENSSL, "false",
                P_INTERFACE, "none"));

        Assertions.assertEquals("false", r.get("constructed"));
        Assertions.assertEquals(IllegalStateException.class.getName(), r.get("exceptionType"));
        Assertions.assertEquals(NONE_BINDS_JNI, r.get("exceptionMessage"));
    }

    /**
     * Supplying the FFM interface library under "none" does not help, because "none" binds JNI: same message.
     */
    @Test
    public void interface_none_withOnlyTheFfmLibrary_namesTheJniLibrary() throws Exception
    {
        Assumptions.assumeTrue(javaMajor() >= 22, "the FFM interface library is loadable on Java 22 and later");
        File seedDir = createInstallDir("none-ffm-seed");
        try
        {
            Probe seed = runProbe(props(
                    P_INSTALL_DIR, seedDir.getAbsolutePath(),
                    P_INTERFACE, "ffm"));
            seed.assertLoadSucceeded();
            File openssl = findUnder(seedDir, OPENSSL_LIB);
            File ffm = findUnder(seedDir, FFM_LIB);

            JvmProbe.Result r = JvmProbe.run(ProviderConstructionProbeMain.class, props(
                    P_EXTRACT_OPENSSL, "false",
                    P_INTERFACE, "none",
                    String.format(P_LOAD_LIB, 0), openssl.getAbsolutePath(),
                    String.format(P_LOAD_LIB, 1), ffm.getAbsolutePath()));

            Assertions.assertEquals("false", r.get("constructed"));
            Assertions.assertEquals(IllegalStateException.class.getName(), r.get("exceptionType"));
            Assertions.assertEquals(NONE_BINDS_JNI, r.get("exceptionMessage"));
        }
        finally
        {
            deleteBestEffort(seedDir);
        }
    }

    private static final String NONE_BINDS_JNI = "no access to native library: interface strategy 'none' binds the "
            + "JNI interface, supply the JNI interface library by load_lib or load_name";

    private static int javaMajor()
    {
        String v = System.getProperty("java.specification.version");
        return v.startsWith("1.") ? Integer.parseInt(v.substring(2)) : Integer.parseInt(v);
    }

    private static File findUnder(File dir, String nameFragment)
    {
        for (File candidate : filesUnder(dir))
        {
            if (candidate.getName().contains(nameFragment))
            {
                return candidate;
            }
        }
        Assertions.fail("no '" + nameFragment + "' library under " + dir + ", found: " + namesOf(filesUnder(dir)));
        return null;
    }

    private static String absentMessage(Platform p, String absentPath)
    {
        return String.format("no native libraries for os: '%s' and arch: '%s' in this jar ('%s' is absent), "
                + "use the openssl-jostle jar published for this architecture", p.os, p.arch, absentPath);
    }

    private static void assertOneWarningWithoutStackTrace(List<String> raw, String message)
    {
        int warnings = 0;
        for (String line : raw)
        {
            if (line.startsWith("WARNING: "))
            {
                warnings++;
                Assertions.assertEquals("WARNING: " + message, line);
            }
            Assertions.assertFalse(line.trim().startsWith("at ") || line.contains("Exception"),
                    "no stack trace expected: " + String.join("\n", raw));
        }
        Assertions.assertEquals(1, warnings, "expected one WARNING line: " + raw);
    }

    /**
     * A platform the resolutions file names whose deps file this jar carries and whose OpenSSL library it does
     * not. Each build holds the libraries of its own platform only, so one always exists.
     * <p>
     * The host's own OS family comes first, under the host's own os.name: a Java 8 JVM picks its file system
     * from os.name at start-up and does not start under another OS's name.
     */
    private static Platform libraryLessPlatform() throws IOException
    {
        String[][] all = {
                {"Linux", "amd64", "/native/linux/x86_64"},
                {"Linux", "aarch64", "/native/linux/aarch64"},
                {"Mac OS X", "aarch64", "/native/osx/arm64"},
                {"Mac OS X", "x86_64", "/native/osx/x86_64"},
                {"Windows 11", "amd64", "/native/windows/x86_64"}};
        String hostOs = System.getProperty("os.name");
        List<String[]> candidates = new ArrayList<>();
        for (String[] c : all)
        {
            if (hostOs.startsWith(c[0].split(" ")[0]))
            {
                candidates.add(new String[]{hostOs, c[1], c[2]});
            }
        }
        for (String[] c : all)
        {
            if (!hostOs.startsWith(c[0].split(" ")[0]))
            {
                candidates.add(c);
            }
        }
        for (String[] c : candidates)
        {
            List<String> deps = readResourceLines(c[2] + "/deps.txt");
            if (deps == null)
            {
                continue;
            }
            String ossl = depsEntry(deps, "OSSL:");
            String jni = depsEntry(deps, "JNI:");
            if (ossl != null && jni != null && Loader.class.getResource(c[2] + "/" + ossl) == null
                    && Loader.class.getResource(c[2] + "/" + jni) == null)
            {
                return new Platform(c[0], c[1], c[2], ossl, jni);
            }
        }
        Assertions.fail("no platform with a deps file and without its libraries on this classpath");
        return null;
    }

    private static String depsEntry(List<String> deps, String prefix)
    {
        for (String line : deps)
        {
            if (line.startsWith(prefix))
            {
                return line.substring(prefix.length()).trim();
            }
        }
        return null;
    }

    private static List<String> readResourceLines(String path) throws IOException
    {
        InputStream in = Loader.class.getResourceAsStream(path);
        if (in == null)
        {
            return null;
        }
        List<String> out = new ArrayList<>();
        BufferedReader reader = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8));
        try
        {
            String line = reader.readLine();
            while (line != null)
            {
                out.add(line);
                line = reader.readLine();
            }
        }
        finally
        {
            reader.close();
        }
        return out;
    }

    private static final class Platform
    {
        final String os;
        final String arch;
        final String root;
        final String ossl;
        final String jni;

        Platform(String os, String arch, String root, String ossl, String jni)
        {
            this.os = os;
            this.arch = arch;
            this.root = root;
            this.ossl = ossl;
            this.jni = jni;
        }
    }

    //
    // ---------------------------------------------------------------- helpers
    //

    /**
     * Runs the loader once with a fixed install dir so a real, platform-correct native
     * library path can be handed to the load_lib test.
     */
    private static File extractOnceAndFind(File installDir, String nameFragment) throws Exception
    {
        Probe seed = runProbe(props(
                P_INSTALL_DIR, installDir.getAbsolutePath(),
                P_INTERFACE, "jni"));
        seed.assertLoadSucceeded();

        for (File candidate : filesUnder(installDir))
        {
            if (candidate.getName().contains(nameFragment))
            {
                return candidate;
            }
        }

        Assertions.fail("no '" + nameFragment + "' library extracted under " + installDir
                + ", found: " + namesOf(filesUnder(installDir)));
        return null;
    }

    /**
     * Copies a library into another directory under its own file name, so the copy is the one
     * a later probe loads.
     */
    private static File copyInto(File library, File dir) throws IOException
    {
        File copy = new File(dir, library.getName());
        Files.copy(library.toPath(), copy.toPath());
        return copy;
    }

    private static void assertNoOpenSslUnder(File installDir)
    {
        for (File file : filesUnder(installDir))
        {
            Assertions.assertFalse(file.getName().contains(OPENSSL_LIB),
                    "no OpenSSL may be extracted into the install dir: " + namesOf(filesUnder(installDir)));
        }
    }

    /**
     * A directory for the child to extract into.
     * <p>
     * Deliberately not JUnit's {@code @TempDir}: the probe JVM {@code System.load}s whatever
     * it extracts, and Windows keeps a loaded DLL locked in a way that can outlive the child
     * process, so the directory is often undeletable when the test ends. {@code @TempDir}
     * treats that as a test failure, and the JUnit in use here (5.7.1) predates
     * {@code CleanupMode}, which would otherwise soften it. Cleanup is therefore best-effort:
     * a leftover directory is untidy, not a failure, and it lands in the same temp area the
     * loader itself extracts into during normal operation.
     */
    private static File createInstallDir(String label) throws IOException
    {
        File dir = File.createTempFile("jostle-loader-" + label + "-", "");
        if (!dir.delete() || !dir.mkdirs())
        {
            throw new IOException("could not create install dir at " + dir);
        }
        return dir;
    }

    private static void deleteBestEffort(File file)
    {
        File[] children = file.listFiles();
        if (children != null)
        {
            for (File child : children)
            {
                deleteBestEffort(child);
            }
        }

        //
        // Ignore the result: on Windows a still-mapped DLL cannot be removed, and that is not
        // something the test under way should fail for.
        //
        file.delete();
    }

    private static Map<String, String> props(String... keyThenValue)
    {
        return JvmProbe.props(keyThenValue);
    }

    private static void assertOnlyTheSuppliedOpenSsl(Probe probe, File library)
    {
        Assertions.assertEquals("Path: " + library.getAbsolutePath(), probe.get("lib.0"),
                "the supplied OpenSSL must be the first load: " + probe.libs());
        for (String lib : probe.libs().subList(1, probe.libs().size()))
        {
            Assertions.assertFalse(lib.contains(OPENSSL_LIB),
                    "the bundled OpenSSL must not be extracted: " + probe.libs());
        }
    }

    private static Probe runProbe(Map<String, String> properties) throws Exception
    {
        return new Probe(JvmProbe.run(LoaderProbeMain.class, properties));
    }

    private static List<File> filesUnder(File root)
    {
        List<File> out = new ArrayList<>();
        collectFiles(root, out);
        return out;
    }

    private static void collectFiles(File dir, List<File> out)
    {
        File[] entries = dir.listFiles();
        if (entries == null)
        {
            return;
        }

        for (File entry : entries)
        {
            if (entry.isDirectory())
            {
                collectFiles(entry, out);
            }
            else
            {
                out.add(entry);
            }
        }
    }

    private static List<String> namesOf(List<File> files)
    {
        List<String> out = new ArrayList<>();
        for (File file : files)
        {
            out.add(file.getName());
        }
        return out;
    }

    /**
     * Loader-shaped view over the generic probe result: the indexed {@code lib.N} lines the
     * loader probe reports are more usefully read as a list.
     */
    private static final class Probe
    {
        private final JvmProbe.Result result;

        private Probe(JvmProbe.Result result)
        {
            this.result = result;
        }

        String get(String key)
        {
            return result.get(key);
        }

        List<String> raw()
        {
            return result.raw();
        }

        List<String> libs()
        {
            List<String> out = new ArrayList<>();
            int count = Integer.parseInt(get("libCount"));
            for (int t = 0; t != count; t++)
            {
                out.add(get("lib." + t));
            }
            return Collections.unmodifiableList(out);
        }

        boolean anyLibContains(String fragment)
        {
            for (String lib : libs())
            {
                if (lib.contains(fragment))
                {
                    return true;
                }
            }
            return false;
        }

        void assertLoadSucceeded()
        {
            Assertions.assertEquals("true", get("loadSuccessful"),
                    "loader failed: " + get("message"));
        }
    }
}
