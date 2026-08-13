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
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.openssl.jostle.Loader;
import org.openssl.jostle.test.JvmProbe;

import java.io.File;
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
    public void installDir_whenSet_isFixedAndReceivesTheExtractedLibraries(@TempDir File installDir)
            throws Exception
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
        Assertions.assertTrue(namesOf(extracted).toString().contains("libcrypto"),
                "expected libcrypto under the fixed install dir, found: " + namesOf(extracted));
    }

    /**
     * With no install dir set the loader falls back to java.io.tmpdir and reports the
     * directory as not fixed. Pinning java.io.tmpdir in the child makes the fallback
     * observable rather than machine dependent.
     */
    @Test
    public void installDir_whenUnset_fallsBackToJavaIoTmpdir(@TempDir File tmpDir)
            throws Exception
    {
        Probe probe = runProbe(props(
                "java.io.tmpdir", tmpDir.getAbsolutePath(),
                P_INTERFACE, "jni"));

        probe.assertLoadSucceeded();
        Assertions.assertEquals("false", probe.get("fixedInstallDir"));
        Assertions.assertEquals(tmpDir.getAbsolutePath(), probe.get("installDir"));
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
        Assertions.assertEquals("false", probe.get("isFFI"));
        Assertions.assertTrue(probe.anyLibContains("libinterface_jni"),
                "JNI interface library not extracted: " + probe.libs());
        Assertions.assertFalse(probe.anyLibContains("libinterface_ffi"),
                "FFI interface library extracted under strategy 'jni': " + probe.libs());
    }

    @Test
    public void interface_ffi_selectsFfiAndExtractsOnlyTheFfiLibrary() throws Exception
    {
        Probe probe = runProbe(props(P_INTERFACE, "ffi"));

        probe.assertLoadSucceeded();
        Assertions.assertEquals("FFI", probe.get("interfaceType"));
        Assertions.assertEquals("true", probe.get("isFFI"));
        Assertions.assertTrue(probe.anyLibContains("libinterface_ffi"),
                "FFI interface library not extracted: " + probe.libs());
        Assertions.assertFalse(probe.anyLibContains("libinterface_jni"),
                "JNI interface library extracted under strategy 'ffi': " + probe.libs());
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
        Assertions.assertEquals("false", probe.get("isFFI"));
        Assertions.assertTrue(probe.anyLibContains("libcrypto"),
                "OpenSSL should still be extracted under strategy 'none': " + probe.libs());
        Assertions.assertFalse(probe.anyLibContains("libinterface_"),
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
    }

    //
    // ---------------------------------------------------------------- extract_openssl
    //

    /**
     * extract_openssl=false suppresses extraction entirely - including the interface library,
     * since the flag gates the whole extraction block rather than just the OSSL entries.
     */
    @Test
    public void extractOpenssl_false_underAutoStrategy_extractsNothing() throws Exception
    {
        Probe probe = runProbe(props(P_EXTRACT_OPENSSL, "false"));

        probe.assertLoadSucceeded();
        Assertions.assertEquals("0", probe.get("libCount"),
                "nothing may be extracted: " + probe.libs());
        Assertions.assertEquals("none", probe.get("interfaceType"));
    }

    /**
     * The caveat documented in README.md: the suppression only applies while the interface
     * strategy is "auto". Naming any explicit strategy re-enables the extraction block, and
     * OpenSSL comes out with it despite extract_openssl=false.
     */
    @Test
    public void extractOpenssl_false_withExplicitStrategy_stillExtractsOpenSsl() throws Exception
    {
        Probe probe = runProbe(props(
                P_EXTRACT_OPENSSL, "false",
                P_INTERFACE, "jni"));

        probe.assertLoadSucceeded();
        Assertions.assertTrue(probe.anyLibContains("libcrypto"),
                "an explicit strategy re-enables extraction: " + probe.libs());
        Assertions.assertTrue(probe.anyLibContains("libinterface_jni"),
                "an explicit strategy re-enables extraction: " + probe.libs());
    }

    /**
     * Only the exact string "true" (any case) counts as true, so a non-boolean value reads as
     * false rather than falling back to the default.
     */
    @Test
    public void extractOpenssl_nonBooleanValue_readsAsFalse() throws Exception
    {
        Probe probe = runProbe(props(P_EXTRACT_OPENSSL, "yes"));

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
    public void loadLib_absolutePath_isLoadedAndReported(@TempDir File installDir) throws Exception
    {
        File library = extractOnceAndFind(installDir, "libcrypto");

        //
        // auto + extract_openssl=false skips the extraction block entirely, so the only
        // library the child loads is the one named here.
        //
        Probe probe = runProbe(props(
                P_EXTRACT_OPENSSL, "false",
                String.format(P_LOAD_LIB, 0), library.getAbsolutePath()));

        probe.assertLoadSucceeded();
        Assertions.assertEquals("1", probe.get("libCount"), "expected exactly one load: " + probe.libs());
        Assertions.assertEquals("Path: " + library.getAbsolutePath(), probe.get("lib.0"));
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
    public void loadLib_zeroPaddedIndex_isAlsoAccepted(@TempDir File installDir) throws Exception
    {
        File library = extractOnceAndFind(installDir, "libcrypto");

        Probe probe = runProbe(props(
                P_EXTRACT_OPENSSL, "false",
                String.format(P_LOAD_LIB_PADDED, 0), library.getAbsolutePath()));

        probe.assertLoadSucceeded();
        Assertions.assertEquals("1", probe.get("libCount"), "expected exactly one load: " + probe.libs());
        Assertions.assertEquals("Path: " + library.getAbsolutePath(), probe.get("lib.0"));
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
    public void loadLib_unPaddedTakesPrecedenceOverZeroPadded(@TempDir File installDir)
            throws Exception
    {
        File library = extractOnceAndFind(installDir, "libcrypto");

        Probe probe = runProbe(props(
                P_EXTRACT_OPENSSL, "false",
                String.format(P_LOAD_LIB, 0), library.getAbsolutePath(),
                String.format(P_LOAD_LIB_PADDED, 0), "/no/such/directory/libnothing.so"));

        probe.assertLoadSucceeded();
        Assertions.assertEquals("1", probe.get("libCount"), "expected exactly one load: " + probe.libs());
        Assertions.assertEquals("Path: " + library.getAbsolutePath(), probe.get("lib.0"),
                "the un-padded value must win over the zero-padded one");
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

    private static Map<String, String> props(String... keyThenValue)
    {
        return JvmProbe.props(keyThenValue);
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
