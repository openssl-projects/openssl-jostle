/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.test.multirelease;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.Loader;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.SymbolLookup;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import java.util.ArrayList;
import java.util.List;

/**
 * Source-level guard: every {@code *FIPSFFI} class resolves its symbols through
 * {@link org.openssl.jostle.jcajce.provider.fips.FIPSLibraryLookup}, never the
 * process-global {@code SymbolLookup.loaderLookup()}.
 *
 * <h2>Why this is structural and not behavioural</h2>
 *
 * The two interface libraries used to export the SAME {@code Jo*} symbol names.
 * A {@code *FIPSFFI} class that used the process-global loader lookup then bound
 * to whichever library the dynamic loader reached first — in practice the base
 * one — and drove mainline libcrypto's default provider while every caller
 * believed it was inside the FIPS module.
 *
 * <p>Nothing observable caught that for a family mainline implements
 * identically. It was tried: rebinding {@code MLDSAServiceFIPSFFI} to
 * {@code loaderLookup()} left the whole PQC suite AND
 * {@code FIPSModuleIsActuallyUsedTest} green, because that probe runs through
 * {@code OpenSSLFIPSFFI}, a different and still correctly-bound class. Behaviour
 * cannot distinguish two providers that compute the same answers, so the
 * invariant is enforced where it is expressible.
 *
 * <p><b>Since 2026-08-23 the names are disjoint</b> — the FIPS library's entry
 * points are renamed {@code JoFIPS_*} by the
 * {@code interface/fips/ffi/<x>_fips_ffi.c} wrappers, and the lookup and the
 * prefix reach the base FFI classes as two INDEPENDENT constructor parameters.
 * That turns the silent failure into a loud one: with the prefix right and the
 * lookup wrong, {@code loaderLookup()} cannot see the FIPS library at all (it is
 * deliberately never {@code System.load}ed) so nothing resolves; with the lookup
 * right and the prefix wrong, the FIPS library has no unprefixed exports, so
 * nothing resolves. Both sabotages were run and both throw
 * {@code NoSuchElementException} at construction. Only doing BOTH wrong is
 * silent, and that is indistinguishable from never having written a FIPS class.
 *
 * <p>{@link #builtLibrariesHaveDisjointEntryPoints()} pins that at the artefact
 * level; the source scan below stays because it is what keeps a new class from
 * reaching for {@code loaderLookup()} in the first place.
 *
 * <p>This mirrors {@code NativeReferenceParityTest}, which guards the
 * multi-release reachability pairing the same way and for the same reason —
 * the defect it prevents is invisible at runtime until it is far too late.
 *
 * <p>Lives beside {@code NativeReferenceParityTest} rather than in
 * {@code test.fips}, because it is a source-parity guard and not a FIPS-module
 * test: it reads source files and needs no module, so it must NOT gate on
 * {@code TEST_FIPS_LIB} and should run on the ordinary non-FIPS CI legs too.
 * {@code FIPSTestGateParityTest} enforces that every class under
 * {@code test.fips} gates at class level, which is exactly why this one does
 * not belong there.
 */
public class FIPSLibraryLookupParityTest
{
    private static final String FFI_DIR =
            "src/main/java25/org/openssl/jostle/jcajce/provider/fips";

    /**
     * The prefix the FIPS interface library's entry points carry. Mirrors
     * {@code FIPSLibraryLookup.SYMBOL_PREFIX}, which is package-private.
     */
    private static final String SYMBOL_PREFIX = "JoFIPS_";

    /**
     * One entry point per bridge family, spelled as the BASE library exports it.
     * Spread across families so a wrapper file omitted from
     * {@code FIPS_FFI_GLUE_SOURCES} is caught rather than only the one family a
     * single probe happened to name.
     * <p>
     * {@code JoOpenSSL_*} is deliberately absent: {@code ffi/openssl_ffi.c} is
     * not a twin any more, so the FIPS library has no prefixed counterpart to
     * find. {@link #fipsLibraryDoesNotCarryTheBaseInitGlue()} pins that instead.
     */
    private static final String[] ENTRY_POINTS = {
            "JoMD_Allocate", "JoMAC_allocate", "JoRSA_allocateSigner",
            "JoEC_generateKeyPair", "JoDSA_generateParameters", "JoDH_kexDerive",
            "JoMLDSA_sign", "JoMLKEM_generateKeyPair", "JoSLHDSA_sign",
            "JoSpec_Encap", "JoASN1_allocate", "JoRand_createContext",
            "JoCCM_init", "JoKDF_HKDF", "JoXEC_generateKeyPair",
            "JoBlockCipher_init",
            "JoNative_isAvailable", "JoFFI_freeUnsecureNullSafe",
    };

    /**
     * Every FFI symbol the Java layer resolves starts with {@code Jo}.
     * <p>
     * Two reasons, one old and one new. The old one is libcrypto: an export
     * named {@code RSA_sign} or {@code get_ossl_errors} can be shadowed by — or
     * shadow — a libcrypto symbol of the same name, and the resulting SIGSEGV
     * appears to come from inside libcrypto (see the {@code Jo*} prefix rule in
     * {@code .claude/guides/native-code.md}). The new one is that the FIPS
     * tree's rename wrappers need a uniform surface: {@code JoFIPS_} + a name
     * that is already distinctive stays readable and greppable, and a stray
     * unprefixed name is a hole in the disjointness the test below asserts.
     * <p>
     * Scans the sources rather than the binaries because it is the resolution
     * SITE that must be conventional — a symbol could be exported correctly and
     * still be reached by an unprefixed alias.
     */
    @Test
    public void everyResolvedFfiSymbolIsJoPrefixed() throws IOException
    {
        Path root = resolveFfiDir().getParent().getParent().getParent()
                .getParent().getParent().getParent();

        // lookup.find("X") and bind(lookup, "X", ...), with or without the
        // symPrefix concatenation the FIPS-capable classes carry.
        Pattern site = Pattern.compile(
                "(?:lookup\\.find\\(|bind\\(lookup, )(?:symPrefix \\+ )?\"([^\"]+)\"");

        List<String> offenders = new ArrayList<>();
        int checked = 0;
        List<Path> sources = new ArrayList<>();
        try (Stream<Path> walk = Files.walk(root))
        {
            walk.filter(p -> p.getFileName().toString().endsWith(".java")).forEach(sources::add);
        }
        for (Path f : sources)
        {
            Matcher m = site.matcher(Files.readString(f, StandardCharsets.UTF_8));
            while (m.find())
            {
                checked++;
                String sym = m.group(1);
                if (!sym.startsWith("Jo"))
                {
                    offenders.add(f.getFileName() + " resolves \"" + sym + "\"");
                }
            }
        }

        Assertions.assertTrue(checked > 100,
                "found only " + checked + " FFI symbol resolutions under " + root
                        + " — the scan pattern no longer matches how symbols are bound,"
                        + " so this test would pass vacuously");

        Assertions.assertTrue(offenders.isEmpty(),
                "FFI symbols resolved without a Jo prefix:\n  "
                        + String.join("\n  ", offenders)
                        + "\nRename the C export (both trees, byte-identical twins) and"
                        + " regenerate the FIPS wrapper's #define block.");
    }

    /**
     * The two built libraries share no entry-point name.
     * <p>
     * This is the property the whole rename exists for, asserted against the
     * artefacts rather than the source: the FIPS library must export
     * {@code JoFIPS_X} and NOT {@code X}, and the base library the reverse. A
     * wrapper file dropped from the CMake list, or a {@code #define} block that
     * missed a symbol, shows up here and nowhere else — the operation would keep
     * working, against the wrong library.
     * <p>
     * Both directions are asserted so the probe cannot pass vacuously: if
     * {@code find} returned empty for everything, the "base library exports the
     * unprefixed name" leg fails.
     */
    @Test
    public void builtLibrariesHaveDisjointEntryPoints()
    {
        // Nothing else in this class touches the provider, so the Loader has
        // not run. load() resolves and System.load's the base interface library
        // (which is what isFFI() reports on); loadFipsInterface() extracts the
        // FIPS one. Neither needs a FIPS module - only the packaged libraries -
        // so this test stays outside the TEST_FIPS_LIB gate.
        Loader.load();
        Assumptions.assumeTrue(Loader.isFFI(), "FFI interface not in use");
        Loader.loadFipsInterface();
        String fipsPath = Loader.getFipsInterfaceLibPath();
        Assumptions.assumeTrue(fipsPath != null,
                "FIPS interface library not extracted: " + Loader.getFipsMessage());

        SymbolLookup fips = SymbolLookup.libraryLookup(Paths.get(fipsPath), Arena.global());
        // The base library IS System.load'ed, so the process-global lookup is
        // how you reach it - and is exactly the lookup a mis-bound FIPS class
        // would have used.
        SymbolLookup base = SymbolLookup.loaderLookup();

        List<String> problems = new ArrayList<>();
        for (String sym : ENTRY_POINTS)
        {
            String prefixed = SYMBOL_PREFIX + sym;

            if (fips.find(sym).isPresent())
            {
                problems.add("FIPS library still exports the unprefixed \"" + sym
                        + "\" — a FIPS class with an empty prefix would resolve it silently");
            }
            if (fips.find(prefixed).isEmpty())
            {
                problems.add("FIPS library does not export \"" + prefixed
                        + "\" — its wrapper is missing from FIPS_FFI_GLUE_SOURCES,"
                        + " or the #define block omits the symbol");
            }
            if (base.find(prefixed).isPresent())
            {
                problems.add("base library exports \"" + prefixed
                        + "\" — the prefix no longer identifies the FIPS library");
            }
            if (base.find(sym).isEmpty())
            {
                problems.add("base library does not export \"" + sym
                        + "\" — the probe cannot tell absence from a renamed base library,"
                        + " so the assertions above would pass vacuously");
            }
        }

        Assertions.assertTrue(problems.isEmpty(),
                "FIPS and base interface libraries do not have disjoint entry points:\n  "
                        + String.join("\n  ", problems));
    }

    /**
     * The lib ctx accessors are named apart across the two trees, so no
     * same-named symbol exists for the dynamic loader to bind wrongly.
     * <p>
     * This is the deepest of the FIPS/base separations and the one whose
     * failure is quietest. The entry-point test above catches a Java class
     * bound to the wrong library. This catches the layer beneath it: a FIPS
     * library that resolved {@code get_global_jostle_ossl_lib_ctx} to the BASE
     * library's definition would run every {@code EVP_*_fetch} in the FIPS tree
     * against the non-FIPS lib ctx — correct-looking crypto from the wrong
     * provider, invisible to every functional test for any algorithm mainline
     * implements identically.
     * <p>
     * Until 2026-08-23 that was prevented only by {@code -Wl,-Bsymbolic} on the
     * FIPS targets (and macOS's two-level namespace). Both still apply and
     * still matter for the ~180 other shared util symbols, but a link option is
     * one edit away from being dropped and its absence is silent. Distinct
     * names make the property observable, which is what this test observes.
     * <p>
     * Both directions are asserted, so a probe that found nothing at all would
     * fail rather than pass vacuously.
     */
    @Test
    public void libCtxAccessorsAreNamedApartAcrossTheTwoLibraries()
    {
        Loader.load();
        Assumptions.assumeTrue(Loader.isFFI(), "FFI interface not in use");
        Loader.loadFipsInterface();
        String fipsPath = Loader.getFipsInterfaceLibPath();
        Assumptions.assumeTrue(fipsPath != null,
                "FIPS interface library not extracted: " + Loader.getFipsMessage());

        SymbolLookup fips = SymbolLookup.libraryLookup(Paths.get(fipsPath), Arena.global());
        SymbolLookup base = SymbolLookup.loaderLookup();

        // base name -> the fips tree's name for the same accessor.
        String[][] pairs = {
                {"get_global_jostle_ossl_lib_ctx", "get_global_jostle_fips_ossl_lib_ctx"},
                {"set_global_jostle_lib_ctx", "set_global_jostle_fips_lib_ctx"},
        };

        List<String> problems = new ArrayList<>();
        for (String[] pair : pairs)
        {
            String baseName = pair[0];
            String fipsName = pair[1];

            if (fips.find(baseName).isPresent())
            {
                problems.add("FIPS library exports \"" + baseName + "\" — the base library"
                        + " exports it too, so load-order interposition has a symbol to bind"
                        + " and FIPS fetches could run against the non-FIPS lib ctx");
            }
            if (fips.find(fipsName).isEmpty())
            {
                problems.add("FIPS library does not export \"" + fipsName
                        + "\" — the fips-named accessor is missing, so this test cannot tell"
                        + " separation from a library that failed to build");
            }
            if (base.find(fipsName).isPresent())
            {
                problems.add("base library exports \"" + fipsName
                        + "\" — the fips name no longer identifies the FIPS library");
            }
            if (base.find(baseName).isEmpty())
            {
                problems.add("base library does not export \"" + baseName
                        + "\" — with neither library exporting it the assertions above"
                        + " would pass vacuously");
            }
        }

        Assertions.assertTrue(problems.isEmpty(),
                "lib ctx accessors are not named apart across the interface libraries:\n  "
                        + String.join("\n  ", problems));
    }

    /**
     * The FIPS library owns its error reader and does NOT carry the base tree's
     * init glue.
     * <p>
     * Until 2026-08-23 {@code interface/fips/ffi/} held a byte-identical twin of
     * {@code openssl_ffi.c}, re-included so the FIPS library could reach
     * {@code JoOpenSSL_getErrors}. That also exported {@code JoOpenSSL_setModule},
     * which builds a lib ctx with {@code jostle_ctx_init_new} — no fipsinstall
     * config, no {@code fips=yes} default properties — and installs it as this
     * library's global. Nothing bound it, so it was never a live defect, but its
     * only possible effect was to make every FIPS fetch resolve to mainline.
     * <p>
     * The JNI side never had it: {@code fips/jni/} holds only
     * {@code openssl_fips_jni.c} with its own {@code getOSSLErrors}. This test
     * pins the FFI side to the same shape, so restoring the twin as a shortcut
     * fails here rather than quietly re-adding the entry point.
     */
    @Test
    public void fipsLibraryDoesNotCarryTheBaseInitGlue()
    {
        Loader.load();
        Assumptions.assumeTrue(Loader.isFFI(), "FFI interface not in use");
        Loader.loadFipsInterface();
        String fipsPath = Loader.getFipsInterfaceLibPath();
        Assumptions.assumeTrue(fipsPath != null,
                "FIPS interface library not extracted: " + Loader.getFipsMessage());

        SymbolLookup fips = SymbolLookup.libraryLookup(Paths.get(fipsPath), Arena.global());
        SymbolLookup base = SymbolLookup.loaderLookup();

        List<String> problems = new ArrayList<>();

        // The FIPS library owns its error reader, under its own name.
        if (fips.find("JoFIPS_get_openssl_errors").isEmpty())
        {
            problems.add("FIPS library does not export \"JoFIPS_get_openssl_errors\""
                    + " — OpenSSLFIPSFFI.getOSSLErrors would throw at first use");
        }

        // Neither spelling of the base init glue may be present.
        for (String gone : new String[]{
                "JoOpenSSL_setModule", "JoFIPS_JoOpenSSL_setModule",
                "JoOpenSSL_getErrors", "JoFIPS_JoOpenSSL_getErrors"})
        {
            if (fips.find(gone).isPresent())
            {
                problems.add("FIPS library exports \"" + gone + "\" — the openssl_ffi.c twin"
                        + " is back in FIPS_FFI_GLUE_SOURCES, which also re-exports a"
                        + " setModule that installs a NON-FIPS lib ctx as the FIPS global");
            }
        }

        // Control: the base library still has both, so a probe that found
        // nothing anywhere could not pass this test vacuously.
        for (String kept : new String[]{"JoOpenSSL_setModule", "JoOpenSSL_getErrors"})
        {
            if (base.find(kept).isEmpty())
            {
                problems.add("base library does not export \"" + kept
                        + "\" — the absence assertions above would pass vacuously");
            }
        }

        Assertions.assertTrue(problems.isEmpty(),
                "FIPS FFI library init-glue surface is wrong:\n  "
                        + String.join("\n  ", problems));
    }

    @Test
    public void everyFipsFfiClassUsesTheLibraryScopedLookup() throws IOException
    {
        Path dir = resolveFfiDir();
        List<String> offenders = new ArrayList<>();
        int checked = 0;

        try (DirectoryStream<Path> files = Files.newDirectoryStream(dir, "*FIPSFFI.java"))
        {
            for (Path f : files)
            {
                checked++;
                // Comments must be stripped first: these classes carry Javadoc
                // explaining why NOT to use loaderLookup, and a raw substring
                // match flags every correctly-written one. (Which it did.)
                String src = stripComments(
                        new String(Files.readAllBytes(f), StandardCharsets.UTF_8));

                if (src.contains("loaderLookup"))
                {
                    offenders.add(f.getFileName() + " uses SymbolLookup.loaderLookup()");
                }
                else if (!src.contains("FIPSLibraryLookup.get()"))
                {
                    // Neither the right lookup nor the wrong one: it resolves
                    // symbols some third way, which needs a human to look at.
                    offenders.add(f.getFileName() + " does not pass FIPSLibraryLookup.get()");
                }
            }
        }

        Assertions.assertTrue(checked > 5,
                "found only " + checked + " *FIPSFFI classes under " + dir
                        + " — the directory or glob is wrong and this test is vacuous");

        Assertions.assertTrue(offenders.isEmpty(),
                "FIPS FFI classes not bound to the FIPS interface library:\n  "
                        + String.join("\n  ", offenders)
                        + "\nBoth libraries export the same Jo* symbols, so these would drive "
                        + "the BASE library while every functional test still passed.");
    }

    /**
     * Java source with block and line comments removed, so a check for a
     * forbidden call cannot be tripped by prose describing it.
     * <p>
     * Deliberately naive - it does not understand string literals, which is
     * fine here: no {@code *FIPSFFI} class contains a string holding "//" or
     * "/*", and a false positive would fail loudly rather than pass silently.
     */
    private static String stripComments(String src)
    {
        StringBuilder out = new StringBuilder(src.length());
        int i = 0;
        while (i < src.length())
        {
            if (src.startsWith("/*", i))
            {
                int end = src.indexOf("*/", i + 2);
                i = end < 0 ? src.length() : end + 2;
            }
            else if (src.startsWith("//", i))
            {
                int end = src.indexOf('\n', i);
                i = end < 0 ? src.length() : end;
            }
            else
            {
                out.append(src.charAt(i));
                i++;
            }
        }
        return out.toString();
    }

    /**
     * The FFI source directory, whether the test runs from the repo root or
     * from the {@code jostle} subproject.
     */
    private static Path resolveFfiDir()
    {
        for (Path base : new Path[]{Paths.get(""), Paths.get("jostle"), Paths.get("..")})
        {
            Path p = base.resolve(FFI_DIR);
            if (Files.isDirectory(p))
            {
                return p;
            }
        }
        throw new IllegalStateException("cannot locate " + FFI_DIR
                + " from working directory " + Paths.get("").toAbsolutePath());
    }
}
