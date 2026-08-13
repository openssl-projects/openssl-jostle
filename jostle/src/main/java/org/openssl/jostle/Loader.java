/*
 *  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle;


import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.util.AccessWrapper;
import org.openssl.jostle.util.Properties;
import org.openssl.jostle.util.Strings;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.channels.FileLock;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Loads native libraries
 */
public class Loader
{

    // NB:
    // Before requesting we use some other logging framework, please consider that
    // a provider is foundational code and should not force dependencies on its users.
    //
    private static final Logger L = Logger.getLogger("BC_OPENSSL_LOADER");

    /**
     * Set this property to change the root path where extracted libraries will be stored.
     * By default, they are installed in the system / user temp dir, but on some platforms loading native
     * libraries from system / user temp directories is disabled.
     */
    public static final String LIB_INSTALL_DIR = "org.openssl.jostle.loader.install_dir";

    /**
     * Use this property to directly load a library from the file system.
     * Use an integer suffix of "_N" To load multiple libraries, for example:
     * "-Dorg.openssl.jostle.loader.load_lib_0=path/to/lib"
     * "-Dorg.openssl.jostle.loader.load_lib_1=/path/to/another_lib"
     * <p>
     * Indices below ten are also accepted zero padded ("_00", "_01"), the spelling
     * used in README.md; see {@link #LOAD_NATIVE_LIBS_PADDED_FORMAT}.
     * <p>
     * Remember to also include either the relevant FFI or JNI library
     */
    public static final String LOAD_NATIVE_LIBS_FORMAT = "org.openssl.jostle.loader.load_lib_%d";

    /**
     * Zero-padded spelling of {@link #LOAD_NATIVE_LIBS_FORMAT}, consulted only for indices
     * below ten and only when the un-padded name is unset - from ten up the two formats
     * produce the same property name.
     */
    public static final String LOAD_NATIVE_LIBS_PADDED_FORMAT = "org.openssl.jostle.loader.load_lib_%02d";

    /**
     * Use this property to directly load a library by its name.
     * * Use an integer suffix of "_N" To load multiple libraries, for example:
     * * "-Dorg.openssl.jostle.loader.load_name_0=openssl"
     * * "-Dorg.openssl.jostle.loader.load_name_1=bc_openssl_ffi"
     * <p>
     * Indices below ten are also accepted zero padded ("_00", "_01"), the spelling
     * used in README.md; see {@link #LOAD_LIBS_BY_NAME_PADDED_FORMAT}.
     * <p>
     * Remember to also include either the relevant FFI or JNI library
     */
    public static final String LOAD_LIBS_BY_NAME_FORMAT = "org.openssl.jostle.loader.load_name_%d";

    /**
     * Zero-padded spelling of {@link #LOAD_LIBS_BY_NAME_FORMAT}, consulted only for indices
     * below ten and only when the un-padded name is unset - from ten up the two formats
     * produce the same property name.
     */
    public static final String LOAD_LIBS_BY_NAME_PADDED_FORMAT = "org.openssl.jostle.loader.load_name_%02d";

    /**
     * Use this property to control the extraction and loading of the interface libs.
     * Values are: "auto","jni", "ffi" and "none";
     */
    public static final String LOADER_INTERFACE = "org.openssl.jostle.loader.interface";

    /**
     * Set this property false to disable extraction the OpenSSL libraries, default is true
     */
    public static final String OPENSSL_EXTRACT = "org.openssl.jostle.loader.extract_openssl";


    private static boolean loadAttempted = false;
    private static boolean loadSuccessful = true;
    private static Extractions.Type interfaceType;
    private static String interfaceResolutionStrategy;
    private static String message = null;
    private static Object sync = new Object();
    private static List<String> loadedLibs = new ArrayList<>();
    private static boolean extractOpenSSL = true;
    private static boolean fixedInstallDir = false;
    private static String installDir;

    // State captured by loadImpl for the lazy, provider-driven FIPS interface
    // load (loadFipsInterface). The FIPS entries (F_JNI:/F_FFI:) are parsed
    // with everything else but never loaded by load() itself.
    private static File installRootDirUsed = null;
    private static String libRootUsed = null;
    private static List<Extractions> parsedExtractions = new ArrayList<>();
    private static boolean fipsLoadAttempted = false;
    private static boolean fipsLoadSuccessful = false;
    private static String fipsMessage = null;
    private static String fipsInterfaceLibPath = null;

    public static void load()
    {
        synchronized (sync)
        {
            if (loadAttempted)
            {
                return;
            }

            loadAttempted = true;
            try
            {
                loadImpl();
            }
            catch (Throwable t)
            {
                L.log(Level.WARNING, t.getMessage(), t);
                message = t.getMessage();
                loadSuccessful = false;


            }
            finally
            {
                loadedLibs = Collections.unmodifiableList(loadedLibs);
            }

        }
    }

    /**
     * Resolve one slot of an indexed loader property, accepting both the un-padded spelling
     * ("_0") the format strings produce and the zero-padded spelling ("_00") documented in
     * README.md. The un-padded name wins when both are set.
     * <p>
     * Only indices below ten need the second lookup - at ten and above "%d" and "%02d"
     * render the same name, so the padded probe would repeat the first one.
     *
     * @param plainFormat  the un-padded format string.
     * @param paddedFormat the zero-padded format string.
     * @param index        the slot to resolve.
     * @return the property value, or null when neither spelling is set.
     */
    private static String indexedProperty(String plainFormat, String paddedFormat, int index)
    {
        String value = Properties.getPropertyValue(String.format(plainFormat, index));
        if (value == null && index < 10)
        {
            value = Properties.getPropertyValue(String.format(paddedFormat, index));
        }
        return value;
    }

    private static void loadImpl()
            throws Throwable
    {
        extractOpenSSL = Properties.isOverrideSet(OPENSSL_EXTRACT, true);
        interfaceResolutionStrategy = Strings.toLowerCase(Properties.getPropertyValue(LOADER_INTERFACE, "auto"));

        installDir = Properties.getPropertyValue(LIB_INSTALL_DIR);
        if (installDir == null)
        {
            L.fine(String.format("%s is not set so using java.io.tmpdir property", LIB_INSTALL_DIR));
            installDir = Properties.getPropertyValue("java.io.tmpdir");
        }
        else
        {
            fixedInstallDir = true;
        }

        //
        // Unable to resolve a temporary directory root!
        //
        if (installDir == null)
        {
            throw new IOException("Unable to resolve a temporary directory");
        }


        //
        // Load native libraries by file paths defined in LOAD_NATIVE_LIBS_xx properties
        //
        for (int t = 0; t < 100; t++)
        {
            String loadByPath = indexedProperty(LOAD_NATIVE_LIBS_FORMAT, LOAD_NATIVE_LIBS_PADDED_FORMAT, t);
            if (loadByPath == null)
            {
                break;
            }

            AccessWrapper.doAction(() ->
            {
                L.fine(String.format("Loading native library '%s'", loadByPath));
                System.load(loadByPath);
                loadedLibs.add("Path: " + loadByPath);
                return null;
            });
        }

        //
        // Attempt loading by name
        //
        for (int t = 0; t < 100; t++)
        {
            String name = indexedProperty(LOAD_LIBS_BY_NAME_FORMAT, LOAD_LIBS_BY_NAME_PADDED_FORMAT, t);
            if (name == null)
            {
                break;
            }

            AccessWrapper.doAction(() ->
            {
                L.fine(String.format("Loading native library '%s'", name));
                System.loadLibrary(name);
                loadedLibs.add("Name: " + name);
                return null;
            });
        }

        //
        // Resolve and load the extractions
        //
        final Pattern quote = Pattern.compile("[\"](\\\"|[^\"]+)[\"]");
        List<Extractions> extractions = new ArrayList<>();
        String libRootInJar = null;


        String os = Properties.getPropertyValue("os.name", "unknown");
        String arch = Properties.getPropertyValue("os.arch", "unknown");
        List<String> resolverEntries = LoaderUtils.readStreamToLines(Loader.class.getResourceAsStream("/native/resolutions.txt"));

        if (resolverEntries != null)
        {

            // we expect:
            // "os regexp" "arch regexp" "path to deps file from root of jar"
            for (String resolverEntry : resolverEntries)
            {
                Matcher matcher = quote.matcher(resolverEntry);

                if (matcher.find())
                {
                    if (!os.matches(matcher.group(1)))
                    {
                        continue;
                    }
                }
                else
                {
                    throw new IOException(String.format("resolution file entry '%s' is invalid", resolverEntry));
                }

                if (matcher.find())
                {
                    if (!arch.matches(matcher.group(1)))
                    {
                        continue;
                    }
                }
                else
                {
                    throw new IOException(String.format("resolution file entry '%s' is invalid", resolverEntry));
                }

                if (matcher.find())
                {
                    libRootInJar = matcher.group(1);
                    break;
                }
                else
                {
                    throw new IOException(String.format("resolution file entry '%s' is invalid", resolverEntry));
                }
            }

            if (libRootInJar == null)
            {
                message = String.format("no native support for os: '%s' and arch: '%s'", os, arch);
                L.warning(message);
                loadSuccessful = false;
                return;
            }


            List<String> depfFileEntries = LoaderUtils.readStreamToLines(Loader.class.getResourceAsStream(libRootInJar + "/" + "deps.txt"));
            if (depfFileEntries == null)
            {
                throw new IOException(String.format("resolution file entry '%s' was not found", libRootInJar));
            }


            for (String depfEntry : depfFileEntries)
            {
                if (depfEntry.startsWith("OSSL:"))
                {
                    extractions.add(new Extractions(depfEntry.substring(5).trim(), Extractions.Type.OSSL));
                }
                else
                {
                    if (depfEntry.startsWith("JNI:"))
                    {
                        extractions.add(new Extractions(depfEntry.substring(4).trim(), Extractions.Type.JNI));
                    }
                    else
                    {
                        if (depfEntry.startsWith("FFI:"))
                        {
                            extractions.add(new Extractions(depfEntry.substring(4).trim(), Extractions.Type.FFI));
                        }
                        else
                        {
                            if (depfEntry.startsWith("F_JNI:"))
                            {
                                extractions.add(new Extractions(depfEntry.substring(6).trim(), Extractions.Type.FIPS_JNI));
                            }
                            else
                            {
                                if (depfEntry.startsWith("F_FFI:"))
                                {
                                    extractions.add(new Extractions(depfEntry.substring(6).trim(), Extractions.Type.FIPS_FFI));
                                }
                                else
                                {
                                    throw new IOException(String.format("deps file entry '%s' is invalid", depfEntry));
                                }
                            }
                        }
                    }
                }
            }

            if (extractions.isEmpty())
            {
                throw new IOException("deps file was empty");
            }
        }
        else
        {
            L.warning("No resolutions file found on classpath");
        }

        libRootUsed = libRootInJar;
        parsedExtractions = extractions;

        if (!extractions.isEmpty() && (extractOpenSSL || !"auto".equals(interfaceResolutionStrategy)))
        {
            final File installRootDir = resolveInstallRootDir();
            installRootDirUsed = installRootDir;

            FileOutputStream fos = null;
            FileLock lock = null;

            try
            {
                fos = new FileOutputStream(LoaderUtils.makeFile(installRootDir, "jostle.lock"));
                lock = fos.getChannel().lock();

                //
                // Iterate the list of extractions, extracting and loading any library tagged OSSL in the deps
                // file in order.
                //

                for (Extractions extraction : extractions)
                {
                    if (extraction.type == Extractions.Type.OSSL)
                    {
                        extractAndLoad(installRootDir, libRootInJar, extraction);
                    }
                }

                //
                // Handle interface type resolution.
                //

                if ("jni".equals(interfaceResolutionStrategy))
                {
                    interfaceType = Extractions.Type.JNI;
                    L.fine("JNI resolution strategy is JNI");
                }
                else
                {
                    if ("ffi".equals(interfaceResolutionStrategy))
                    {
                        interfaceType = Extractions.Type.FFI;
                        L.fine("JNI resolution strategy is JNI");
                    }
                    else
                    {
                        if ("auto".equals(interfaceResolutionStrategy))
                        {
                            L.fine("JNI resolution strategy is auto");
                            try
                            {
                                //
                                // This will only be available for Java 22 and above runtimes.
                                //
                                Class.forName("org.openssl.jostle.FFI");
                                interfaceType = Extractions.Type.FFI;
                                L.fine("FFI is detected");
                            }
                            catch (Throwable t)
                            {
                                interfaceType = Extractions.Type.JNI;
                                L.fine("JNI is detected");
                            }
                        }
                        else
                        {
                            if (!"none".equals(interfaceResolutionStrategy))
                            {
                                L.fine("Unknown resolution strategy detected: " + interfaceResolutionStrategy);
                                throw new IOException(String.format("Unsupported interface resolution '%s'", interfaceResolutionStrategy));
                            }
                        }
                    }
                }

                if (interfaceType != null)
                {
                    for (Extractions extraction : extractions)
                    {
                        if (extraction.type == interfaceType)
                        {
                            extractAndLoad(installRootDir, libRootInJar, extraction);
                        }
                    }
                }
                else
                {
                    L.fine("Interface library not extracted");
                }

            }
            finally
            {
                try
                {
                    lock.release();
                }
                catch (Throwable ignored)
                {
                }

                try
                {
                    fos.close();
                }
                catch (Throwable ignored)
                {
                }
            }
        }

        loadSuccessful = true;
        message = "Loader Finished Successfully";
    }

    private static File resolveInstallRootDir()
            throws IOException
    {
        if (fixedInstallDir)
        {
            String version = JostleProvider.INFO.substring(JostleProvider.INFO.lastIndexOf('v') + 1);

            return LoaderUtils.createVersionedTempDir(installDir, version);
        }
        return LoaderUtils.createTempDir("jostle");
    }

    private static File extractOnly(File installRootDir, String libRootInJar, Extractions extraction, String[] sources)
            throws Exception
    {
        String pathInJar = libRootInJar + "/" + extraction.name;
        File libFile = LoaderUtils.extractFromClasspath(installRootDir, pathInJar, extraction.name, sources);
        if (libFile == null)
        {
            throw new IOException(String.format("extraction file '%s' not found", pathInJar));
        }
        else
        {
            L.fine(String.format("Wrote %s to %s, %d bytes", extraction.name, libFile.getAbsoluteFile(), libFile.length()));
        }
        return libFile;
    }

    private static void extractAndLoad(File installRootDir, String libRootInJar, Extractions extraction)
            throws Exception
    {
        String[] sources = new String[2];
        File libFile = extractOnly(installRootDir, libRootInJar, extraction, sources);
        System.load(libFile.getAbsolutePath());


        if (sources[0] != null && sources[1] != null)
        {
            loadedLibs.add("Loaded: " + sources[1]);
            loadedLibs.add("  Compared to: " + sources[0]);
        }
        else
        {
            loadedLibs.add("Extracted: " + sources[0]);
        }
    }

    /**
     * Lazily extract (and for JNI, load) the FIPS interface library. Never
     * driven by {@link #load()}: only FIPS-aware code (the FIPS NI selector,
     * reached from the FIPS provider) triggers it, so non-FIPS deployments
     * never touch the FIPS library. Idempotent; one attempt per JVM.
     *
     * <p>The flavor follows the base interface resolution (JNI or FFI). The
     * FFI flavor is extracted but deliberately NOT System.load'ed: the FIPS
     * library shares export names with the base interface library, so its
     * symbols must never enter the process-global loader lookup - the FIPS
     * FFI implementation dlopens it via a library-scoped SymbolLookup on
     * {@link #getFipsInterfaceLibPath()} instead.
     *
     * <p>The OpenSSL FIPS module itself (fips.dylib / fips.so / fips.dll) is
     * NOT bundled or extracted - libcrypto loads it from the externally
     * configured module directory.
     */
    public static void loadFipsInterface()
    {
        synchronized (sync)
        {
            load();

            if (fipsLoadAttempted)
            {
                return;
            }
            fipsLoadAttempted = true;

            try
            {
                loadFipsImpl();
                fipsLoadSuccessful = true;
                fipsMessage = "FIPS interface loaded";
            }
            catch (Throwable t)
            {
                L.log(Level.WARNING, t.getMessage(), t);
                fipsMessage = t.getMessage();
                fipsLoadSuccessful = false;
            }
        }
    }

    private static void loadFipsImpl()
            throws Throwable
    {
        if (!loadSuccessful)
        {
            throw new IOException(String.format("base loader failed: %s", message));
        }
        if (interfaceType == null)
        {
            throw new IOException("interface resolution strategy is 'none'; no FIPS interface flavor to load");
        }

        Extractions.Type wanted = interfaceType == Extractions.Type.FFI
                ? Extractions.Type.FIPS_FFI : Extractions.Type.FIPS_JNI;

        Extractions target = null;
        for (Extractions extraction : parsedExtractions)
        {
            if (extraction.type == wanted)
            {
                target = extraction;
                break;
            }
        }
        if (target == null)
        {
            throw new IOException(String.format("deps file has no %s entry for this platform", wanted));
        }

        File installRootDir = installRootDirUsed;
        if (installRootDir == null)
        {
            installRootDir = resolveInstallRootDir();
        }

        FileOutputStream fos = null;
        FileLock lock = null;
        try
        {
            fos = new FileOutputStream(LoaderUtils.makeFile(installRootDir, "jostle.lock"));
            lock = fos.getChannel().lock();

            String[] sources = new String[2];
            File libFile = extractOnly(installRootDir, libRootUsed, target, sources);
            if (wanted == Extractions.Type.FIPS_JNI)
            {
                System.load(libFile.getAbsolutePath());
            }
            fipsInterfaceLibPath = libFile.getAbsolutePath();
        }
        finally
        {
            try
            {
                lock.release();
            }
            catch (Throwable ignored)
            {
            }

            try
            {
                fos.close();
            }
            catch (Throwable ignored)
            {
            }
        }
    }

    public static boolean isLoadAttempted()
    {
        return loadAttempted;
    }

    public static boolean isLoadSuccessful()
    {
        return loadSuccessful;
    }

    public static String getMessage()
    {
        return message;
    }

    public static String getInterfaceTypeName()
    {
        if (interfaceType == null)
        {
            return "none";
        }
        return interfaceType.toString();

    }

    public static String getInterfaceResolutionStrategy()
    {
        return interfaceResolutionStrategy;
    }

    public static List<String> getLoadedLibs()
    {
        return loadedLibs;
    }

    public static boolean isFFI()
    {
        return Extractions.Type.FFI == interfaceType;
    }

    public static String getInstallDir()
    {
        return installDir;
    }

    public static boolean isFixedInstallDir()
    {
        return fixedInstallDir;
    }

    public static boolean isFipsLoadAttempted()
    {
        return fipsLoadAttempted;
    }

    public static boolean isFipsLoadSuccessful()
    {
        return fipsLoadSuccessful;
    }

    public static String getFipsMessage()
    {
        return fipsMessage;
    }

    /**
     * Absolute path of the extracted FIPS interface library, or null if
     * {@link #loadFipsInterface()} has not succeeded. The FIPS FFI
     * implementation opens this with a library-scoped SymbolLookup.
     */
    public static String getFipsInterfaceLibPath()
    {
        return fipsInterfaceLibPath;
    }

    private static class Extractions
    {

        private enum Type
        {
            /**
             * JNI interface library
             */
            JNI,
            /**
             * FFI interface library
             */
            FFI,
            /**
             * OpenSSL library or related
             */
            OSSL,
            /**
             * FIPS JNI interface library - loaded lazily by loadFipsInterface, never by load()
             */
            FIPS_JNI,
            /**
             * FIPS FFI interface library - extracted lazily by loadFipsInterface (not System.load'ed)
             */
            FIPS_FFI
        }

        final String name;
        final Type type;


        public Extractions(String name, Type type)
        {
            this.name = name;
            this.type = type;
        }
    }
}
