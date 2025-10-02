/*
 *  Copyright 2005-2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://www.openssl.org/source/license.html
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
    // a provider is foundational code, and should not force dependencies on its users.
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
     * "-Dorg.bouncycastle.jostle.loader.load_lib_0=path/to/lib"
     * "-Dorg.bouncycastle.jostle.loader.load_lib_1=/path/to/another_lib"
     * <p>
     * Remember to also include either the relevant FFI or JNI library
     */
    public static final String LOAD_NATIVE_LIBS_FORMAT = "org.openssl.jostle.loader.load_lib_%d";

    /**
     * Use this property to directly load a library by its name.
     * * Use an integer suffix of "_N" To load multiple libraries, for example:
     * * "-Dorg.bouncycastle.jostle.loader.load_name_0=openssl"
     * * "-Dorg.bouncycastle.jostle.loader.load_name_1=bc_openssl_ffi"
     * <p>
     * Remember to also include either the relevant FFI or JNI library
     */
    public static final String LOAD_LIBS_BY_NAME_FORMAT = "org.openssl.jostle.loader.load_name_%d";

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
            } catch (Throwable t)
            {
                L.log(Level.WARNING, t.getMessage(), t);
                message = t.getMessage();
                loadSuccessful = false;


            } finally
            {
                loadedLibs = Collections.unmodifiableList(loadedLibs);
            }

        }
    }

    private static void loadImpl()
            throws Throwable
    {
        extractOpenSSL = Properties.isOverrideSet(OPENSSL_EXTRACT, true);
        interfaceResolutionStrategy = Strings.toLowerCase(Properties.getPropertyValue(LOADER_INTERFACE, "auto"));

        String libDir = Properties.getPropertyValue(LIB_INSTALL_DIR);
        if (libDir == null)
        {
            L.fine(String.format("%s is not set so using java.io.tmpdir property", LIB_INSTALL_DIR));
            libDir = Properties.getPropertyValue("java.io.tmpdir");
        } else
        {
            fixedInstallDir = true;
        }

        //
        // Unable to resolve a temporary directory root!
        //
        if (libDir == null)
        {
            throw new IOException("Unable to resolve a temporary directory");
        }


        //
        // Load native libraries by file paths defined in LOAD_NATIVE_LIBS_xx properties
        //
        for (int t = 0; t < 100; t++)
        {
            String loadByPath = Properties.getPropertyValue(String.format(LOAD_NATIVE_LIBS_FORMAT, t));
            if (loadByPath == null)
            {
                break;
            }

            AccessWrapper.doAction(() -> {
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
            String name = Properties.getPropertyValue(String.format(LOAD_LIBS_BY_NAME_FORMAT, t));
            if (name == null)
            {
                break;
            }

            AccessWrapper.doAction(() -> {
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
                } else
                {
                    throw new IOException(String.format("resolution file entry '%s' is invalid", resolverEntry));
                }

                if (matcher.find())
                {
                    if (!arch.matches(matcher.group(1)))
                    {
                        continue;
                    }
                } else
                {
                    throw new IOException(String.format("resolution file entry '%s' is invalid", resolverEntry));
                }

                if (matcher.find())
                {
                    libRootInJar = matcher.group(1);
                    break;
                } else
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
                } else if (depfEntry.startsWith("JNI:"))
                {
                    extractions.add(new Extractions(depfEntry.substring(4).trim(), Extractions.Type.JNI));
                } else if (depfEntry.startsWith("FFI:"))
                {
                    extractions.add(new Extractions(depfEntry.substring(4).trim(), Extractions.Type.FFI));
                } else
                {
                    throw new IOException(String.format("deps file  entry '%s' is invalid", depfEntry));
                }
            }

            if (extractions.isEmpty())
            {
                throw new IOException("deps file was empty");
            }
        } else
        {
            L.warning("No resolutions file found on classpath");
        }

        if (!extractions.isEmpty() && (extractOpenSSL || interfaceResolutionStrategy != null))
        {
            final File installRootDir;
            if (fixedInstallDir)
            {
                String version = JostleProvider.INFO.substring(JostleProvider.INFO.lastIndexOf('v') + 1);

                installRootDir = LoaderUtils.createVersionedTempDir(libDir, version);
            } else
            {
                installRootDir = LoaderUtils.createTempDir("jostle");
            }

            FileOutputStream fos = null;
            FileLock lock = null;

            try
            {
                fos = new FileOutputStream(new File(installRootDir, "jostle.lock"));
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
                } else if ("ffi".equals(interfaceResolutionStrategy))
                {
                    interfaceType = Extractions.Type.FFI;
                    L.fine("JNI resolution strategy is JNI");
                } else if ("auto".equals(interfaceResolutionStrategy))
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
                    } catch (Throwable t)
                    {
                        interfaceType = Extractions.Type.JNI;
                        L.fine("JNI is detected");
                    }
                } else if (!"none".equals(interfaceResolutionStrategy))
                {
                    L.fine("Unknown resolution strategy detected: " + interfaceResolutionStrategy);
                    throw new IOException(String.format("Unsupported interface resolution '%s'", interfaceResolutionStrategy));
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
                } else
                {
                    L.fine("Interface library not extracted");
                }

            } finally
            {
                try
                {
                    lock.release();
                } catch (Throwable ignored)
                {
                }

                try
                {
                    fos.close();
                } catch (Throwable ignored)
                {
                }
            }
        }

        loadSuccessful = true;
        message = "Loader Finished Successfully";
    }

    private static void extractAndLoad(File installRootDir, String libRootInJar, Extractions extraction)
            throws Exception
    {
        String pathInJar = libRootInJar + "/" + extraction.name;
        File libFile = LoaderUtils.extractFromClasspath(installRootDir, pathInJar, extraction.name);
        if (libFile == null)
        {
            throw new IOException(String.format("extraction file '%s' not found", pathInJar));
        } else
        {
            L.fine(String.format("Wrote %s to %s, %d bytes", extraction.name, libFile.getAbsoluteFile(), libFile.length()));
        }
        System.load(libFile.getAbsolutePath());
        loadedLibs.add("Extracted: " + pathInJar);
    }

    /**
     * Recursively delete file / directory, if it is a directory it will recurse into that directory
     * endeavouring to delete all it can until ultimately trying to delete the passed in directory.
     * <p>
     * If it is a file it will delete that.
     *
     * @param src the target to delete
     */
    private static void delete(File src)
    {
        L.fine("Cleaning up: " + src.getAbsolutePath());
        if (src.isDirectory())
        {
            File[] files = src.listFiles();
            if (files != null)
            {
                for (File file : files)
                {
                    delete(file);
                }
            }
        }
        if (!src.delete())
        {
            L.fine("Failed to delete " + src);
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
            OSSL
        }

        final String name;
        final Type type;


        public Extractions(String pathInJar, Type type)
        {
            this.name = pathInJar;
            this.type = type;
        }
    }
}
