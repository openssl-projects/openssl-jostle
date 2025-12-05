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

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Loads native libraries
 */
class LoaderUtils
{
    private static final Logger LOG = Logger.getLogger(LoaderUtils.class.getName());

    /**
     * Returns a fresh temp dir base on prefix path.
     *
     * @param moduleName name of the temp dir is being created for.
     * @return a File representing the destination directory.
     * @throws IOException
     */
    static File createTempDir(String moduleName)
        throws IOException
    {
        if (moduleName == null)
        {
            throw new NullPointerException("moduleName cannot be null");
        }

        String prefixPath = getPropertyValue("java.io.tmpdir");

        try
        {
            return AccessController.doPrivileged(new PrivilegedAction<File>()
            {
                @Override
                public File run()
                {
                    File prefix = new File(prefixPath);

                    if (prefix.isFile())
                    {
                        throw new IllegalStateException(String.format("'%s' exists and is a file", prefixPath));
                    }

                    if (!prefix.exists())
                    {
                        if (!prefix.mkdirs())
                        {
                            throw new IllegalStateException(String.format("failed to create temporary directory '%s'", prefixPath));
                        }
                    }

                    //
                    // We create our own temp dir because using the inbuilt one may
                    // try and create an entropy source which may cause a failure as this provider
                    // may not be fully installed.
                    //
                    long now = System.nanoTime();
                    for (int t = 0; t < 10000; t++)
                    {
                        File dir = new File(prefix, String.format("%s_%d", moduleName, now + t));
                        if (dir.exists() || !dir.mkdirs())
                        {
                            continue;
                        }

                        final File tmpDir = dir;
                        
                        //
                        // Shutdown hook clean up installed libraries.
                        //
                        Runtime.getRuntime().addShutdownHook(new Thread(new Runnable()
                        {
                            @Override
                            public void run()
                            {
                                if (LOG.isLoggable(Level.FINE))
                                {
                                    LOG.fine("cleanup shutdown hook started");
                                }

                                if (!tmpDir.exists())
                                {
                                    return;
                                }
                                boolean isDeleted = true;
                                if (tmpDir.isDirectory())
                                {
                                    for (File f : tmpDir.listFiles())
                                    {
                                        isDeleted &= f.delete();
                                    }
                                }

                                isDeleted &= tmpDir.delete();

                                if (!isDeleted)
                                {
                                    LOG.fine("failed to delete: " + tmpDir.getAbsolutePath());
                                }
                                else
                                {
                                    LOG.fine("successfully cleaned up: " + tmpDir.getAbsolutePath());
                                }
                            }
                        }));

                        return dir;
                    }

                    throw new IllegalStateException(String.format("failed to create temporary directory in '%s'", prefixPath));
                }
            });

        }
        catch (IllegalStateException e)
        {
            throw new IOException(e.getMessage(), e);
        }
    }

    /**
     * Returns a fresh temp dir or the prefixPath as a file if versioning is in use.
     *
     * @param prefixPath Path to where the temp dir is created.
     * @param version    software version string, non-null if versioning in use.
     * @return a File representing the destination directory.
     * @throws IOException
     */
    static File createVersionedTempDir(String prefixPath, String version)
        throws IOException
    {
        if (version == null)
        {
            throw new NullPointerException("version cannot be null");
        }

        try
        {
            return AccessController.doPrivileged(new PrivilegedAction<File>()
            {
                @Override
                public File run()
                {
                    File prefix = new File(new File(prefixPath), version);

                    if (prefix.isFile())
                    {
                        throw new IllegalStateException(String.format("'%s' exists and is a file", prefixPath));
                    }

                    if (!prefix.exists())
                    {
                        if (!prefix.mkdirs())
                        {
                            throw new IllegalStateException(String.format("failed to create temporary directory '%s'", prefixPath));
                        }
                    }

                    return prefix;
                }
            });
        }
        catch (IllegalStateException e)
        {
            throw new IOException(e.getMessage(), e);
        }
    }

    static File extractFromClasspath(File tmpDir, String pathInJar, String name, String[] sources)
        throws Exception
    {
        return AccessController.doPrivileged(new PrivilegedAction<File>()
        {
            public File run()
            {
                sources[0] = pathInJar;
                InputStream in = Loader.class.getResourceAsStream(pathInJar);
                if (in == null)
                {
                    return null;
                }
                
                File savedFile = new File(tmpDir, name);

                if (savedFile.exists())
                {
                    if (savedFile.isDirectory())
                    {
                        throw new IllegalStateException("extracted file name '" + savedFile.getAbsolutePath() + "' is actually a directory and already exists");
                    }

                    //
                    // Compare content
                    //
                    try (FileInputStream fin = new FileInputStream(savedFile))
                    {
                        if (isContentSame(fin, in))
                        {
                            sources[1] = savedFile.getAbsolutePath();
                            return savedFile;
                        }

                        throw new IllegalStateException("existing file name '" + savedFile.getAbsolutePath() + "' does not match expected file content");
                    }
                    catch (RuntimeException e)
                    {
                        throw e;
                    }
                    catch (Exception ex)
                    {
                        throw new IllegalStateException("unable to read exising extracted library" + savedFile.getAbsolutePath(), ex);
                    }
                }

                try (FileOutputStream fos = new FileOutputStream(savedFile))
                {
                    byte[] buf = new byte[8192];
                    int len;

                    while ((len = in.read(buf)) > -1)
                    {
                        fos.write(buf, 0, len);
                    }
                    fos.flush();
                }
                catch (IOException e)
                {
                    throw new RuntimeException(e);
                }

                return savedFile;
            }
        });
    }

    static List<String> readStreamToLines(InputStream inputStream)
        throws IOException
    {

        if (inputStream == null)
        {
            return null;
        }

        List<String> lines = new ArrayList();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream)))
        {
            String line;
            while ((line = reader.readLine()) != null)
            {
                line = line.trim();
                if (line.startsWith("#") || line.isEmpty())
                {
                    continue;
                }
                lines.add(line);
            }
        }
        return lines;
    }

    private static boolean isContentSame(InputStream left, InputStream right)
    {
        BufferedInputStream binLeft = null;
        BufferedInputStream binRight = null;
        try
        {
            binLeft = new BufferedInputStream(left);
            binRight = new BufferedInputStream(right);
            int vLeft = 0;
            int vRight = 0;
            while (vLeft >= 0)
            {
                vLeft = binLeft.read();
                vRight = binRight.read();

                if (vLeft != vRight)
                {
                    return false;
                }
            }
        }
        catch (Exception ex)
        {
            throw new RuntimeException(ex.getMessage(), ex);
        }
        finally
        {
            // Force  close, ignore any exceptions

            try
            {
                binLeft.close();
            }
            catch (Exception ignored)
            {
            }
            try
            {
                binRight.close();
            }
            catch (Exception ignored)
            {
            }
        }

        return true;
    }

    private static String getPropertyValue(final String propertyName)
    {
        return AccessController.doPrivileged(new PrivilegedAction<String>()
        {
            public String run()
            {
                String v = Security.getProperty(propertyName);
                if (v != null)
                {
                    return v;
                }
                return System.getProperty(propertyName);
            }
        });
    }
}
