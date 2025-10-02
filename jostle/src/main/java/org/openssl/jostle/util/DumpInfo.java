/*
 *  Copyright 2005-2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://www.openssl.org/source/license.html
 *
 */

package org.openssl.jostle.util;

import org.openssl.jostle.Loader;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.NISelector;

import java.security.Security;
import java.util.logging.ConsoleHandler;
import java.util.logging.Level;
import java.util.logging.Logger;

public class DumpInfo
{
    public static void main(String[] args) throws Exception
    {
        ConsoleHandler handler = null;
        if (args.length > 0)
        {
            if (args[0].equals("-fine"))
            {
                handler = new ConsoleHandler();
                handler.setLevel(Level.FINE);
                Logger root = Logger.getLogger("");
                root.addHandler(handler);
                root.setLevel(Level.FINE);
            }
        }

        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }


        System.out.println("\n\n-------------------------------------------------------------------------------");
        System.out.println("DumpInfo\n\nProvider:");
        System.out.println("  Info: " + Security.getProvider(JostleProvider.PROVIDER_NAME).getInfo());
        System.out.println("  Name: " + JostleProvider.PROVIDER_NAME);
        System.out.println("  OS: " + System.getProperty("os.name"));
        System.out.println("  Version: " + System.getProperty("os.version"));
        System.out.println("  Arch: " + System.getProperty("os.arch"));
        System.out.println("  Java Version: " + System.getProperty("java.version"));
        System.out.println("  Java Vendor: " + System.getProperty("java.vendor"));
        System.out.println("\nLoader:");
        System.out.println("  Load Attempted: " + Loader.isLoadAttempted());
        System.out.println("  Load Successful: " + Loader.isLoadSuccessful());
        System.out.println("  Loader Message: " + Loader.getMessage());
        System.out.println("  Loader Interface Resolution Strategy: " + Loader.getInterfaceResolutionStrategy());
        System.out.println("  Loader Interface: " + Loader.getInterfaceTypeName());
        System.out.println("  Loaded Native Libraries:");
        Loader.getLoadedLibs().forEach(it -> {
            System.out.println("    " + it);
        });


        System.out.println("\nNative Status:");
        System.out.println("  Native Available: " + NISelector.NativeServiceNI.isNativeAvailable());
        if (NISelector.NativeServiceNI.isNativeAvailable())
        {
            System.out.println("  OpenSSL Version: " + NISelector.NativeServiceNI.getOpenSSLVersion());
        } else
        {
            System.out.println("  OpenSSL Version: Not available");
        }
        System.out.println(".END");

        System.out.println("Use: -fine to emit FINE level logs");

        System.out.println("-------------------------------------------------------------------------------");

        if (handler != null) {
            handler.flush();
        }


    }
}
