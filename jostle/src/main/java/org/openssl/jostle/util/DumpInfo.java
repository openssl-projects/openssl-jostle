/*
 *  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.util;

import org.openssl.jostle.Loader;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.NISelector;

import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.logging.ConsoleHandler;
import java.util.logging.Level;
import java.util.logging.Logger;

public class DumpInfo
{
    public static void main(String[] args) throws Exception
    {
        boolean fine = false;
        boolean services = false;
        for (String arg : args)
        {
            if (arg.equals("--fine"))
            {
                fine = true;
            }
            else if (arg.equals("--services"))
            {
                services = true;
            }
        }

        ConsoleHandler handler = null;
        if (fine)
        {
            handler = new ConsoleHandler();
            handler.setLevel(Level.FINE);
            Logger root = Logger.getLogger("");
            root.addHandler(handler);
            root.setLevel(Level.FINE);
        }

        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }


        // -DM System.out.println
        System.out.println("\n\n-------------------------------------------------------------------------------");
        // -DM System.out.println
        System.out.println("DumpInfo\n\nProvider:");
        // -DM System.out.println
        System.out.println("  Info: " + Security.getProvider(JostleProvider.PROVIDER_NAME).getInfo());
        // -DM System.out.println
        System.out.println("  Name: " + JostleProvider.PROVIDER_NAME);
        // -DM System.out.println
        System.out.println("  OS: " + System.getProperty("os.name"));
        // -DM System.out.println
        System.out.println("  Version: " + System.getProperty("os.version"));
        // -DM System.out.println
        System.out.println("  Arch: " + System.getProperty("os.arch"));
        // -DM System.out.println
        System.out.println("  Java Version: " + System.getProperty("java.version"));
        // -DM System.out.println
        System.out.println("  Java Vendor: " + System.getProperty("java.vendor"));
        // -DM System.out.println
        System.out.println("\nLoader:");
        // -DM System.out.println
        System.out.println("  Load Attempted: " + Loader.isLoadAttempted());
        // -DM System.out.println
        System.out.println("  Load Successful: " + Loader.isLoadSuccessful());
        // -DM System.out.println
        System.out.println("  Loader Message: " + Loader.getMessage());
        // -DM System.out.println
        System.out.println("  Loader Interface Resolution Strategy: " + Loader.getInterfaceResolutionStrategy());
        // -DM System.out.println
        System.out.println("  Loader Interface: " + Loader.getInterfaceTypeName());


        if (Loader.isFixedInstallDir())
        {
            // -DM System.out.println
            System.out.println("  Using Fixed Install Dir: " + Loader.getInstallDir());
        }
        else
        {
            // -DM System.out.println
            System.out.println("  Using Install Dir: " + Loader.getInstallDir());
        }

        // -DM System.out.println
        System.out.println("  Loaded Native Libraries:");
        Loader.getLoadedLibs().forEach(it ->
        {
            // -DM System.out.println
            System.out.println("    " + it);
        });

        // -DM System.out.println
        System.out.println("\nNative Status:");
        // -DM System.out.println
        System.out.println("  Native Available: " + NISelector.NativeServiceNI.isNativeAvailable());
        if (NISelector.NativeServiceNI.isNativeAvailable())
        {
            // -DM System.out.println
            System.out.println("  OpenSSL Version: " + NISelector.NativeServiceNI.getOpenSSLVersion());
        }
        else
        {
            // -DM System.out.println
            System.out.println("  OpenSSL Version: Not available");
        }
        if (services)
        {
            printServices();
        }

        // -DM System.out.println
        System.out.println(".END");
        // -DM System.out.println
        System.out.println("Use: --fine to emit FINE level logs, --services to list provider services grouped by type");

        // -DM System.out.println
        System.out.println("-------------------------------------------------------------------------------");

        if (handler != null)
        {
            handler.flush();
        }


    }

    private static void printServices()
    {
        Provider provider = Security.getProvider(JostleProvider.PROVIDER_NAME);
        Set<Provider.Service> serviceSet = provider.getServices();

        Map<String, List<String>> algorithmsByType = new TreeMap<String, List<String>>();
        for (Provider.Service service : serviceSet)
        {
            List<String> algorithms = algorithmsByType.get(service.getType());
            if (algorithms == null)
            {
                algorithms = new ArrayList<String>();
                algorithmsByType.put(service.getType(), algorithms);
            }
            algorithms.add(service.getAlgorithm());
        }

        // -DM System.out.println
        System.out.println("\nServices (" + serviceSet.size() + " total, grouped by type):");
        for (Map.Entry<String, List<String>> entry : algorithmsByType.entrySet())
        {
            Collections.sort(entry.getValue());
            // -DM System.out.println
            System.out.println("  " + entry.getKey() + " (" + entry.getValue().size() + "):");
            for (String algorithm : entry.getValue())
            {
                // -DM System.out.println
                System.out.println("    " + algorithm);
            }
            // -DM System.out.println
            System.out.println();
        }
    }
}
