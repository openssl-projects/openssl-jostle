/*
 *  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider;

import java.lang.ref.WeakReference;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.util.*;

import org.openssl.jostle.CryptoServicesRegistrar;
import org.openssl.jostle.util.AccessSupplier;
import org.openssl.jostle.util.AccessWrapper;
import org.openssl.jostle.util.Properties;

public class JostleProvider
        extends Provider
{
    public static final String PROVIDER_NAME = "JSL";
    public static final String INFO = "Jostle Provider for OpenSSL v1.0.0-SNAPSHOT";
    private static final double VERSION = 0.1;

    /**
     * Set the OpenSSL provider name to load.
     */
    public static final String OPENSSL_PROVIDER_NAME = "org.openssl.jostle.ossl_prov";

    private Map<String, BcService> serviceMap = new HashMap<String, BcService>();
    private Map<String, EngineCreator> creatorMap = new HashMap<String, EngineCreator>();

    private WeakReference<Set<Service>> serviceSetCache = new WeakReference<Set<Service>>(null);

    public JostleProvider()
    {
        this(null);
    }

    public JostleProvider(String config)
    {
        super(PROVIDER_NAME, VERSION, INFO);

        synchronized (JostleProvider.class)
        {
            //
            // Will trigger loading of native libraries
            //
            CryptoServicesRegistrar.assertNativeAvailable();

            String nonDefaultOsslProvider = Properties.getPropertyValue(OPENSSL_PROVIDER_NAME, null);
            if (nonDefaultOsslProvider != null)
            {
                // Will throw if there is an issue, this will break the loader
                OpenSSL.setOSSLProvider(nonDefaultOsslProvider);
            }
        }

        AccessWrapper.doAction(new AccessSupplier()
        {
            @Override
            public Object run()
            {
                setup();
                return null;
            }
        });
    }

    private void setup()
    {
        new ProvAES().configure(this);
        new ProvCAMELLIA().configure(this);
        new ProvARIA().configure(this);
        new ProvSM4().configure(this);
        new ProvMLDSA().configure(this);
        new ProvSLHDSA().configure(this);
        new ProvMLKEM().configure(this);
    }

    void addAttribute(String type, String name, String attributeName, String attributeValue)
    {
        String key = type + "." + name;
        String attributeKey = key + " " + attributeName;
        if (containsKey(attributeKey))
        {
            throw new IllegalStateException("duplicate provider attribute key (" + attributeKey + ") found");
        }

        put(attributeKey, attributeValue);
    }

    void addAttribute(String type, ASN1ObjectIdentifier name, String attributeName, String attributeValue)
    {
        String key = type + "." + name;
        String attributeKey = key + " " + attributeName;
        if (containsKey(attributeKey))
        {
            throw new IllegalStateException("duplicate provider attribute key (" + attributeKey + ") found");
        }

        put(attributeKey, attributeValue);
    }

    void addAttributes(String type, String name, Map<String, String> attributes)
    {
        for (Map.Entry<String, String> attrEntry : attributes.entrySet())
        {
            addAttribute(type, name, attrEntry.getKey(), attrEntry.getValue());
        }
    }

    void addAttributes(String type, ASN1ObjectIdentifier name, Map<String, String> attributes)
    {
        for (Map.Entry<String, String> attrEntry : attributes.entrySet())
        {
            addAttribute(type, name, attrEntry.getKey(), attrEntry.getValue());
        }
    }

    public void addAlgorithmImplementation(String type, String name, String className, Map<String, String> attributes, EngineCreator creator)
    {
        String key1 = type + "." + name;
        if (containsKey(key1))
        {
            throw new IllegalStateException("duplicate provider key (" + key1 + ") found");
        }

        addAttributes(type, name, attributes);
        addAttribute(type, name, "ImplementedIn", "Software");

        put(key1, className);
        if (creatorMap.containsKey(className))
        {
            throw new IllegalStateException("duplicate creatorMap key (" + className + ") found");
        }
        creatorMap.put(className, creator);
    }

    void addAlgorithmImplementation(String type, ASN1ObjectIdentifier name, String className, Map<String, String> attributes, EngineCreator creator)
    {
        String key1 = type + "." + name;
        if (containsKey(key1))
        {
            throw new IllegalStateException("duplicate provider key (" + key1 + ") found");
        }

        addAttributes(type, name, attributes);
        addAttribute(type, name, "ImplementedIn", "Software");

        put(key1, className);
        if (creatorMap.containsKey(className))
        {
            throw new IllegalStateException("duplicate creatorMap key (" + className + ") found");
        }
        creatorMap.put(className, creator);

        doPut("Alg.Alias." + type + ".OID." + name, name.getId());
    }

    void addAlias(String key, String value)
    {
        if (containsKey(key))
        {
            throw new IllegalStateException("duplicate provider key (" + key + ") found");
        }

        put(key, value);
    }

    void addAlias(String type, String name, String... aliases)
    {
        if (!containsKey(type + "." + name))
        {
            throw new IllegalStateException("primary key (" + type + "." + name + ") not found");
        }

        for (String alias : aliases)
        {
            doPut("Alg.Alias." + type + "." + alias, name);
        }
    }

    void addAlias(String type, String name, ASN1ObjectIdentifier... oids)
    {
        if (!containsKey(type + "." + name))
        {
            throw new IllegalStateException("primary key (" + type + "." + name + ") not found");
        }

        for (ASN1ObjectIdentifier oid : oids)
        {
            doPut("Alg.Alias." + type + "." + oid, name);
            doPut("Alg.Alias." + type + ".OID." + oid, name);
        }
    }

    private void doPut(String key, String name)
    {
        if (containsKey(key))
        {
            throw new IllegalStateException("duplicate provider key (" + key + ") found");
        }

        put(key, name);
    }

    public synchronized final Service getService(String type, String algorithm)
    {
        String upperCaseAlgName = algorithm.toUpperCase(Locale.ROOT);

        BcService service = serviceMap.get(type + "." + upperCaseAlgName);

        if (service == null)
        {
            String aliasString = "Alg.Alias." + type + ".";
            String realName = (String) this.get(aliasString + upperCaseAlgName);

            if (realName == null)
            {
                realName = upperCaseAlgName;
            }

            String className = (String) this.get(type + "." + realName);

            if (className == null)
            {
                return null;
            }

            String attributeKeyStart = type + "." + upperCaseAlgName + " ";

            List<String> aliases = new ArrayList<String>();
            Map<String, String> attributes = new HashMap<String, String>();

            for (Map.Entry<Object, Object> entry : this.entrySet())
            {
                String sKey = (String) entry.getKey();
                if (sKey.startsWith(aliasString))
                {
                    if (entry.getValue().equals(algorithm))
                    {
                        aliases.add(sKey.substring(aliasString.length()));
                    }
                }
                if (sKey.startsWith(attributeKeyStart))
                {
                    attributes.put(sKey.substring(attributeKeyStart.length()), (String) entry.getValue());
                }
            }

            service = new BcService(this, type, upperCaseAlgName, className, aliases, getAttributeMap(attributes), creatorMap.get(className));

            serviceMap.put(type + "." + upperCaseAlgName, service);
        }

        return service;
    }

    public synchronized final Set<Service> getServices()
    {
        Set<Service> bcServiceSet = serviceSetCache.get();

        if (bcServiceSet == null)
        {
            Set<Service> serviceSet = super.getServices();

            bcServiceSet = new LinkedHashSet<Service>();

            bcServiceSet.add(getService("SecureRandom", "DEFAULT"));
            bcServiceSet.add(getService("SecureRandom", "NONCEANDIV"));

            for (Service service : serviceSet)
            {
                Service serv = getService(service.getType(), service.getAlgorithm());
                if (serv != null)
                {
                    bcServiceSet.add(serv);
                }
            }

            bcServiceSet = Collections.unmodifiableSet(bcServiceSet);

            serviceSetCache = new WeakReference<Set<Service>>(bcServiceSet);
        }

        return bcServiceSet;
    }

    private final Map<Map<String, String>, Map<String, String>> attributeMaps = new HashMap<Map<String, String>, Map<String, String>>();

    private Map<String, String> getAttributeMap(Map<String, String> attributeMap)
    {
        Map<String, String> attrMap = attributeMaps.get(attributeMap);
        if (attrMap != null)
        {
            return attrMap;
        }

        attributeMaps.put(attributeMap, attributeMap);

        return attributeMap;
    }

    private static class BcService
            extends Service
    {
        private final EngineCreator creator;

        /**
         * Construct a new service.
         *
         * @param provider   the provider that offers this service
         * @param type       the type of this service
         * @param algorithm  the algorithm name
         * @param className  the name of the class implementing this service
         * @param aliases    List of aliases or null if algorithm has no aliases
         * @param attributes Map of attributes or null if this implementation
         *                   has no attributes
         * @throws NullPointerException if provider, type, algorithm, or
         *                              className is null
         */
        public BcService(Provider provider, String type, String algorithm, String className, List<String> aliases, Map<String, String> attributes, EngineCreator creator)
        {
            super(provider, type, algorithm, className, aliases, attributes);
            this.creator = creator;
        }

        public Object newInstance(Object constructorParameter)
                throws NoSuchAlgorithmException
        {
            try
            {
                Object instance = creator.createInstance(constructorParameter);

                if (instance == null)
                {
                    throw new NoSuchAlgorithmException("No such algorithm in FIPS approved mode: " + getAlgorithm());
                }

                return instance;
            } catch (NoSuchAlgorithmException e)
            {
                throw e;
            } catch (Exception e)
            {
                throw new NoSuchAlgorithmException("Unable to invoke creator for " + getAlgorithm() + ": " + e.getMessage(), e);
            }
        }
    }

    public void addAlgorithm(String key, String value)
    {
        if (containsKey(key))
        {
            throw new IllegalStateException("duplicate provider key (" + key + ") found");
        }

        put(key, value);
    }

    public void addAttributes(String key, Map<String, String> attributeMap)
    {
        put(key + " ImplementedIn", "Software");

        for (Iterator it = attributeMap.keySet().iterator(); it.hasNext();)
        {
            String attributeName = (String)it.next();
            String attributeKey = key + " " + attributeName;
            if (containsKey(attributeKey))
            {
                throw new IllegalStateException("duplicate provider attribute key (" + attributeKey + ") found");
            }

            put(attributeKey, attributeMap.get(attributeName));
        }
    }




}
