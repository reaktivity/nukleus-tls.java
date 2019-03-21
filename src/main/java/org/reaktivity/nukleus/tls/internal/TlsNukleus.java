/**
 * Copyright 2016-2018 The Reaktivity Project
 *
 * The Reaktivity Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package org.reaktivity.nukleus.tls.internal;

import static java.lang.System.getProperty;
import static org.reaktivity.nukleus.route.RouteKind.CLIENT;
import static org.reaktivity.nukleus.route.RouteKind.SERVER;

import java.io.File;
import java.io.FileInputStream;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.Map;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

import org.agrona.DirectBuffer;
import org.agrona.LangUtil;
import org.agrona.collections.Long2ObjectHashMap;
import org.agrona.collections.MutableInteger;
import org.reaktivity.nukleus.Nukleus;
import org.reaktivity.nukleus.function.MessagePredicate;
import org.reaktivity.nukleus.internal.CopyOnWriteHashMap;
import org.reaktivity.nukleus.route.RouteKind;
import org.reaktivity.nukleus.tls.internal.types.control.RouteFW;
import org.reaktivity.nukleus.tls.internal.types.control.TlsRouteExFW;
import org.reaktivity.nukleus.tls.internal.types.control.UnrouteFW;

final class TlsNukleus implements Nukleus
{
    static final String NAME = "tls";

    private static final String PROPERTY_TLS_KEYSTORE = "tls.keystore";
    private static final String PROPERTY_TLS_KEYSTORE_TYPE = "tls.keystore.type";
    private static final String PROPERTY_TLS_KEYSTORE_PASSWORD = "tls.keystore.password";
    private static final String PROPERTY_TLS_TRUSTSTORE = "tls.truststore";
    private static final String PROPERTY_TLS_TRUSTSTORE_TYPE = "tls.truststore.type";
    private static final String PROPERTY_TLS_TRUSTSTORE_PASSWORD = "tls.truststore.password";

    private static final String DEFAULT_TLS_KEYSTORE = "keys";
    private static final String DEFAULT_TLS_KEYSTORE_TYPE = "JKS";
    private static final String DEFAULT_TLS_KEYSTORE_PASSWORD = "generated";
    private static final String DEFAULT_TLS_TRUSTSTORE = "trust";
    private static final String DEFAULT_TLS_TRUSTSTORE_TYPE = "JKS";
    private static final String DEFAULT_TLS_TRUSTSTORE_PASSWORD = "generated";

    private final UnrouteFW unrouteRO = new UnrouteFW();
    private final RouteFW routeRO = new RouteFW();
    private final TlsRouteExFW tlsRouteExRO = new TlsRouteExFW();

    private final TlsConfiguration config;
    private final Map<RouteKind, MessagePredicate> routeHandlers;
    private final Map<String, MutableInteger> routesByStore;
    private final Long2ObjectHashMap<String> storesByRouteId;
    private final Map<String, SSLContext> contextsByStore;

    TlsNukleus(
        TlsConfiguration config)
    {
        this.config = config;

        this.routesByStore = new HashMap<>();
        this.storesByRouteId = new Long2ObjectHashMap<>();
        this.contextsByStore = new CopyOnWriteHashMap<>();

        Map<RouteKind, MessagePredicate> routeHandlers = new EnumMap<>(RouteKind.class);
        routeHandlers.put(SERVER, this::handleRoute);
        routeHandlers.put(CLIENT, this::handleRoute);
        this.routeHandlers = routeHandlers;
    }

    @Override
    public String name()
    {
        return TlsNukleus.NAME;
    }

    @Override
    public TlsConfiguration config()
    {
        return config;
    }

    @Override
    public MessagePredicate routeHandler(
        RouteKind kind)
    {
        return routeHandlers.get(kind);
    }

    @Override
    public TlsElektron supplyElektron()
    {
        return new TlsElektron(config, contextsByStore::get);
    }

    private boolean handleRoute(
        int msgTypeId,
        DirectBuffer buffer,
        int index,
        int length)
    {
        switch(msgTypeId)
        {
            case RouteFW.TYPE_ID:
            {
                final RouteFW route = routeRO.wrap(buffer, index, index + length);
                handleRoute(route);
            }
            break;
            case UnrouteFW.TYPE_ID:
            {
                final UnrouteFW unroute = unrouteRO.wrap(buffer, index, index + length);
                handleUnroute(unroute);
            }
            break;
        }
        return true;
    }

    private void handleRoute(
        final RouteFW route)
    {
        final TlsRouteExFW routeEx = route.extension().get(tlsRouteExRO::wrap);
        final String store = routeEx.store().asString();
        final long routeId = route.correlationId();

        if (store != null)
        {
            storesByRouteId.put(routeId, store);
        }
        MutableInteger routesCount = routesByStore.computeIfAbsent(store, s -> new MutableInteger());
        routesCount.value++;
        contextsByStore.computeIfAbsent(store, s -> initContext(config, store));
    }

    private void handleUnroute(
        final UnrouteFW unroute)
    {
        final long routeId = unroute.routeId();
        final String store = storesByRouteId.remove(routeId);

        MutableInteger routesCount = routesByStore.computeIfPresent(store, (s, c) -> decrement(c));
        if (routesCount != null && routesCount.value == 0)
        {
            routesByStore.remove(store);
            contextsByStore.remove(store);
        }
    }

    private MutableInteger decrement(MutableInteger routesCount)
    {
        routesCount.value--;
        return routesCount;
    }

    static SSLContext initContext(
        TlsConfiguration tlsConfig,
        String store)
    {
        Path directory = tlsConfig.directory();
        SSLContext context = null;

        try
        {
            String keyStorePassword = getProperty(PROPERTY_TLS_KEYSTORE_PASSWORD, DEFAULT_TLS_KEYSTORE_PASSWORD);
            String keyStoreFilename = getProperty(PROPERTY_TLS_KEYSTORE, DEFAULT_TLS_KEYSTORE);
            String keyStoreType = getProperty(PROPERTY_TLS_KEYSTORE_TYPE, DEFAULT_TLS_KEYSTORE_TYPE);
            File keyStoreFile = resolve(directory, store, keyStoreFilename);

            KeyManager[] keyManagers = null;
            if (keyStoreFile.exists())
            {
                KeyStore keyStore = KeyStore.getInstance(keyStoreType);
                keyStore.load(new FileInputStream(keyStoreFile), keyStorePassword.toCharArray());
                KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(
                        tlsConfig.keyManagerAlgorithm());
                keyManagerFactory.init(keyStore, keyStorePassword.toCharArray());
                keyManagers = keyManagerFactory.getKeyManagers();
            }

            String trustStorePassword = getProperty(PROPERTY_TLS_TRUSTSTORE_PASSWORD, DEFAULT_TLS_TRUSTSTORE_PASSWORD);
            String trustStoreFilename = System.getProperty(PROPERTY_TLS_TRUSTSTORE, DEFAULT_TLS_TRUSTSTORE);
            String trustStoreType = System.getProperty(PROPERTY_TLS_TRUSTSTORE_TYPE, DEFAULT_TLS_TRUSTSTORE_TYPE);
            File trustStoreFile = resolve(directory, store, trustStoreFilename);

            TrustManager[] trustManagers = null;
            if (trustStoreFile.exists())
            {
                KeyStore trustStore = KeyStore.getInstance(trustStoreType);
                trustStore.load(new FileInputStream(trustStoreFile), trustStorePassword.toCharArray());
                // TODO: TLS Alert Record, code 112 / scope trustStore to match routes?
                TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(
                        TrustManagerFactory.getDefaultAlgorithm());
                trustManagerFactory.init(trustStore);
                trustManagers = trustManagerFactory.getTrustManagers();
            }

            context = SSLContext.getInstance("TLS");
            context.init(keyManagers, trustManagers, new SecureRandom());
        }
        catch (Exception ex)
        {
            LangUtil.rethrowUnchecked(ex);
        }

        return context;
    }

    private static File resolve(
        Path directory,
        String store,
        String storeFilename)
    {
        return store == null
                ? directory.resolve("tls").resolve(storeFilename).toFile()
                : directory.resolve("tls").resolve("stores").resolve(store).resolve(storeFilename).toFile();
    }
}
