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
package org.reaktivity.nukleus.tls.internal.stream;

import static java.lang.System.getProperty;

import java.io.File;
import java.io.FileInputStream;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;
import java.util.function.BiConsumer;
import java.util.function.IntUnaryOperator;
import java.util.function.LongFunction;
import java.util.function.LongSupplier;
import java.util.function.LongUnaryOperator;
import java.util.function.Supplier;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

import org.agrona.DirectBuffer;
import org.agrona.LangUtil;
import org.agrona.MutableDirectBuffer;
import org.agrona.collections.Long2ObjectHashMap;
import org.agrona.collections.MutableInteger;
import org.reaktivity.nukleus.buffer.BufferPool;
import org.reaktivity.nukleus.route.RouteManager;
import org.reaktivity.nukleus.stream.StreamFactory;
import org.reaktivity.nukleus.stream.StreamFactoryBuilder;
import org.reaktivity.nukleus.tls.internal.TlsConfiguration;
import org.reaktivity.nukleus.tls.internal.stream.ServerStreamFactory.ServerHandshake;
import org.reaktivity.nukleus.tls.internal.types.control.RouteFW;
import org.reaktivity.nukleus.tls.internal.types.control.TlsRouteExFW;
import org.reaktivity.nukleus.tls.internal.types.control.UnrouteFW;

public final class ServerStreamFactoryBuilder implements StreamFactoryBuilder
{
    private static final String PROPERTY_TLS_KEYSTORE = "tls.keystore";
    private static final String PROPERTY_TLS_KEYSTORE_PASSWORD = "tls.keystore.password";
    private static final String PROPERTY_TLS_TRUSTSTORE = "tls.truststore";
    private static final String PROPERTY_TLS_TRUSTSTORE_PASSWORD = "tls.truststore.password";

    private static final String DEFAULT_TLS_KEYSTORE = "keys";
    private static final String DEFAULT_TLS_KEYSTORE_PASSWORD = "generated";
    private static final String DEFAULT_TLS_TRUSTSTORE = "trust";
    private static final String DEFAULT_TLS_TRUSTSTORE_PASSWORD = "generated";

    private final UnrouteFW unrouteRO = new UnrouteFW();
    private final RouteFW routeRO = new RouteFW();
    private final TlsRouteExFW tlsRouteExRO = new TlsRouteExFW();

    private final TlsConfiguration config;
    private final BiConsumer<Runnable, Runnable> executeTask;
    private final Map<String, SSLContext> contextsByStore;
    private final Map<String, MutableInteger> routesByStore;
    private final Long2ObjectHashMap<String> storesByRouteId;
    private final Long2ObjectHashMap<ServerHandshake> correlations;

    private RouteManager router;
    private MutableDirectBuffer writeBuffer;
    private LongSupplier supplyInitialId;
    private LongUnaryOperator supplyReplyId;
    private LongSupplier supplyCorrelationId;
    private Supplier<BufferPool> supplyBufferPool;
    private LongSupplier supplyTrace;

    public ServerStreamFactoryBuilder(
        TlsConfiguration config,
        BiConsumer<Runnable, Runnable> executeTask)
    {
        this.config = config;
        this.executeTask = executeTask;
        this.contextsByStore = new HashMap<>();
        this.routesByStore = new HashMap<>();
        this.storesByRouteId = new Long2ObjectHashMap<>();
        this.correlations = new Long2ObjectHashMap<>();
    }

    @Override
    public ServerStreamFactoryBuilder setRouteManager(
        RouteManager router)
    {
        this.router = router;
        return this;
    }

    @Override
    public ServerStreamFactoryBuilder setWriteBuffer(
        MutableDirectBuffer writeBuffer)
    {
        this.writeBuffer = writeBuffer;
        return this;
    }

    @Override
    public StreamFactoryBuilder setTraceSupplier(
            LongSupplier supplyTrace)
    {
        this.supplyTrace = supplyTrace;
        return this;
    }

    @Override
    public ServerStreamFactoryBuilder setInitialIdSupplier(
        LongSupplier supplyInitialId)
    {
        this.supplyInitialId = supplyInitialId;
        return this;
    }

    @Override
    public StreamFactoryBuilder setReplyIdSupplier(
        LongUnaryOperator supplyReplyId)
    {
        this.supplyReplyId = supplyReplyId;
        return this;
    }

    @Override
    public ServerStreamFactoryBuilder setGroupBudgetClaimer(LongFunction<IntUnaryOperator> groupBudgetClaimer)
    {
        return this;
    }

    @Override
    public ServerStreamFactoryBuilder setGroupBudgetReleaser(LongFunction<IntUnaryOperator> groupBudgetReleaser)
    {
        return this;
    }

    @Override
    public ServerStreamFactoryBuilder setTargetCorrelationIdSupplier(
        LongSupplier supplyCorrelationId)
    {
        this.supplyCorrelationId = supplyCorrelationId;
        return this;
    }

    @Override
    public StreamFactoryBuilder setBufferPoolSupplier(
        Supplier<BufferPool> supplyBufferPool)
    {
        this.supplyBufferPool = supplyBufferPool;
        return this;
    }

    public boolean handleRoute(int msgTypeId, DirectBuffer buffer, int index, int length)
    {
        switch(msgTypeId)
        {
            case RouteFW.TYPE_ID:
            {
                final RouteFW route = routeRO.wrap(buffer, index, index + length);
                final TlsRouteExFW routeEx = route.extension().get(tlsRouteExRO::wrap);
                final String store = routeEx.store().asString();
                final long routeId = route.correlationId();
                storesByRouteId.put(routeId, store);
                MutableInteger routesCount = routesByStore.computeIfAbsent(store, s -> new MutableInteger());
                routesCount.value++;
                contextsByStore.computeIfAbsent(store, s -> initContext(config, store));
            }
            break;
            case UnrouteFW.TYPE_ID:
            {
                final UnrouteFW unroute = unrouteRO.wrap(buffer, index, index + length);
                final long routeId = unroute.routeId();
                final String store = storesByRouteId.remove(routeId);
                MutableInteger routesCount = routesByStore.computeIfPresent(store, (s, c) -> decrement(c));
                if (routesCount != null && routesCount.value == 0)
                {
                    routesByStore.remove(store);
                    contextsByStore.remove(store);
                }
            }
            break;
        }
        return true;
    }

    private MutableInteger decrement(MutableInteger routesCount)
    {
        routesCount.value--;
        return routesCount;
    }

    @Override
    public StreamFactory build()
    {
        final BufferPool bufferPool = supplyBufferPool.get();

        return new ServerStreamFactory(
            config,
            executeTask,
            contextsByStore,
            router,
            writeBuffer,
            bufferPool,
            supplyInitialId,
            supplyReplyId,
            supplyCorrelationId,
            correlations,
            supplyTrace);
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
            File keyStoreFile = resolve(directory, store, keyStoreFilename);

            KeyManager[] keyManagers = null;
            if (keyStoreFile.exists())
            {
                KeyStore keyStore = KeyStore.getInstance("JKS");
                keyStore.load(new FileInputStream(keyStoreFile), keyStorePassword.toCharArray());
                KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(
                        tlsConfig.keyManagerAlgorithm());
                keyManagerFactory.init(keyStore, keyStorePassword.toCharArray());
                keyManagers = keyManagerFactory.getKeyManagers();
            }

            String trustStorePassword = getProperty(PROPERTY_TLS_TRUSTSTORE_PASSWORD, DEFAULT_TLS_TRUSTSTORE_PASSWORD);
            String trustStoreFilename = System.getProperty(PROPERTY_TLS_TRUSTSTORE, DEFAULT_TLS_TRUSTSTORE);
            File trustStoreFile = resolve(directory, store, trustStoreFilename);

            TrustManager[] trustManagers = null;
            if (trustStoreFile.exists())
            {
                KeyStore trustStore = KeyStore.getInstance("JKS");
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
