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

import static org.reaktivity.nukleus.tls.internal.stream.ServerStreamFactoryBuilder.initContext;

import java.util.HashMap;
import java.util.Map;
import java.util.function.BiConsumer;
import java.util.function.Function;
import java.util.function.IntUnaryOperator;
import java.util.function.LongConsumer;
import java.util.function.LongFunction;
import java.util.function.LongSupplier;
import java.util.function.LongUnaryOperator;
import java.util.function.Supplier;

import javax.net.ssl.SSLContext;

import org.agrona.DirectBuffer;
import org.agrona.MutableDirectBuffer;
import org.agrona.collections.Long2ObjectHashMap;
import org.agrona.collections.MutableInteger;
import org.reaktivity.nukleus.buffer.BufferPool;
import org.reaktivity.nukleus.route.RouteManager;
import org.reaktivity.nukleus.stream.StreamFactory;
import org.reaktivity.nukleus.stream.StreamFactoryBuilder;
import org.reaktivity.nukleus.tls.internal.TlsConfiguration;
import org.reaktivity.nukleus.tls.internal.TlsCounters;
import org.reaktivity.nukleus.tls.internal.types.control.RouteFW;
import org.reaktivity.nukleus.tls.internal.types.control.TlsRouteExFW;
import org.reaktivity.nukleus.tls.internal.types.control.UnrouteFW;

public final class ClientStreamFactoryBuilder implements StreamFactoryBuilder
{
    private final RouteFW routeRO = new RouteFW();
    private final UnrouteFW unrouteRO = new UnrouteFW();
    private final TlsRouteExFW tlsRouteExRO = new TlsRouteExFW();

    private final TlsConfiguration config;
    private final BiConsumer<Runnable, Runnable> executeTask;
    private final Map<String, SSLContext> contextsByStore;
    private final Map<String, MutableInteger> routesByStore;
    private final Long2ObjectHashMap<String> storesByRouteId;
    private final Long2ObjectHashMap<ClientStreamFactory.ClientHandshake> correlations;

    private RouteManager router;
    private MutableDirectBuffer writeBuffer;
    private LongSupplier supplyInitialId;
    private LongUnaryOperator supplyReplyId;
    private LongSupplier supplyCorrelationId;
    private LongSupplier supplyTrace;
    private Supplier<BufferPool> supplyBufferPool;
    private Function<String, LongSupplier> supplyCounter;
    private Function<String, LongConsumer> supplyAccumulator;

    public ClientStreamFactoryBuilder(
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
    public ClientStreamFactoryBuilder setRouteManager(
        RouteManager router)
    {
        this.router = router;
        return this;
    }

    @Override
    public ClientStreamFactoryBuilder setWriteBuffer(
        MutableDirectBuffer writeBuffer)
    {
        this.writeBuffer = writeBuffer;
        return this;
    }

    @Override
    public ClientStreamFactoryBuilder setInitialIdSupplier(
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
    public StreamFactoryBuilder setTraceSupplier(
            LongSupplier supplyTrace)
    {
        this.supplyTrace = supplyTrace;
        return this;
    }

    @Override
    public ClientStreamFactoryBuilder setGroupBudgetClaimer(
        LongFunction<IntUnaryOperator> groupBudgetClaimer)
    {
        return this;
    }

    @Override
    public ClientStreamFactoryBuilder setGroupBudgetReleaser(
        LongFunction<IntUnaryOperator> groupBudgetReleaser)
    {
        return this;
    }

    @Override
    public ClientStreamFactoryBuilder setTargetCorrelationIdSupplier(
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

    @Override
    public StreamFactoryBuilder setCounterSupplier(
            Function<String, LongSupplier> supplyCounter)
    {
        this.supplyCounter = supplyCounter;
        return this;
    }

    @Override
    public StreamFactoryBuilder setAccumulatorSupplier(
            Function<String, LongConsumer> supplyAccumulator)
    {
        this.supplyAccumulator = supplyAccumulator;
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

                if (store != null)
                {
                    storesByRouteId.put(routeId, store);
                }

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
        final TlsCounters counters = new TlsCounters(supplyCounter, supplyAccumulator);

        return new ClientStreamFactory(
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
            supplyTrace,
            counters);
    }
}
