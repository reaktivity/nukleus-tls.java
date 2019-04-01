/**
 * Copyright 2016-2019 The Reaktivity Project
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

import java.util.function.Function;
import java.util.function.IntUnaryOperator;
import java.util.function.LongConsumer;
import java.util.function.LongFunction;
import java.util.function.LongSupplier;
import java.util.function.LongUnaryOperator;
import java.util.function.Supplier;

import org.agrona.MutableDirectBuffer;
import org.agrona.collections.Long2ObjectHashMap;
import org.reaktivity.nukleus.buffer.BufferPool;
import org.reaktivity.nukleus.function.SignalingExecutor;
import org.reaktivity.nukleus.route.RouteManager;
import org.reaktivity.nukleus.stream.StreamFactory;
import org.reaktivity.nukleus.stream.StreamFactoryBuilder;
import org.reaktivity.nukleus.tls.internal.StoreInfo;
import org.reaktivity.nukleus.tls.internal.TlsConfiguration;
import org.reaktivity.nukleus.tls.internal.TlsCounters;
import org.reaktivity.nukleus.tls.internal.stream.ServerStreamFactory.ServerHandshake;

public final class ServerStreamFactoryBuilder implements StreamFactoryBuilder
{
    private final TlsConfiguration config;
    private final Function<String, StoreInfo> lookupStoreInfo;
    private final Long2ObjectHashMap<ServerHandshake> correlations;

    private RouteManager router;
    private SignalingExecutor executor;
    private MutableDirectBuffer writeBuffer;
    private LongUnaryOperator supplyInitialId;
    private LongUnaryOperator supplyReplyId;
    private Supplier<BufferPool> supplyBufferPool;
    private LongSupplier supplyTrace;
    private Function<String, LongSupplier> supplyCounter;
    private Function<String, LongConsumer> supplyAccumulator;

    public ServerStreamFactoryBuilder(
        TlsConfiguration config,
        Function<String, StoreInfo> lookupStoreInfo)
    {
        this.config = config;
        this.lookupStoreInfo = lookupStoreInfo;
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
    public ServerStreamFactoryBuilder setExecutor(
        SignalingExecutor executor)
    {
        this.executor = executor;
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
        LongUnaryOperator supplyInitialId)
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
    public StreamFactoryBuilder setBufferPoolSupplier(
        Supplier<BufferPool> supplyBufferPool)
    {
        this.supplyBufferPool = supplyBufferPool;
        return this;
    }

    @Override
    public StreamFactory build()
    {
        final BufferPool bufferPool = supplyBufferPool.get();
        final TlsCounters counters = new TlsCounters(supplyCounter, supplyAccumulator);

        return new ServerStreamFactory(
            config,
            executor,
            router,
            writeBuffer,
            bufferPool,
            supplyInitialId,
            supplyReplyId,
            correlations,
            supplyTrace,
            lookupStoreInfo,
            counters);
    }
}
