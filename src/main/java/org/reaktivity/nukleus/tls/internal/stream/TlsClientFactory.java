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

import static java.util.Arrays.asList;
import static java.util.Objects.requireNonNull;
import static java.util.Optional.ofNullable;
import static org.reaktivity.nukleus.buffer.BufferPool.NO_SLOT;
import static org.reaktivity.nukleus.concurrent.Signaler.NO_CANCEL_ID;

import java.nio.ByteBuffer;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.LongUnaryOperator;
import java.util.function.ToIntFunction;

import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;

import org.agrona.DirectBuffer;
import org.agrona.MutableDirectBuffer;
import org.agrona.collections.Long2ObjectHashMap;
import org.agrona.concurrent.UnsafeBuffer;
import org.reaktivity.nukleus.buffer.BufferPool;
import org.reaktivity.nukleus.buffer.CountingBufferPool;
import org.reaktivity.nukleus.concurrent.Signaler;
import org.reaktivity.nukleus.function.MessageConsumer;
import org.reaktivity.nukleus.function.MessageFunction;
import org.reaktivity.nukleus.function.MessagePredicate;
import org.reaktivity.nukleus.route.RouteManager;
import org.reaktivity.nukleus.stream.StreamFactory;
import org.reaktivity.nukleus.tls.internal.TlsConfiguration;
import org.reaktivity.nukleus.tls.internal.TlsCounters;
import org.reaktivity.nukleus.tls.internal.TlsNukleus;
import org.reaktivity.nukleus.tls.internal.TlsStoreInfo;
import org.reaktivity.nukleus.tls.internal.types.OctetsFW;
import org.reaktivity.nukleus.tls.internal.types.OctetsFW.Builder;
import org.reaktivity.nukleus.tls.internal.types.codec.TlsRecordInfoFW;
import org.reaktivity.nukleus.tls.internal.types.codec.TlsUnwrappedDataFW;
import org.reaktivity.nukleus.tls.internal.types.codec.TlsUnwrappedInfoFW;
import org.reaktivity.nukleus.tls.internal.types.control.RouteFW;
import org.reaktivity.nukleus.tls.internal.types.control.TlsRouteExFW;
import org.reaktivity.nukleus.tls.internal.types.stream.AbortFW;
import org.reaktivity.nukleus.tls.internal.types.stream.BeginFW;
import org.reaktivity.nukleus.tls.internal.types.stream.DataFW;
import org.reaktivity.nukleus.tls.internal.types.stream.EndFW;
import org.reaktivity.nukleus.tls.internal.types.stream.ExtensionFW;
import org.reaktivity.nukleus.tls.internal.types.stream.ResetFW;
import org.reaktivity.nukleus.tls.internal.types.stream.SignalFW;
import org.reaktivity.nukleus.tls.internal.types.stream.TlsBeginExFW;
import org.reaktivity.nukleus.tls.internal.types.stream.WindowFW;

public final class TlsClientFactory implements StreamFactory
{
    private static final OctetsFW EMPTY_OCTETS = new OctetsFW().wrap(new UnsafeBuffer(new byte[0]), 0, 0);
    private static final Consumer<OctetsFW.Builder> EMPTY_EXTENSION = ex -> {};
    private static final int MAXIMUM_HEADER_SIZE = 5 + 20 + 256;    // TODO version + MAC + padding
    private static final int HANDSHAKE_TASK_COMPLETE_SIGNAL = 1;
    private static final MutableDirectBuffer EMPTY_MUTABLE_DIRECT_BUFFER = new UnsafeBuffer(new byte[0]);

    private static final Optional<TlsStream> NULL_STREAM = ofNullable(null);

    private final ThreadLocal<RouteFW> routeRO = ThreadLocal.withInitial(RouteFW::new);
    private final ThreadLocal<TlsRouteExFW> tlsRouteExRO = ThreadLocal.withInitial(TlsRouteExFW::new);

    private final BeginFW beginRO = new BeginFW();
    private final DataFW dataRO = new DataFW();
    private final EndFW endRO = new EndFW();
    private final AbortFW abortRO = new AbortFW();
    private final SignalFW signalRO = new SignalFW();
    private final ExtensionFW extensionRO = new ExtensionFW();

    private final BeginFW.Builder beginRW = new BeginFW.Builder();
    private final DataFW.Builder dataRW = new DataFW.Builder();
    private final EndFW.Builder endRW = new EndFW.Builder();
    private final AbortFW.Builder abortRW = new AbortFW.Builder();

    private final WindowFW windowRO = new WindowFW();
    private final ResetFW resetRO = new ResetFW();

    private final TlsRecordInfoFW tlsRecordInfoRO = new TlsRecordInfoFW();
    private final TlsUnwrappedInfoFW.Builder tlsUnwrappedInfoRW = new TlsUnwrappedInfoFW.Builder();
    private final TlsUnwrappedDataFW tlsUnwrappedDataRO = new TlsUnwrappedDataFW();
    private final TlsUnwrappedDataFW.Builder tlsUnwrappedDataRW = new TlsUnwrappedDataFW.Builder();

    private final TlsBeginExFW tlsBeginExRO = new TlsBeginExFW();
    private final TlsBeginExFW.Builder tlsBeginExRW = new TlsBeginExFW.Builder();

    private final WindowFW.Builder windowRW = new WindowFW.Builder();
    private final ResetFW.Builder resetRW = new ResetFW.Builder();

    private final TlsClientDecoder decodeHandshake = this::decodeHandshake;
    private final TlsClientDecoder decodeHandshakeFinished = this::decodeHandshakeFinished;
    private final TlsClientDecoder decodeHandshakeNeedTask = this::decodeHandshakeNeedTask;
    private final TlsClientDecoder decodeHandshakeNeedUnwrap = this::decodeHandshakeNeedUnwrap;
    private final TlsClientDecoder decodeHandshakeNeedWrap = this::decodeHandshakeNeedWrap;
    private final TlsClientDecoder decodeNotHandshaking = this::decodeNotHandshaking;
    private final TlsClientDecoder decodeNotHandshakingUnwrapped = this::decodeNotHandshakingUnwrapped;
    private final TlsClientDecoder decodeIgnoreAll = this::decodeIgnoreAll;

    private final MessageFunction<RouteFW> wrapRoute = (t, b, i, l) -> routeRO.get().wrap(b, i, i + l);

    private final int tlsTypeId;
    private final Signaler signaler;
    private final RouteManager router;
    private final MutableDirectBuffer writeBuffer;
    private final BufferPool decodePool;
    private final BufferPool encodePool;
    private final LongUnaryOperator supplyInitialId;
    private final LongUnaryOperator supplyReplyId;
    private final int initialPaddingAdjust;

    private final int decodeBudgetMax;
    private final int handshakeBudgetMax;

    private final Long2ObjectHashMap<TlsStream.TlsClient> correlations;
    private final Function<String, TlsStoreInfo> lookupStore;

    private final ByteBuffer inNetByteBuffer;
    private final MutableDirectBuffer inNetBuffer;
    private final ByteBuffer outNetByteBuffer;
    private final DirectBuffer outNetBuffer;
    private final ByteBuffer inAppByteBuffer;
    private final MutableDirectBuffer inAppBuffer;
    private final ByteBuffer outAppByteBuffer;
    private final DirectBuffer outAppBuffer;

    public TlsClientFactory(
        TlsConfiguration config,
        Signaler signaler,
        RouteManager router,
        MutableDirectBuffer writeBuffer,
        BufferPool bufferPool,
        LongUnaryOperator supplyInitialId,
        LongUnaryOperator supplyReplyId,
        ToIntFunction<String> supplyTypeId,
        Function<String, TlsStoreInfo> lookupStore,
        TlsCounters counters)
    {
        this.tlsTypeId = supplyTypeId.applyAsInt(TlsNukleus.NAME);
        this.signaler = requireNonNull(signaler);
        this.lookupStore = requireNonNull(lookupStore);
        this.router = requireNonNull(router);
        this.writeBuffer = requireNonNull(writeBuffer);
        this.decodePool = new CountingBufferPool(bufferPool, counters.clientDecodeAcquires, counters.clientDecodeReleases);
        this.encodePool = new CountingBufferPool(bufferPool, counters.clientEncodeAcquires, counters.clientEncodeReleases);
        this.supplyInitialId = requireNonNull(supplyInitialId);
        this.supplyReplyId = requireNonNull(supplyReplyId);
        this.correlations = new Long2ObjectHashMap<>();
        this.decodeBudgetMax = decodePool.slotCapacity();
        this.handshakeBudgetMax = Math.min(config.handshakeWindowBytes(), decodeBudgetMax);
        this.initialPaddingAdjust = Math.min(bufferPool.slotCapacity() >> 14, 1) * MAXIMUM_HEADER_SIZE;

        this.inNetByteBuffer = ByteBuffer.allocate(writeBuffer.capacity());
        this.inNetBuffer = new UnsafeBuffer(inNetByteBuffer);
        this.outNetByteBuffer = ByteBuffer.allocate(writeBuffer.capacity());
        this.outNetBuffer = new UnsafeBuffer(outNetByteBuffer);
        this.inAppByteBuffer = ByteBuffer.allocate(writeBuffer.capacity());
        this.inAppBuffer = new UnsafeBuffer(inAppByteBuffer);
        this.outAppByteBuffer = ByteBuffer.allocate(writeBuffer.capacity());
        this.outAppBuffer = new UnsafeBuffer(outAppByteBuffer);
    }

    @Override
    public MessageConsumer newStream(
        int msgTypeId,
        DirectBuffer buffer,
        int index,
        int length,
        MessageConsumer sender)
    {
        final BeginFW begin = beginRO.wrap(buffer, index, index + length);
        final long streamId = begin.streamId();

        MessageConsumer newStream = null;

        if ((streamId & 0x0000_0000_0000_0001L) != 0L)
        {
            newStream = newApplicationStream(begin, sender);
        }
        else
        {
            newStream = newNetworkStream(begin, sender);
        }

        return newStream;
    }

    private MessageConsumer newApplicationStream(
        final BeginFW begin,
        final MessageConsumer application)
    {
        final long routeId = begin.routeId();
        final long authorization = begin.authorization();
        final OctetsFW extension = begin.extension();
        final ExtensionFW beginEx = extensionRO.tryWrap(extension.buffer(), extension.offset(), extension.limit());
        final TlsBeginExFW tlsBeginEx = beginEx != null && beginEx.typeId() == tlsTypeId ?
                tlsBeginExRO.tryWrap(extension.buffer(), extension.offset(), extension.limit()) : null;

        final MessagePredicate filter = (t, b, i, l) ->
        {
            final RouteFW route = wrapRoute.apply(t, b, i, l);
            final TlsRouteExFW tlsRouteExRO = TlsClientFactory.this.tlsRouteExRO.get();
            final TlsRouteExFW routeEx = route.extension().get(tlsRouteExRO::wrap);
            final String hostname = routeEx.hostname().asString();
            final String protocol = routeEx.protocol().asString();
            final String tlsHostname = tlsBeginEx != null ? tlsBeginEx.hostname().asString() : null;
            final String tlsProtocol = tlsBeginEx != null ? tlsBeginEx.protocol().asString() : null;

            return (tlsHostname == null || Objects.equals(tlsHostname, hostname)) &&
                    (protocol == null || Objects.equals(tlsProtocol, protocol));
        };

        final RouteFW route = router.resolve(routeId, authorization, filter, wrapRoute);

        MessageConsumer newStream = null;

        if (route != null)
        {
            final TlsRouteExFW tlsRouteExRO = TlsClientFactory.this.tlsRouteExRO.get();
            final TlsRouteExFW routeEx = route.extension().get(tlsRouteExRO::wrap);
            String store = routeEx.store().asString();

            String tlsHostname = tlsBeginEx != null ? tlsBeginEx.hostname().asString() : null;
            if (tlsHostname == null)
            {
                tlsHostname = routeEx.hostname().asString();
            }

            String tlsProtocol = tlsBeginEx != null ? tlsBeginEx.protocol().asString() : null;
            if (tlsProtocol == null)
            {
                tlsProtocol = routeEx.protocol().asString();
            }

            final long networkRouteId = route.correlationId();

            final long applicationInitialId = begin.streamId();
            final long applicationRouteId = begin.routeId();
            final long applicationAffinity = begin.affinity();

            final TlsStoreInfo storeInfo = lookupStore.apply(store);
            final SSLContext context = storeInfo != null ? storeInfo.context : null;
            if (context != null)
            {
                final SSLEngine tlsEngine = context.createSSLEngine(tlsHostname, -1);
                tlsEngine.setUseClientMode(true);

                final SSLParameters tlsParameters = tlsEngine.getSSLParameters();
                tlsParameters.setEndpointIdentificationAlgorithm("HTTPS");
                if (tlsHostname != null)
                {
                    tlsParameters.setServerNames(asList(new SNIHostName(tlsHostname)));
                }
                if (tlsProtocol != null && !tlsProtocol.isEmpty())
                {
                    tlsParameters.setApplicationProtocols(new String[] { tlsProtocol });
                }
                tlsEngine.setSSLParameters(tlsParameters);

                newStream = new TlsStream(
                    application,
                    applicationRouteId,
                    applicationInitialId,
                    applicationAffinity,
                    tlsEngine,
                    tlsHostname,
                    networkRouteId)::onApplication;
            }
        }

        return newStream;
    }

    private MessageConsumer newNetworkStream(
        final BeginFW begin,
        final MessageConsumer network)
    {
        final long streamId = begin.streamId();

        MessageConsumer newStream = null;

        final TlsStream.TlsClient stream = correlations.remove(streamId);
        if (stream != null)
        {
            newStream = stream::onNetwork;
        }

        return newStream;
    }

    private void doBegin(
        MessageConsumer receiver,
        long routeId,
        long streamId,
        long traceId,
        long authorization,
        long affinity,
        Consumer<OctetsFW.Builder> extension)
    {
        final BeginFW begin = beginRW.wrap(writeBuffer, 0, writeBuffer.capacity())
                .routeId(routeId)
                .streamId(streamId)
                .traceId(traceId)
                .authorization(authorization)
                .affinity(affinity)
                .extension(extension)
                .build();

        receiver.accept(begin.typeId(), begin.buffer(), begin.offset(), begin.sizeof());
    }

    private void doData(
        MessageConsumer receiver,
        long routeId,
        long streamId,
        long traceId,
        long authorization,
        long budgetId,
        int reserved,
        DirectBuffer payload,
        int offset,
        int length,
        Consumer<OctetsFW.Builder> extension)
    {
        final DataFW data = dataRW.wrap(writeBuffer, 0, writeBuffer.capacity())
                .routeId(routeId)
                .streamId(streamId)
                .traceId(traceId)
                .authorization(authorization)
                .budgetId(budgetId)
                .reserved(reserved)
                .payload(payload, offset, length)
                .extension(extension)
                .build();

        receiver.accept(data.typeId(), data.buffer(), data.offset(), data.sizeof());
    }

    private void doEnd(
        MessageConsumer receiver,
        long routeId,
        long streamId,
        long traceId,
        long authorization,
        Consumer<Builder> extension)
    {
        final EndFW end = endRW.wrap(writeBuffer, 0, writeBuffer.capacity())
                               .routeId(routeId)
                               .streamId(streamId)
                               .traceId(traceId)
                               .authorization(authorization)
                               .extension(extension)
                               .build();

        receiver.accept(end.typeId(), end.buffer(), end.offset(), end.sizeof());
    }

    private void doAbort(
        MessageConsumer receiver,
        long routeId,
        long streamId,
        long traceId,
        long authorization,
        Consumer<Builder> extension)
    {
        final AbortFW abort = abortRW.wrap(writeBuffer, 0, writeBuffer.capacity())
                .routeId(routeId)
                .streamId(streamId)
                .traceId(traceId)
                .authorization(authorization)
                .extension(extension)
                .build();

        receiver.accept(abort.typeId(), abort.buffer(), abort.offset(), abort.sizeof());
    }

    private void doWindow(
        MessageConsumer sender,
        long routeId,
        long streamId,
        long traceId,
        long authorization,
        long budgetId,
        int credit,
        int padding)
    {
        final WindowFW window = windowRW.wrap(writeBuffer, 0, writeBuffer.capacity())
                .routeId(routeId)
                .streamId(streamId)
                .traceId(traceId)
                .authorization(authorization)
                .budgetId(budgetId)
                .credit(credit)
                .padding(padding)
                .build();

        sender.accept(window.typeId(), window.buffer(), window.offset(), window.sizeof());
    }

    private void doReset(
        MessageConsumer sender,
        long routeId,
        long streamId,
        long traceId,
        long authorization)
    {
        final ResetFW reset = resetRW.wrap(writeBuffer, 0, writeBuffer.capacity())
               .routeId(routeId)
               .streamId(streamId)
               .traceId(traceId)
               .authorization(authorization)
               .build();

        sender.accept(reset.typeId(), reset.buffer(), reset.offset(), reset.sizeof());
    }

    private int decodeHandshake(
        TlsStream.TlsClient client,
        long traceId,
        long authorization,
        long budgetId,
        int reserved,
        DirectBuffer buffer,
        int offset,
        int progress,
        int limit)
    {
        final SSLEngine tlsEngine = client.tlsEngine;
        switch (tlsEngine.getHandshakeStatus())
        {
        case NOT_HANDSHAKING:
            client.decoder = decodeNotHandshaking;
            break;
        case FINISHED:
            client.decoder = decodeHandshakeFinished;
            break;
        case NEED_TASK:
            client.decoder = decodeHandshakeNeedTask;
            break;
        case NEED_WRAP:
            client.decoder = decodeHandshakeNeedWrap;
            break;
        case NEED_UNWRAP:
            client.decoder = decodeHandshakeNeedUnwrap;
            break;
        case NEED_UNWRAP_AGAIN:
            assert false : "NEED_UNWRAP_AGAIN used by DTLS only";
            break;
        }

        return progress;
    }

    private int decodeNotHandshaking(
        TlsStream.TlsClient client,
        long traceId,
        long authorization,
        long budgetId,
        int reserved,
        MutableDirectBuffer buffer,
        int offset,
        int progress,
        int limit)
    {
        final int length = limit - progress;
        if (length != 0)
        {
            final TlsRecordInfoFW tlsRecordInfo = tlsRecordInfoRO.tryWrap(buffer, progress, limit);
            if (tlsRecordInfo != null)
            {
                final int tlsRecordOffset = tlsRecordInfo.offset();
                final int tlsRecordDataOffset = tlsRecordInfo.limit();
                final int tlsRecordDataLimit = tlsRecordDataOffset + tlsRecordInfo.length();
                if (tlsRecordDataLimit <= limit)
                {
                    inNetByteBuffer.clear();
                    inNetBuffer.putBytes(0, buffer, progress, tlsRecordDataLimit - progress);
                    inNetByteBuffer.limit(tlsRecordDataLimit - progress);
                    outAppByteBuffer.clear();

                    try
                    {
                        final SSLEngineResult result = client.tlsEngine.unwrap(inNetByteBuffer, outAppByteBuffer);
                        final int bytesProduced = result.bytesProduced();
                        final int bytesConsumed = result.bytesConsumed();

                        switch (result.getStatus())
                        {
                        case BUFFER_UNDERFLOW:
                            client.decoder = decodeHandshake;
                            break;
                        case BUFFER_OVERFLOW:
                            assert false;
                            break;
                        case OK:
                            if (result.getHandshakeStatus() == HandshakeStatus.FINISHED)
                            {
                                if (TlsNukleus.DEBUG_HANDSHAKE_FINISHED)
                                {
                                    System.out.format("result = %s, stream = %s\n", result, client.stream);
                                }

                                if (!client.stream.isPresent())
                                {
                                    client.onDecodeHandshakeFinished(traceId, budgetId);
                                }
                            }

                            if (bytesProduced == 0)
                            {
                                client.decoder = decodeHandshake;
                            }
                            else
                            {
                                assert bytesConsumed == tlsRecordDataLimit - tlsRecordOffset;
                                assert bytesProduced <= bytesConsumed : String.format("%d <= %d", bytesProduced, bytesConsumed);

                                tlsUnwrappedDataRW.wrap(buffer, tlsRecordDataOffset, tlsRecordDataLimit)
                                                  .payload(outAppBuffer, 0, bytesProduced)
                                                  .build();

                                client.decoder = decodeNotHandshakingUnwrapped;
                            }
                            break;
                        case CLOSED:
                            assert bytesProduced == 0;
                            client.onDecodeInboundClosed(traceId);
                            client.decoder = decodeHandshake;
                            progress += bytesConsumed;
                            break;
                        }
                    }
                    catch (SSLException ex)
                    {
                        client.cleanupNetwork(traceId);
                        client.decoder = decodeIgnoreAll;
                    }
                }
            }
        }

        return progress;
    }

    private int decodeNotHandshakingUnwrapped(
        TlsStream.TlsClient client,
        long traceId,
        long authorization,
        long budgetId,
        int reserved,
        MutableDirectBuffer buffer,
        int offset,
        int progress,
        int limit)
    {
        final int length = limit - progress;
        if (length != 0)
        {
            final TlsRecordInfoFW tlsRecordInfo = tlsRecordInfoRO.wrap(buffer, progress, limit);
            final int tlsRecordDataOffset = tlsRecordInfo.limit();
            final int tlsRecordDataLimit = tlsRecordDataOffset + tlsRecordInfo.length();

            final TlsUnwrappedDataFW tlsUnwrappedData = tlsUnwrappedDataRO.wrap(buffer, tlsRecordDataOffset, tlsRecordDataLimit);
            final TlsStream stream = client.stream.orElse(null);
            final int replyBudget = stream != null ? stream.replyBudget : 0;
            final int replyPadding = stream != null ? stream.replyPadding : 0;
            assert replyPadding == 0;

            final int bytesOffset = tlsRecordInfo.sizeof();
            final int bytesConsumed = bytesOffset + tlsRecordInfo.length();
            final int bytesProduced = tlsUnwrappedData.length();
            final int bytesReserved = (int)((long) reserved * bytesConsumed / (limit - offset));

            final int bytesPosition = tlsUnwrappedData.info().position();
            final int bytesProgress = bytesOffset + bytesPosition;
            final int bytesLimit = bytesOffset + bytesProduced;

            assert bytesPosition < bytesProduced : String.format("%d < %d", bytesPosition, bytesProduced);
            assert bytesReserved >= bytesOffset : String.format("%d >= %d", bytesReserved, bytesOffset);
            assert bytesReserved >= bytesProduced : String.format("%d >= %d", bytesReserved, bytesProduced);

            final int bytesReservedOffset = bytesPosition != 0 ?
                bytesOffset + (int)((long) (bytesReserved - bytesOffset) * bytesPosition / bytesProduced) : 0;
            final int bytesReservedLimit = bytesReservedOffset + Math.min(bytesReserved - bytesReservedOffset, replyBudget);

            final int maxBytesReserved = bytesReservedLimit - bytesReservedOffset;

            final int maxBytesLimit = bytesOffset + (int)((long) bytesProduced * bytesReservedLimit / bytesReserved);
            final int maxBytesProduced = maxBytesLimit - bytesProgress;

            assert maxBytesReserved >= maxBytesProduced : String.format("%d >= %d", maxBytesReserved, maxBytesProduced);
            assert maxBytesLimit <= bytesLimit : String.format("%d <= %d", maxBytesLimit, bytesLimit);

            if (maxBytesProduced > 0)
            {
                final OctetsFW payload = tlsUnwrappedData.payload();

                client.onDecodeUnwrapped(traceId, authorization, budgetId, maxBytesReserved,
                        payload.buffer(), payload.offset() + bytesPosition, maxBytesProduced);

                final int newBytesPosition = bytesPosition + maxBytesProduced;
                if (newBytesPosition == bytesProduced)
                {
                    progress += bytesConsumed;
                    client.decoder = decodeHandshake;
                }
                else
                {
                    tlsUnwrappedInfoRW.wrap(buffer, tlsRecordDataOffset, tlsRecordDataLimit)
                                      .position(newBytesPosition)
                                      .build();
                }
            }
        }

        return progress;
    }

    private int decodeHandshakeFinished(
        TlsStream.TlsClient client,
        long traceId,
        long authorization,
        long budgetId,
        int reserved,
        DirectBuffer buffer,
        int offset,
        int progress,
        int limit)
    {
        client.onDecodeHandshakeFinished(traceId, authorization);
        client.decoder = decodeHandshake;
        return progress;
    }

    private int decodeHandshakeNeedTask(
        TlsStream.TlsClient client,
        long traceId,
        long authorization,
        long budgetId,
        int reserved,
        DirectBuffer buffer,
        int offset,
        int progress,
        int limit)
    {
        client.onDecodeHandshakeNeedTask(traceId, authorization);
        client.decoder = decodeHandshake;
        return progress;
    }

    private int decodeHandshakeNeedUnwrap(
        TlsStream.TlsClient client,
        long traceId,
        long authorization,
        long budgetId,
        int reserved,
        DirectBuffer buffer,
        int offset,
        int progress,
        int limit)
    {
        final int length = limit - progress;
        if (length != 0)
        {
            inNetByteBuffer.clear();
            inNetBuffer.putBytes(0, buffer, progress, length);
            inNetByteBuffer.limit(length);
            outAppByteBuffer.clear();

            try
            {
                final SSLEngineResult result = client.tlsEngine.unwrap(inNetByteBuffer, outAppByteBuffer);
                final int bytesConsumed = result.bytesConsumed();
                final int bytesProduced = result.bytesProduced();

                switch (result.getStatus())
                {
                case BUFFER_UNDERFLOW:
                    break;
                case BUFFER_OVERFLOW:
                    assert false;
                    break;
                case OK:
                    assert bytesProduced == 0;
                    if (result.getHandshakeStatus() == HandshakeStatus.FINISHED)
                    {
                        client.onDecodeHandshakeFinished(traceId, budgetId);
                    }
                    client.decoder = decodeHandshake;
                    break;
                case CLOSED:
                    assert bytesProduced == 0;
                    client.onDecodeInboundClosed(traceId);
                    client.decoder = decodeIgnoreAll;
                    break;
                }

                progress += bytesConsumed;
            }
            catch (SSLException ex)
            {
                client.cleanupNetwork(traceId);
                client.decoder = decodeIgnoreAll;
            }
        }

        return progress;
    }

    private int decodeHandshakeNeedWrap(
        TlsStream.TlsClient client,
        long traceId,
        long authorization,
        long budgetId,
        int reserved,
        DirectBuffer buffer,
        int offset,
        int progress,
        int limit)
    {
        client.doEncodeWrap(traceId, budgetId, EMPTY_OCTETS);
        client.decoder = decodeHandshake;
        return progress;
    }

    private int decodeIgnoreAll(
        TlsStream.TlsClient client,
        long traceId,
        long authorization,
        long budgetId,
        int reserved,
        DirectBuffer buffer,
        int offset,
        int progress,
        int limit)
    {
        return limit;
    }

    @FunctionalInterface
    private interface TlsClientDecoder
    {
        int decode(
            TlsStream.TlsClient client,
            long traceId,
            long authorization,
            long budgetId,
            int reserved,
            MutableDirectBuffer buffer,
            int offset,
            int progress,
            int limit);
    }

    private final class TlsStream
    {
        private final MessageConsumer application;
        private final long routeId;
        private final long initialId;
        private final long replyId;
        private final long affinity;
        private final TlsClient client;

        private int initialBudget;
        private int replyBudget;
        private int replyPadding;

        private int state;

        private TlsStream(
            MessageConsumer application,
            long routeId,
            long initialId,
            long affinity,
            SSLEngine tlsEngine,
            String tlsHostname,
            long tlsRouteId)
        {
            this.application = application;
            this.routeId = routeId;
            this.initialId = initialId;
            this.replyId = supplyReplyId.applyAsLong(initialId);
            this.affinity = affinity;
            this.client = new TlsClient(tlsEngine, tlsHostname, tlsRouteId);
        }

        private void onApplication(
            int msgTypeId,
            DirectBuffer buffer,
            int index,
            int length)
        {
            switch (msgTypeId)
            {
            case BeginFW.TYPE_ID:
                final BeginFW begin = beginRO.wrap(buffer, index, index + length);
                onApplicationBegin(begin);
                break;
            case DataFW.TYPE_ID:
                final DataFW data = dataRO.wrap(buffer, index, index + length);
                onApplicationData(data);
                break;
            case EndFW.TYPE_ID:
                final EndFW end = endRO.wrap(buffer, index, index + length);
                onApplicationEnd(end);
                break;
            case AbortFW.TYPE_ID:
                final AbortFW abort = abortRO.wrap(buffer, index, index + length);
                onApplicationAbort(abort);
                break;
            case WindowFW.TYPE_ID:
                final WindowFW window = windowRO.wrap(buffer, index, index + length);
                onApplicationWindow(window);
                break;
            case ResetFW.TYPE_ID:
                final ResetFW reset = resetRO.wrap(buffer, index, index + length);
                onApplicationReset(reset);
                break;
            default:
                break;
            }
        }

        private void onApplicationBegin(
            BeginFW begin)
        {
            state = TlsState.openInitial(state);

            final long traceId = begin.traceId();
            final long authorization = begin.authorization();
            final OctetsFW extension = begin.extension();

            client.doNetworkBegin(traceId, authorization, affinity, extension);
        }

        private void onApplicationData(
            DataFW data)
        {
            final long traceId = data.traceId();

            initialBudget -= data.reserved();

            if (initialBudget < 0)
            {
                cleanupApplication(traceId);
                client.doNetworkAbortIfNecessary(traceId);
            }
            else if (data.length() > 0)
            {
                final long budgetId = data.budgetId();
                final OctetsFW payload = data.payload();

                client.doEncodeWrap(traceId, budgetId, payload);
            }
        }

        private void onApplicationEnd(
            EndFW end)
        {
            final long traceId = end.traceId();
            final long budgetId = 0L; // TODO

            state = TlsState.closeInitial(state);
            client.stream = nullIfClosed(state, client.stream);

            client.doEncodeCloseOutbound(traceId, budgetId);
        }

        private void onApplicationAbort(
            AbortFW abort)
        {
            final long traceId = abort.traceId();

            state = TlsState.closeInitial(state);
            client.stream = nullIfClosed(state, client.stream);

            client.doNetworkAbortIfNecessary(traceId);

            doApplicationAbortIfNecessary(traceId);
            client.doNetworkResetIfNecessary(traceId);
        }

        private void onApplicationWindow(
            WindowFW window)
        {
            final long traceId = window.traceId();
            final long budgetId = window.budgetId();

            replyBudget += window.credit();
            replyPadding = window.padding();

            state = TlsState.openReply(state);

            client.flushNetworkWindow(traceId, budgetId, replyBudget, replyPadding);
        }

        private void onApplicationReset(
            ResetFW reset)
        {
            final long traceId = reset.traceId();

            state = TlsState.closeInitial(state);
            client.stream = nullIfClosed(state, client.stream);

            client.doNetworkResetIfNecessary(traceId);

            doApplicationResetIfNecessary(traceId);
            client.doNetworkAbortIfNecessary(traceId);
        }

        private void doApplicationBegin(
            long traceId,
            long authorization,
            String hostname,
            String protocol)
        {
            state = TlsState.openingReply(state);

            router.setThrottle(replyId, this::onApplication);
            doBegin(application, routeId, replyId, traceId, authorization, affinity,
                ex -> ex.set((b, o, l) -> tlsBeginExRW.wrap(b, o, l)
                                                      .typeId(tlsTypeId)
                                                      .hostname(hostname)
                                                      .protocol(protocol)
                                                      .build()
                                                      .sizeof()));
        }

        private void doApplicationData(
            long traceId,
            long budgetId,
            int reserved,
            DirectBuffer buffer,
            int offset,
            int length)
        {
            assert reserved >= length + replyPadding : String.format("%d >= %d", reserved, length + replyPadding);

            replyBudget -= reserved;

            if (replyBudget < 0)
            {
                client.doNetworkResetIfNecessary(traceId);
                cleanupApplication(traceId);
            }
            else
            {
                doData(application, routeId, replyId, traceId, client.authorization, budgetId,
                       reserved, buffer, offset, length, EMPTY_EXTENSION);
            }
        }

        private void doApplicationEnd(
            long traceId)
        {
            state = TlsState.closeReply(state);
            client.stream = nullIfClosed(state, client.stream);
            doEnd(application, routeId, replyId, traceId, client.authorization, EMPTY_EXTENSION);
        }

        private void doApplicationAbort(
            long traceId)
        {
            state = TlsState.closeReply(state);
            client.stream = nullIfClosed(state, client.stream);
            doAbort(application, routeId, replyId, traceId, client.authorization, EMPTY_EXTENSION);
        }

        private void doApplicationReset(
            long traceId)
        {
            state = TlsState.closeInitial(state);
            client.stream = nullIfClosed(state, client.stream);

            doReset(application, routeId, initialId, traceId, client.authorization);
        }

        private void doApplicationAbortIfNecessary(
            long traceId)
        {
            if (TlsState.replyOpening(state) && !TlsState.replyClosed(state))
            {
                doApplicationAbort(traceId);
            }
        }

        private void doApplicationResetIfNecessary(
            long traceId)
        {
            if (TlsState.initialOpening(state) && !TlsState.initialClosed(state))
            {
                doApplicationReset(traceId);
            }
        }

        private void flushApplicationWindow(
            long traceId,
            long budgetId)
        {
            int initialCredit = client.initialBudget - client.encodeSlotOffset - initialBudget;
            if (initialCredit > 0 && TlsState.initialOpened(state))
            {
                final int initialPadding = client.initialPadding + initialPaddingAdjust;
                initialBudget += initialCredit;
                doWindow(application, routeId, initialId, traceId, client.authorization,
                         budgetId, initialCredit, initialPadding);
            }
        }

        private void cleanupApplication(
            long traceId)
        {
            doApplicationAbortIfNecessary(traceId);
            doApplicationResetIfNecessary(traceId);
        }

        private final class TlsClient
        {
            private final SSLEngine tlsEngine;
            private final String tlsHostname;
            private final MessageConsumer network;
            private final long routeId;
            private final long initialId;
            private final long replyId;

            private TlsClientDecoder decoder;

            private long authorization;
            private int state;

            private int initialBudget;
            private int initialPadding;

            private int replyBudget;

            private int encodeSlot = NO_SLOT;
            private int encodeSlotOffset;
            private long encodeSlotTraceId;

            private int decodeSlot = NO_SLOT;
            private int decodeSlotOffset;
            private int decodeSlotReserved;
            private long decodeSlotBudgetId;

            private long handshakeTaskFutureId = NO_CANCEL_ID;

            private Optional<TlsStream> stream;

            private TlsClient(
                SSLEngine tlsEngine,
                String tlsHostname,
                long routeId)
            {
                this.tlsEngine = tlsEngine;
                this.tlsHostname = tlsHostname;
                this.routeId = routeId;
                this.initialId = supplyInitialId.applyAsLong(routeId);
                this.replyId = supplyReplyId.applyAsLong(initialId);
                this.network = router.supplyReceiver(initialId);
                this.decoder = decodeHandshake;
                this.stream = NULL_STREAM;
            }

            private void onNetwork(
                int msgTypeId,
                DirectBuffer buffer,
                int index,
                int length)
            {
                switch (msgTypeId)
                {
                case BeginFW.TYPE_ID:
                    final BeginFW begin = beginRO.wrap(buffer, index, index + length);
                    onNetworkBegin(begin);
                    break;
                case DataFW.TYPE_ID:
                    final DataFW data = dataRO.wrap(buffer, index, index + length);
                    onNetworkData(data);
                    break;
                case EndFW.TYPE_ID:
                    final EndFW end = endRO.wrap(buffer, index, index + length);
                    onNetworkEnd(end);
                    break;
                case AbortFW.TYPE_ID:
                    final AbortFW abort = abortRO.wrap(buffer, index, index + length);
                    onNetworkAbort(abort);
                    break;
                case ResetFW.TYPE_ID:
                    final ResetFW reset = resetRO.wrap(buffer, index, index + length);
                    onNetworkReset(reset);
                    break;
                case WindowFW.TYPE_ID:
                    final WindowFW window = windowRO.wrap(buffer, index, index + length);
                    onNetworkWindow(window);
                    break;
                case SignalFW.TYPE_ID:
                    final SignalFW signal = signalRO.wrap(buffer, index, index + length);
                    onNetworkSignal(signal);
                    break;
                default:
                    break;
                }
            }

            private void onNetworkBegin(
                BeginFW begin)
            {
                final long traceId = begin.traceId();

                authorization = begin.authorization();
                state = TlsState.openReply(state);

                doNetworkWindow(traceId, 0L, handshakeBudgetMax, 0);
            }

            private void onNetworkData(
                DataFW data)
            {
                final long traceId = data.traceId();
                final long budgetId = data.budgetId();

                authorization = data.authorization();
                replyBudget -= data.reserved();

                if (replyBudget < 0)
                {
                    cleanupNetwork(traceId);
                }
                else
                {
                    if (decodeSlot == NO_SLOT)
                    {
                        decodeSlot = decodePool.acquire(initialId);
                    }

                    if (decodeSlot == NO_SLOT)
                    {
                        cleanupNetwork(traceId);
                    }
                    else
                    {
                        final OctetsFW payload = data.payload();
                        int reserved = data.reserved();
                        int offset = payload.offset();
                        int limit = payload.limit();

                        final MutableDirectBuffer buffer = decodePool.buffer(decodeSlot);
                        buffer.putBytes(decodeSlotOffset, payload.buffer(), offset, limit - offset);
                        decodeSlotOffset += limit - offset;
                        decodeSlotReserved += reserved;
                        decodeSlotBudgetId = budgetId;

                        offset = 0;
                        limit = decodeSlotOffset;
                        reserved = decodeSlotReserved;

                        decodeNetwork(traceId, authorization, budgetId, reserved, buffer, offset, limit);
                    }
                }
            }

            private void onNetworkEnd(
                EndFW end)
            {
                final long traceId = end.traceId();
                final long budgetId = decodeSlotBudgetId; // TODO

                authorization = end.authorization();
                state = TlsState.closeReply(state);

                if (decodeSlot == NO_SLOT || !stream.isPresent())
                {
                    closeInboundQuietly(tlsEngine);

                    cleanupDecodeSlotIfNecessary();

                    // TODO: support half-closed in-bound plus close-on-flush out-bound
                    stream.ifPresent(s -> s.doApplicationAbortIfNecessary(traceId));
                    stream.ifPresent(s -> s.doApplicationResetIfNecessary(traceId));

                    doEncodeCloseOutbound(traceId, budgetId);

                    decoder = decodeIgnoreAll;
                }
            }

            private void onNetworkAbort(
                AbortFW abort)
            {
                final long traceId = abort.traceId();
                final long budgetId = decodeSlotBudgetId; // TODO

                authorization = abort.authorization();
                state = TlsState.closeReply(state);

                closeInboundQuietly(tlsEngine);

                cleanupDecodeSlotIfNecessary();

                stream.ifPresent(s -> s.doApplicationAbortIfNecessary(traceId));
                stream.ifPresent(s -> s.doApplicationResetIfNecessary(traceId));

                doEncodeCloseOutbound(traceId, budgetId);
            }

            private void onNetworkReset(
                ResetFW reset)
            {
                final long traceId = reset.traceId();

                authorization = reset.authorization();
                state = TlsState.closeInitial(state);

                cleanupEncodeSlotIfNecessary();

                closeInboundQuietly(tlsEngine);

                stream.ifPresent(s -> s.doApplicationResetIfNecessary(traceId));
                stream.ifPresent(s -> s.doApplicationAbortIfNecessary(traceId));

                doNetworkResetIfNecessary(traceId);
            }

            private void onNetworkWindow(
                WindowFW window)
            {
                final long traceId = window.traceId();
                final long budgetId = window.budgetId();
                final int credit = window.credit();
                final int padding = window.padding();

                authorization = window.authorization();

                initialBudget += credit;
                initialPadding = padding;

                state = TlsState.openInitial(state);

                if (encodeSlot != NO_SLOT)
                {
                    final MutableDirectBuffer buffer = encodePool.buffer(encodeSlot);
                    final int limit = encodeSlotOffset;

                    encodeNetwork(encodeSlotTraceId, authorization, budgetId, buffer, 0, limit);
                }

                doEncodeWrapIfNecessary(traceId, budgetId);

                if (encodeSlot == NO_SLOT)
                {
                    stream.ifPresent(s -> s.flushApplicationWindow(traceId, budgetId));
                }
            }

            private void onNetworkSignal(
                SignalFW signal)
            {
                switch (signal.signalId())
                {
                case HANDSHAKE_TASK_COMPLETE_SIGNAL:
                    onNetworkSignalHandshakeTaskComplete(signal);
                    break;
                }
            }

            private void onNetworkSignalHandshakeTaskComplete(
                SignalFW signal)
            {
                assert handshakeTaskFutureId != NO_CANCEL_ID;

                handshakeTaskFutureId = NO_CANCEL_ID;

                final long traceId = signal.traceId();
                final long authorization = signal.authorization();
                final long budgetId = decodeSlotBudgetId; // TODO: signal.budgetId ?

                MutableDirectBuffer buffer = EMPTY_MUTABLE_DIRECT_BUFFER;
                int reserved = 0;
                int offset = 0;
                int limit = 0;

                if (decodeSlot != NO_SLOT)
                {
                    reserved = decodeSlotReserved;
                    buffer = decodePool.buffer(decodeSlot);
                    limit = decodeSlotOffset;
                }

                decodeNetwork(traceId, authorization, budgetId, reserved, buffer, offset, limit);
            }

            private void doNetworkBegin(
                long traceId,
                long authorization,
                long affinity,
                OctetsFW extension)
            {
                state = TlsState.openingInitial(state);
                correlations.put(replyId, this);

                router.setThrottle(initialId, this::onNetwork);
                doBegin(network, routeId, initialId, traceId, authorization, affinity, ex -> ex.set(extension));

                try
                {
                    tlsEngine.beginHandshake();
                }
                catch (SSLException ex)
                {
                    cleanupNetwork(traceId);
                }
            }

            private void doNetworkData(
                long traceId,
                long budgetId,
                DirectBuffer buffer,
                int offset,
                int limit)
            {
                if (encodeSlot != NO_SLOT)
                {
                    final MutableDirectBuffer encodeBuffer = encodePool.buffer(encodeSlot);
                    encodeBuffer.putBytes(encodeSlotOffset, buffer, offset, limit - offset);
                    encodeSlotOffset += limit - offset;
                    encodeSlotTraceId = traceId;

                    buffer = encodeBuffer;
                    offset = 0;
                    limit = encodeSlotOffset;
                }

                encodeNetwork(traceId, authorization, budgetId, buffer, offset, limit);
            }

            private void doNetworkEnd(
                long traceId)
            {
                cleanupEncodeSlotIfNecessary();
                doEnd(network, routeId, initialId, traceId, authorization, EMPTY_EXTENSION);
                state = TlsState.closeInitial(state);
            }

            private void doNetworkEndIfNecessary(
                long traceId)
            {
                if (TlsState.initialOpening(state) && !TlsState.initialClosed(state))
                {
                    doNetworkEnd(traceId);
                }
            }

            private void doNetworkAbortIfNecessary(
                long traceId)
            {
                if (!TlsState.initialClosed(state))
                {
                    doAbort(network, routeId, initialId, traceId, authorization, EMPTY_EXTENSION);
                    state = TlsState.closeInitial(state);
                }

                cleanupEncodeSlotIfNecessary();
            }

            private void doNetworkResetIfNecessary(
                long traceId)
            {
                if (!TlsState.replyClosed(state))
                {
                    doReset(network, routeId, replyId, traceId, authorization);
                    state = TlsState.closeReply(state);
                }

                cleanupDecodeSlotIfNecessary();
            }

            private void doNetworkWindow(
                long traceId,
                long budgetId,
                int credit,
                int padding)
            {
                assert credit > 0 : String.format("%d > 0", credit);

                replyBudget += credit;

                doWindow(network, routeId, replyId, traceId, authorization, budgetId, credit, padding);
            }

            private void flushNetworkWindow(
                long traceId,
                long budgetId,
                int replyBudgetMax,
                int replyPadding)
            {
                int replyCredit = Math.min(replyBudgetMax, decodeBudgetMax) - replyBudget - decodeSlotOffset;
                if (replyCredit > 0)
                {
                    doNetworkWindow(traceId, budgetId, replyCredit, replyPadding);
                }

                decodeNetworkIfNecessary(traceId);
            }

            private void encodeNetwork(
                long traceId,
                long authorization,
                long budgetId,
                DirectBuffer buffer,
                int offset,
                int limit)
            {
                final int maxLength = limit - offset;
                final int length = Math.max(Math.min(initialBudget - initialPadding, maxLength), 0);

                if (length > 0)
                {
                    final int reserved = length + initialPadding;

                    initialBudget -= reserved;

                    assert initialBudget >= 0 : String.format("%d >= 0", initialBudget);

                    doData(network, routeId, initialId, traceId, authorization, budgetId,
                           reserved, buffer, offset, length, EMPTY_EXTENSION);
                }

                final int remaining = maxLength - length;
                if (remaining > 0)
                {
                    if (encodeSlot == NO_SLOT)
                    {
                        encodeSlot = encodePool.acquire(initialId);
                    }

                    if (encodeSlot == NO_SLOT)
                    {
                        cleanupNetwork(traceId);
                    }
                    else
                    {
                        final MutableDirectBuffer encodeBuffer = encodePool.buffer(encodeSlot);
                        encodeBuffer.putBytes(0, buffer, offset + length, remaining);
                        encodeSlotOffset = remaining;
                    }
                }
                else
                {
                    cleanupEncodeSlotIfNecessary();

                    if (TlsState.initialClosing(state))
                    {
                        doNetworkEndIfNecessary(traceId);
                    }
                }
            }

            private void decodeNetwork(
                long traceId,
                long authorization,
                long budgetId,
                int reserved,
                MutableDirectBuffer buffer,
                int offset,
                int limit)
            {
                TlsClientDecoder previous = null;
                int progress = offset;
                while (progress <= limit && previous != decoder && handshakeTaskFutureId == NO_CANCEL_ID)
                {
                    previous = decoder;
                    progress = decoder.decode(this, traceId, authorization, budgetId, reserved, buffer, offset, progress, limit);
                }

                if (progress < limit)
                {
                    if (decodeSlot == NO_SLOT)
                    {
                        decodeSlot = decodePool.acquire(initialId);
                    }

                    if (decodeSlot == NO_SLOT)
                    {
                        cleanupNetwork(traceId);
                    }
                    else
                    {
                        final MutableDirectBuffer decodeBuffer = decodePool.buffer(decodeSlot);
                        decodeBuffer.putBytes(0, buffer, progress, limit - progress);
                        decodeSlotOffset = limit - progress;
                        decodeSlotReserved = (limit - progress) * (reserved / (limit - offset));
                    }

                    if (!stream.isPresent())
                    {
                        final int credit = Math.min(handshakeBudgetMax, decodeBudgetMax - decodeSlotOffset - replyBudget);
                        if (credit > 0)
                        {
                            doNetworkWindow(traceId, budgetId, credit, 0);
                        }
                    }
                }
                else
                {
                    cleanupDecodeSlotIfNecessary();

                    if (TlsState.replyClosed(state))
                    {
                        closeInboundQuietly(tlsEngine);

                        // TODO: support half-closed in-bound plus close-on-flush out-bound
                        stream.ifPresent(s -> s.doApplicationAbortIfNecessary(traceId));
                        stream.ifPresent(s -> s.doApplicationResetIfNecessary(traceId));

                        doEncodeCloseOutbound(traceId, budgetId);

                        decoder = decodeIgnoreAll;
                    }
                    else if (!stream.isPresent())
                    {
                        final int credit = progress - offset;
                        if (credit > 0)
                        {
                            doNetworkWindow(traceId, budgetId, credit, 0);
                        }
                    }
                }
            }

            private void decodeNetworkIfNecessary(
                long traceId)
            {
                if (decodeSlot != NO_SLOT)
                {
                    final long budgetId = decodeSlotBudgetId; // TODO: signal.budgetId ?

                    final MutableDirectBuffer buffer = decodePool.buffer(decodeSlot);
                    final int reserved = decodeSlotReserved;
                    final int offset = 0;
                    final int limit = decodeSlotOffset;

                    decodeNetwork(traceId, authorization, budgetId, reserved, buffer, offset, limit);
                }
            }

            private void onDecodeHandshakeNeedTask(
                long traceId,
                long authorization)
            {
                if (handshakeTaskFutureId == NO_CANCEL_ID)
                {
                    final Runnable task = tlsEngine.getDelegatedTask();
                    assert task != null;
                    handshakeTaskFutureId = signaler.signalTask(task, routeId, initialId, HANDSHAKE_TASK_COMPLETE_SIGNAL);
                }
            }

            private void onDecodeHandshakeFinished(
                long traceId,
                long budgetId)
            {
                assert stream == NULL_STREAM;
                stream = Optional.of(TlsStream.this);

                final String protocol = tlsEngine.getApplicationProtocol();

                doApplicationBegin(traceId, budgetId, tlsHostname, protocol);

                TlsStream.this.state = TlsState.openInitial(TlsStream.this.state);
                flushApplicationWindow(traceId, budgetId);
            }

            private void onDecodeUnwrapped(
                long traceId,
                long authorization,
                long budgetId,
                int reserved,
                DirectBuffer buffer,
                int offset,
                int length)
            {
                stream.ifPresent(s -> s.doApplicationData(traceId, budgetId, reserved, buffer, offset, length));
            }

            private void onDecodeInboundClosed(
                long traceId)
            {
                assert tlsEngine.isInboundDone();
                stream.ifPresent(s -> s.doApplicationEnd(traceId));
            }

            private void doEncodeWrap(
                long traceId,
                long budgetId,
                OctetsFW payload)
            {
                final DirectBuffer buffer = payload.buffer();
                final int offset = payload.offset();
                final int length = payload.sizeof();

                inAppByteBuffer.clear();
                inAppBuffer.putBytes(0, buffer, offset, length);
                inAppByteBuffer.limit(length);
                outNetByteBuffer.clear();

                try
                {
                    loop:
                    do
                    {
                        final SSLEngineResult result = tlsEngine.wrap(inAppByteBuffer, outNetByteBuffer);
                        final int bytesProduced = result.bytesProduced();

                        switch (result.getStatus())
                        {
                        case BUFFER_OVERFLOW:
                        case BUFFER_UNDERFLOW:
                            assert false;
                            break;
                        case CLOSED:
                            assert bytesProduced > 0;
                            stream.ifPresent(s -> s.doApplicationResetIfNecessary(traceId));
                            state = TlsState.closingReply(state);
                            break loop;
                        case OK:
                            assert bytesProduced > 0;
                            if (result.getHandshakeStatus() == HandshakeStatus.FINISHED)
                            {
                                onDecodeHandshakeFinished(traceId, budgetId);
                            }
                            break;
                        }
                    } while (inAppByteBuffer.hasRemaining());

                    final int outNetBytesProduced = outNetByteBuffer.position();
                    doNetworkData(traceId, budgetId, outNetBuffer, 0, outNetBytesProduced);
                }
                catch (SSLException ex)
                {
                    cleanupNetwork(traceId);
                }
            }

            private void doEncodeCloseOutbound(
                long traceId,
                long budgetId)
            {
                tlsEngine.closeOutbound();
                state = TlsState.closingReply(state);

                doEncodeWrapIfNecessary(traceId, budgetId);

                doNetworkEndIfNecessary(traceId);
            }

            private void doEncodeWrapIfNecessary(
                long traceId,
                long budgetId)
            {
                if (tlsEngine.getHandshakeStatus() == HandshakeStatus.NEED_WRAP)
                {
                    doEncodeWrap(traceId, budgetId, EMPTY_OCTETS);
                }
            }

            private void cleanupNetwork(
                long traceId)
            {
                doNetworkResetIfNecessary(traceId);
                doNetworkAbortIfNecessary(traceId);

                cleanupApplication(traceId);
            }

            private void cleanupDecodeSlotIfNecessary()
            {
                if (decodeSlot != NO_SLOT)
                {
                    decodePool.release(decodeSlot);
                    decodeSlot = NO_SLOT;
                    decodeSlotOffset = 0;
                    decodeSlotReserved = 0;
                }
            }

            private void cleanupEncodeSlotIfNecessary()
            {
                if (encodeSlot != NO_SLOT)
                {
                    encodePool.release(encodeSlot);
                    encodeSlot = NO_SLOT;
                    encodeSlotOffset = 0;
                    encodeSlotTraceId = 0;
                }
            }
        }
    }

    private static void closeInboundQuietly(
        SSLEngine tlsEngine)
    {
        try
        {
            tlsEngine.closeInbound();
        }
        catch (SSLException ex)
        {
            // ignore
        }
    }

    private static Optional<TlsStream> nullIfClosed(
        int state,
        Optional<TlsStream> stream)
    {
        return TlsState.initialClosed(state) && TlsState.replyClosed(state) ? NULL_STREAM : stream;
    }
}
