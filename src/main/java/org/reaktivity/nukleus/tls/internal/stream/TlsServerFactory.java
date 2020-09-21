/**
 * Copyright 2016-2020 The Reaktivity Project
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

import static java.util.Objects.requireNonNull;
import static org.reaktivity.nukleus.buffer.BufferPool.NO_SLOT;
import static org.reaktivity.nukleus.concurrent.Signaler.NO_CANCEL_ID;
import static org.reaktivity.reaktor.internal.router.RouteId.localId;

import java.nio.ByteBuffer;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Consumer;
import java.util.function.IntFunction;
import java.util.function.LongUnaryOperator;
import java.util.function.ToIntFunction;
import java.util.function.ToLongFunction;

import javax.net.ssl.ExtendedSSLSession;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.security.auth.x500.X500Principal;

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
import org.reaktivity.nukleus.tls.internal.types.String8FW;
import org.reaktivity.nukleus.tls.internal.types.codec.TlsExtensionFW;
import org.reaktivity.nukleus.tls.internal.types.codec.TlsNameType;
import org.reaktivity.nukleus.tls.internal.types.codec.TlsRecordInfoFW;
import org.reaktivity.nukleus.tls.internal.types.codec.TlsServerNameExtensionFW;
import org.reaktivity.nukleus.tls.internal.types.codec.TlsServerNameFW;
import org.reaktivity.nukleus.tls.internal.types.codec.TlsUnwrappedDataFW;
import org.reaktivity.nukleus.tls.internal.types.codec.TlsUnwrappedInfoFW;
import org.reaktivity.nukleus.tls.internal.types.codec.TlsVector16FW;
import org.reaktivity.nukleus.tls.internal.types.control.RouteFW;
import org.reaktivity.nukleus.tls.internal.types.control.TlsRouteExFW;
import org.reaktivity.nukleus.tls.internal.types.stream.AbortFW;
import org.reaktivity.nukleus.tls.internal.types.stream.BeginFW;
import org.reaktivity.nukleus.tls.internal.types.stream.DataFW;
import org.reaktivity.nukleus.tls.internal.types.stream.EndFW;
import org.reaktivity.nukleus.tls.internal.types.stream.ResetFW;
import org.reaktivity.nukleus.tls.internal.types.stream.SignalFW;
import org.reaktivity.nukleus.tls.internal.types.stream.TlsBeginExFW;
import org.reaktivity.nukleus.tls.internal.types.stream.WindowFW;

public final class TlsServerFactory implements StreamFactory
{
    private static final OctetsFW EMPTY_OCTETS = new OctetsFW().wrap(new UnsafeBuffer(new byte[0]), 0, 0);
    private static final Consumer<OctetsFW.Builder> EMPTY_EXTENSION = ex -> {};
    private static final int MAXIMUM_HEADER_SIZE = 5 + 20 + 256;    // TODO version + MAC + padding
    private static final int HANDSHAKE_TASK_COMPLETE_SIGNAL = 1;
    private static final MutableDirectBuffer EMPTY_MUTABLE_DIRECT_BUFFER = new UnsafeBuffer(new byte[0]);

    static final Optional<TlsServer.TlsStream> NULL_STREAM = Optional.ofNullable(null);

    private final ThreadLocal<RouteFW> routeRO = ThreadLocal.withInitial(RouteFW::new);
    private final ThreadLocal<TlsRouteExFW> tlsRouteExRO = ThreadLocal.withInitial(TlsRouteExFW::new);

    private final BeginFW beginRO = new BeginFW();
    private final DataFW dataRO = new DataFW();
    private final EndFW endRO = new EndFW();
    private final AbortFW abortRO = new AbortFW();
    private final SignalFW signalRO = new SignalFW();

    private final BeginFW.Builder beginRW = new BeginFW.Builder();
    private final DataFW.Builder dataRW = new DataFW.Builder();
    private final EndFW.Builder endRW = new EndFW.Builder();
    private final AbortFW.Builder abortRW = new AbortFW.Builder();

    private final TlsBeginExFW.Builder tlsBeginExRW = new TlsBeginExFW.Builder();

    private final WindowFW windowRO = new WindowFW();
    private final ResetFW resetRO = new ResetFW();

    private final WindowFW.Builder windowRW = new WindowFW.Builder();
    private final ResetFW.Builder resetRW = new ResetFW.Builder();

    private final TlsRecordInfoFW tlsRecordInfoRO = new TlsRecordInfoFW();
    private final TlsVector16FW tlsVector16RO = new TlsVector16FW();
    private final TlsServerNameExtensionFW tlsServerNameExtensionRO = new TlsServerNameExtensionFW();
    private final TlsServerNameFW tlsServerNameRO = new TlsServerNameFW();
    private final String8FW tlsProtocolNameRO = new String8FW();

    private final TlsUnwrappedInfoFW.Builder tlsUnwrappedInfoRW = new TlsUnwrappedInfoFW.Builder();
    private final TlsUnwrappedDataFW tlsUnwrappedDataRO = new TlsUnwrappedDataFW();
    private final TlsUnwrappedDataFW.Builder tlsUnwrappedDataRW = new TlsUnwrappedDataFW.Builder();

    private final TlsServerDecoder decodeHandshake = this::decodeHandshake;
    private final TlsServerDecoder decodeBeforeHandshake = this::decodeBeforeHandshake;
    private final TlsServerDecoder decodeHandshakeFinished = this::decodeHandshakeFinished;
    private final TlsServerDecoder decodeHandshakeNeedTask = this::decodeHandshakeNeedTask;
    private final TlsServerDecoder decodeHandshakeNeedUnwrap = this::decodeHandshakeNeedUnwrap;
    private final TlsServerDecoder decodeHandshakeNeedWrap = this::decodeHandshakeNeedWrap;
    private final TlsServerDecoder decodeNotHandshaking = this::decodeNotHandshaking;
    private final TlsServerDecoder decodeNotHandshakingUnwrapped = this::decodeNotHandshakingUnwrapped;
    private final TlsServerDecoder decodeIgnoreAll = this::decodeIgnoreAll;

    private final MessageFunction<RouteFW> wrapRoute = (t, b, i, l) -> routeRO.get().wrap(b, i, i + l);

    private final MessageFunction<TlsRouteExFW> wrapRouteEx = (t, b, i, l) -> wrapRoute.apply(t, b, i, l).extension()
                                                                                       .get(tlsRouteExRO.get()::tryWrap);

    private final int tlsTypeId;
    private final Signaler signaler;
    private final RouteManager router;
    private final MutableDirectBuffer writeBuffer;
    private final BufferPool decodePool;
    private final BufferPool encodePool;
    private final LongUnaryOperator supplyInitialId;
    private final LongUnaryOperator supplyReplyId;
    private final int replyPaddingAdjust;

    private final int decodeBudgetMax;
    private final int handshakeBudgetMax;

    private final Long2ObjectHashMap<TlsServer.TlsStream> correlations;
    private final IntFunction<TlsStoreInfo> lookupStore;
    private final TlsCounters counters;

    private final ByteBuffer inNetByteBuffer;
    private final MutableDirectBuffer inNetBuffer;
    private final ByteBuffer outNetByteBuffer;
    private final DirectBuffer outNetBuffer;
    private final ByteBuffer inAppByteBuffer;
    private final MutableDirectBuffer inAppBuffer;
    private final ByteBuffer outAppByteBuffer;
    private final DirectBuffer outAppBuffer;
    private final DirectBuffer tlsHostnameRO;

    public TlsServerFactory(
        TlsConfiguration config,
        Signaler signaler,
        RouteManager router,
        MutableDirectBuffer writeBuffer,
        BufferPool bufferPool,
        LongUnaryOperator supplyInitialId,
        LongUnaryOperator supplyReplyId,
        ToIntFunction<String> supplyTypeId,
        IntFunction<TlsStoreInfo> lookupStore,
        TlsCounters counters)
    {
        this.tlsTypeId = supplyTypeId.applyAsInt(TlsNukleus.NAME);
        this.signaler = requireNonNull(signaler);
        this.lookupStore = requireNonNull(lookupStore);
        this.counters = requireNonNull(counters);
        this.router = requireNonNull(router);
        this.writeBuffer = requireNonNull(writeBuffer);
        this.decodePool = new CountingBufferPool(bufferPool, counters.serverDecodeAcquires, counters.serverDecodeReleases);
        this.encodePool = new CountingBufferPool(bufferPool, counters.serverEncodeAcquires, counters.serverEncodeReleases);
        this.supplyInitialId = requireNonNull(supplyInitialId);
        this.supplyReplyId = requireNonNull(supplyReplyId);
        this.replyPaddingAdjust = Math.max(bufferPool.slotCapacity() >> 14, 1) * MAXIMUM_HEADER_SIZE;
        this.decodeBudgetMax = decodePool.slotCapacity();
        this.handshakeBudgetMax = Math.min(config.handshakeWindowBytes(), decodeBudgetMax);
        this.correlations = new Long2ObjectHashMap<>();

        this.inNetByteBuffer = ByteBuffer.allocate(writeBuffer.capacity());
        this.inNetBuffer = new UnsafeBuffer(inNetByteBuffer);
        this.outNetByteBuffer = ByteBuffer.allocate(writeBuffer.capacity() << 1);
        this.outNetBuffer = new UnsafeBuffer(outNetByteBuffer);
        this.inAppByteBuffer = ByteBuffer.allocate(writeBuffer.capacity());
        this.inAppBuffer = new UnsafeBuffer(inAppByteBuffer);
        this.outAppByteBuffer = ByteBuffer.allocate(writeBuffer.capacity());
        this.outAppBuffer = new UnsafeBuffer(outAppByteBuffer);
        this.tlsHostnameRO = new UnsafeBuffer(ByteBuffer.allocate(255));
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

        MessageConsumer newStream;

        if ((streamId & 0x0000_0000_0000_0001L) != 0L)
        {
            newStream = newNetworkStream(begin, sender);
        }
        else
        {
            newStream = newApplicationStream(begin, sender);
        }

        return newStream;
    }

    private MessageConsumer newNetworkStream(
        final BeginFW begin,
        final MessageConsumer network)
    {
        final long routeId = begin.routeId();
        final long authorization = begin.authorization();

        final MessagePredicate emptyFilter = (t, b, o, l) -> true;
        final RouteFW route = router.resolve(routeId, authorization, emptyFilter, wrapRoute);

        MessageConsumer newStream = null;

        if (route != null)
        {
            final long resolvedId = route.correlationId();
            final long initialId = begin.streamId();

            final TlsStoreInfo tlsStoreInfo = lookupStore.apply(localId(resolvedId));
            final SSLContext sslContext = tlsStoreInfo == null ? null : tlsStoreInfo.context;
            final SSLEngine tlsEngine = sslContext == null ? null : sslContext.createSSLEngine();

            if (tlsEngine != null)
            {
                tlsEngine.setUseClientMode(false);

                tlsEngine.setWantClientAuth(tlsStoreInfo.supportsClientAuth);

                tlsEngine.setHandshakeApplicationProtocolSelector((ex, ps) ->
                {
                    SSLSession session = tlsEngine.getHandshakeSession();
                    byte[] tlsHostnameEncoded = null;
                    if (session instanceof ExtendedSSLSession)
                    {
                        ExtendedSSLSession sessionEx = (ExtendedSSLSession) session;
                        List<SNIServerName> serverNames = sessionEx.getRequestedServerNames();
                        if (!serverNames.isEmpty())
                        {
                            SNIServerName serverName = serverNames.get(0);
                            tlsHostnameEncoded = serverName.getEncoded();
                        }
                    }

                    DirectBuffer tlsHostname = null;
                    if (tlsHostnameEncoded != null)
                    {
                        tlsHostnameRO.wrap(tlsHostnameEncoded);
                        tlsHostname = tlsHostnameRO;
                    }

                    final DirectBuffer tlsHostname0 = tlsHostname;
                    final MessagePredicate filter = (t, b, i, l) ->
                    {
                        final TlsRouteExFW routeExFW = wrapRouteEx.apply(t, b, i, l);

                        final String8FW hostname = routeExFW.hostname();

                        return hostname != null && Objects.equals(tlsHostname0, hostname.value());
                    };

                    final RouteFW alpnRoute = router.resolve(routeId, authorization, filter, wrapRoute);

                    String protocol = null;
                    if (alpnRoute != null)
                    {
                        final TlsRouteExFW newRouteEx = alpnRoute.extension().get(tlsRouteExRO.get()::tryWrap);
                        final String alpnProtocol = newRouteEx.protocol().asString();
                        protocol = alpnProtocol == null ? "" : alpnProtocol;
                    }

                    return protocol;
                });

                final TlsServer server = new TlsServer(network, routeId, initialId, authorization,
                    tlsEngine, tlsStoreInfo::authorization);

                newStream = server::onNetwork;
            }
        }

        return newStream;
    }

    private MessageConsumer newApplicationStream(
        final BeginFW begin,
        final MessageConsumer application)
    {
        final long streamId = begin.streamId();

        MessageConsumer newStream = null;

        final TlsServer.TlsStream stream = correlations.remove(streamId);
        if (stream != null)
        {
            newStream = stream::onApplication;
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
        DirectBuffer buffer,
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
                .payload(buffer, offset, length)
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
        Consumer<OctetsFW.Builder> extension)
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
        Consumer<OctetsFW.Builder> extension)
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
        MessageConsumer receiver,
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

        receiver.accept(window.typeId(), window.buffer(), window.offset(), window.sizeof());
    }

    private void doReset(
        MessageConsumer receiver,
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

        receiver.accept(reset.typeId(), reset.buffer(), reset.offset(), reset.sizeof());
    }

    private int decodeBeforeHandshake(
        TlsServer server,
        long traceId,
        long authorization,
        long budgetId,
        int reserved,
        DirectBuffer buffer,
        int offset,
        int progress,
        int limit)
    {
        try
        {
            server.tlsEngine.beginHandshake();
            server.decoder = decodeHandshake;
        }
        catch (SSLException | RuntimeException ex)
        {
            server.tlsEngine = null;
        }

        if (server.tlsEngine == null)
        {
            server.cleanupNetwork(traceId);
            server.decoder = decodeIgnoreAll;
        }

        return progress;
    }

    private int decodeHandshake(
        TlsServer server,
        long traceId,
        long authorization,
        long budgetId,
        int reserved,
        DirectBuffer buffer,
        int offset,
        int progress,
        int limit)
    {
        final SSLEngine tlsEngine = server.tlsEngine;
        switch (tlsEngine.getHandshakeStatus())
        {
        case NOT_HANDSHAKING:
            server.decoder = decodeNotHandshaking;
            break;
        case FINISHED:
            server.decoder = decodeHandshakeFinished;
            break;
        case NEED_TASK:
            server.decoder = decodeHandshakeNeedTask;
            break;
        case NEED_WRAP:
            server.decoder = decodeHandshakeNeedWrap;
            break;
        case NEED_UNWRAP:
            server.decoder = decodeHandshakeNeedUnwrap;
            break;
        case NEED_UNWRAP_AGAIN:
            assert false : "NEED_UNWRAP_AGAIN used by DTLS only";
            break;
        }

        return progress;
    }

    private int decodeNotHandshaking(
        TlsServer server,
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
                final int tlsRecordBytes = tlsRecordInfo.sizeof() + tlsRecordInfo.length();

                server.decodableRecordBytes = tlsRecordBytes;

                if (tlsRecordBytes <= length)
                {
                    final int tlsRecordDataOffset = tlsRecordInfo.limit();
                    final int tlsRecordDataLimit = tlsRecordDataOffset + tlsRecordInfo.length();

                    assert tlsRecordBytes == tlsRecordDataLimit - progress;

                    inNetByteBuffer.clear();
                    inNetBuffer.putBytes(0, buffer, progress, tlsRecordDataLimit - progress);
                    inNetByteBuffer.limit(tlsRecordDataLimit - progress);
                    outAppByteBuffer.clear();

                    try
                    {
                        final SSLEngineResult result = server.tlsEngine.unwrap(inNetByteBuffer, outAppByteBuffer);
                        final int bytesProduced = result.bytesProduced();
                        final int bytesConsumed = result.bytesConsumed();

                        switch (result.getStatus())
                        {
                        case BUFFER_UNDERFLOW:
                        case BUFFER_OVERFLOW:
                            assert false;
                            break;
                        case OK:
                            if (bytesProduced == 0)
                            {
                                assert result.getHandshakeStatus() != HandshakeStatus.FINISHED;
                                server.decoder = decodeHandshake;
                                progress += bytesConsumed;
                            }
                            else
                            {
                                assert bytesConsumed == tlsRecordBytes;
                                assert bytesProduced <= bytesConsumed : String.format("%d <= %d", bytesProduced, bytesConsumed);

                                tlsUnwrappedDataRW.wrap(buffer, tlsRecordDataOffset, tlsRecordDataLimit)
                                                  .payload(outAppBuffer, 0, bytesProduced)
                                                  .build();

                                server.decodableRecordBytes -= bytesConsumed;
                                assert server.decodableRecordBytes == 0;

                                server.decoder = decodeNotHandshakingUnwrapped;
                            }
                            break;
                        case CLOSED:
                            assert bytesProduced == 0;
                            server.onDecodeInboundClosed(traceId);
                            server.decoder = TlsState.initialClosed(server.state) ? decodeIgnoreAll : decodeHandshake;
                            progress += bytesConsumed;
                            break;
                        }
                    }
                    catch (SSLException | RuntimeException ex)
                    {
                        server.cleanupNetwork(traceId);
                        server.decoder = decodeIgnoreAll;
                    }
                }
                else if (TlsState.initialClosed(server.state))
                {
                    server.decoder = decodeIgnoreAll;
                }
            }
        }

        return progress;
    }

    private int decodeNotHandshakingUnwrapped(
        TlsServer server,
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
            assert server.decodableRecordBytes == 0;

            final TlsRecordInfoFW tlsRecordInfo = tlsRecordInfoRO.wrap(buffer, progress, limit);
            final int tlsRecordDataOffset = tlsRecordInfo.limit();
            final int tlsRecordDataLimit = tlsRecordDataOffset + tlsRecordInfo.length();

            final TlsUnwrappedDataFW tlsUnwrappedData = tlsUnwrappedDataRO.wrap(buffer, tlsRecordDataOffset, tlsRecordDataLimit);
            final TlsServer.TlsStream stream = server.stream.orElse(null);
            final int initialBudget = stream != null ? stream.initialBudget : 0;
            final int initialPadding = stream != null ? stream.initialPadding : 0;

            final int bytesOffset = tlsRecordInfo.sizeof();
            final int bytesConsumed = bytesOffset + tlsRecordInfo.length();
            final int bytesProduced = tlsUnwrappedData.length();

            final int bytesPosition = tlsUnwrappedData.info().position();
            final int bytesRemaining = bytesProduced - bytesPosition;

            assert bytesRemaining > 0 : String.format("%d > 0", bytesRemaining);

            final int bytesReservedMax = Math.min(initialBudget, bytesRemaining + initialPadding);
            final int bytesRemainingMax = Math.max(bytesReservedMax - initialPadding, 0);

            assert bytesReservedMax >= bytesRemainingMax : String.format("%d >= %d", bytesReservedMax, bytesRemainingMax);

            if (bytesRemainingMax > 0)
            {
                final OctetsFW payload = tlsUnwrappedData.payload();

                server.onDecodeUnwrapped(traceId, authorization, budgetId, bytesReservedMax,
                        payload.buffer(), payload.offset() + bytesPosition, bytesRemainingMax);

                final int newBytesPosition = bytesPosition + bytesRemainingMax;
                assert newBytesPosition <= bytesProduced;

                if (newBytesPosition == bytesProduced)
                {
                    progress += bytesConsumed;
                    server.decoder = decodeHandshake;
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
        TlsServer server,
        long traceId,
        long authorization,
        long budgetId,
        int reserved,
        DirectBuffer buffer,
        int offset,
        int progress,
        int limit)
    {
        server.onDecodeHandshakeFinished(traceId, authorization);
        server.decoder = decodeHandshake;
        return progress;
    }

    private int decodeHandshakeNeedTask(
        TlsServer server,
        long traceId,
        long authorization,
        long budgetId,
        int reserved,
        DirectBuffer buffer,
        int offset,
        int progress,
        int limit)
    {
        server.onDecodeHandshakeNeedTask(traceId, authorization);
        server.decoder = decodeHandshake;
        return progress;
    }

    private int decodeHandshakeNeedUnwrap(
        TlsServer server,
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
                final SSLEngineResult result = server.tlsEngine.unwrap(inNetByteBuffer, outAppByteBuffer);
                final int bytesConsumed = result.bytesConsumed();
                final int bytesProduced = result.bytesProduced();

                switch (result.getStatus())
                {
                case BUFFER_UNDERFLOW:
                    if (TlsState.initialClosed(server.state))
                    {
                        server.decoder = decodeIgnoreAll;
                    }
                    break;
                case BUFFER_OVERFLOW:
                    assert false;
                    break;
                case OK:
                    assert bytesProduced == 0;
                    if (result.getHandshakeStatus() == HandshakeStatus.FINISHED)
                    {
                        server.onDecodeHandshakeFinished(traceId, budgetId);
                    }
                    server.decoder = decodeHandshake;
                    break;
                case CLOSED:
                    assert bytesProduced == 0;
                    server.onDecodeInboundClosed(traceId);
                    server.decoder = decodeIgnoreAll;
                    break;
                }

                progress += bytesConsumed;
            }
            catch (SSLException | RuntimeException ex)
            {
                server.cleanupNetwork(traceId);
                server.decoder = decodeIgnoreAll;
            }
        }

        return progress;
    }

    private int decodeHandshakeNeedWrap(
        TlsServer server,
        long traceId,
        long authorization,
        long budgetId,
        int reserved,
        DirectBuffer buffer,
        int offset,
        int progress,
        int limit)
    {
        server.doEncodeWrap(traceId, budgetId, EMPTY_OCTETS);
        server.decoder = decodeHandshake;
        return progress;
    }

    private int decodeIgnoreAll(
        TlsServer server,
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

    private String decodeServerName(
        TlsExtensionFW tlsExtension)
    {
        String serverName = null;

        final TlsServerNameExtensionFW tlsServerNameExtension = tlsExtension.data().get(tlsServerNameExtensionRO::tryWrap);
        if (tlsServerNameExtension != null)
        {
            final TlsVector16FW tlsServerNames = tlsServerNameExtension.serverNames();
            final OctetsFW tlsServerNamesData = tlsServerNames.data();
            final DirectBuffer dataBuffer = tlsServerNamesData.buffer();
            final int dataLimit = tlsServerNamesData.limit();
            for (int dataOffset = tlsServerNamesData.offset(); dataOffset < dataLimit; )
            {
                final TlsServerNameFW tlsServerName = tlsServerNameRO.tryWrap(dataBuffer, dataOffset, dataLimit);
                if (tlsServerName != null && tlsServerName.kind() == TlsNameType.HOSTNAME.value())
                {
                    serverName = tlsServerName.hostname().asString();
                    break;
                }
                dataOffset = tlsServerName.limit();
            }
        }

        return serverName;
    }

    private List<String> decodeApplicationLayerProtocolNegotiation(
        TlsExtensionFW tlsExtension)
    {
        final List<String> protocolNames = new ArrayList<>(3);

        final TlsVector16FW tlsExtensionData = tlsExtension.data().get(tlsVector16RO::tryWrap);
        if (tlsExtensionData != null)
        {
            final OctetsFW tlsAlpnData = tlsExtensionData.data();
            final DirectBuffer dataBuffer = tlsAlpnData.buffer();
            final int dataLimit = tlsAlpnData.limit();
            for (int dataOffset = tlsAlpnData.offset(); dataOffset < dataLimit; )
            {
                final String8FW tlsProtocolName = tlsProtocolNameRO.tryWrap(dataBuffer, dataOffset, dataLimit);
                final String protocolName = tlsProtocolName != null ? tlsProtocolName.asString() : null;
                if (protocolName != null && !protocolName.isEmpty())
                {
                    protocolNames.add(protocolName);
                }
                dataOffset = tlsProtocolName.limit();
            }
        }

        return protocolNames;
    }

    @FunctionalInterface
    private interface TlsServerDecoder
    {
        int decode(
            TlsServer server,
            long traceId,
            long authorization,
            long budgetId,
            int reserved,
            MutableDirectBuffer buffer,
            int offset,
            int progress,
            int limit);
    }

    final class TlsServer
    {
        private final MessageConsumer network;
        private final long routeId;
        private final long initialId;
        private ToLongFunction<String> supplyAuthorization;
        private final long replyId;
        private long authorization;
        private long affinity;

        private SSLEngine tlsEngine;

        private long handshakeTaskFutureId = NO_CANCEL_ID;

        private int decodeSlot = NO_SLOT;
        private int decodeSlotOffset;
        private int decodeSlotReserved;
        private long decodeSlotBudgetId;

        private int decodableRecordBytes;

        private int encodeSlot = NO_SLOT;
        private int encodeSlotOffset;
        private long encodeSlotTraceId;

        private int initialBudget;

        private long replyBudgetId;
        private int replyBudget;
        private int replyPadding;

        private int state;
        private TlsServerDecoder decoder;
        private Optional<TlsStream> stream;

        private TlsServer(
            MessageConsumer network,
            long networkRouteId,
            long networkInitialId,
            long authorization,
            SSLEngine tlsEngine,
            ToLongFunction<String> supplyAuthorization)
        {
            this.network = network;
            this.routeId = networkRouteId;

            this.initialId = networkInitialId;
            this.replyId = supplyReplyId.applyAsLong(initialId);
            this.decoder = decodeBeforeHandshake;
            this.stream = NULL_STREAM;
            this.tlsEngine = tlsEngine;
            this.supplyAuthorization = supplyAuthorization;
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
            affinity = begin.affinity();
            state = TlsState.openInitial(state);

            doNetworkWindow(traceId, 0L, handshakeBudgetMax, 0);
            doNetworkBegin(traceId);
        }

        private void onNetworkData(
            DataFW data)
        {
            final long traceId = data.traceId();
            final long budgetId = data.budgetId();

            authorization = data.authorization();
            initialBudget -= data.reserved();

            if (initialBudget < 0)
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
            state = TlsState.closeInitial(state);

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
            else
            {
                decodeNetworkIfNecessary(traceId);
            }
        }

        private void onNetworkAbort(
            AbortFW abort)
        {
            final long traceId = abort.traceId();
            final long budgetId = decodeSlotBudgetId; // TODO

            authorization = abort.authorization();
            state = TlsState.closeInitial(state);

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
            state = TlsState.closeReply(state);

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

            state = TlsState.openReply(state);

            authorization = window.authorization();

            replyBudgetId = budgetId;
            replyBudget += credit;
            replyPadding = padding;

            if (encodeSlot != NO_SLOT)
            {
                final MutableDirectBuffer buffer = encodePool.buffer(encodeSlot);
                final int limit = encodeSlotOffset;

                encodeNetwork(encodeSlotTraceId, authorization, budgetId, buffer, 0, limit);
            }

            if (encodeSlot == NO_SLOT)
            {
                stream.ifPresent(s -> s.flushApplicationWindow(traceId));
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
            long traceId)
        {
            doBegin(network, routeId, replyId, traceId, authorization, affinity, EMPTY_EXTENSION);
            router.setThrottle(replyId, this::onNetwork);
            state = TlsState.openingReply(state);
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
            doEnd(network, routeId, replyId, traceId, authorization, EMPTY_EXTENSION);
            state = TlsState.closeReply(state);
        }

        private void doNetworkEndIfNecessary(
            long traceId)
        {
            if (!TlsState.replyClosed(state))
            {
                doNetworkEnd(traceId);
            }
        }

        private void doNetworkAbortIfNecessary(
            long traceId)
        {
            if (!TlsState.replyClosed(state))
            {
                doAbort(network, routeId, replyId, traceId, authorization, EMPTY_EXTENSION);
                state = TlsState.closeReply(state);
            }

            cleanupEncodeSlotIfNecessary();
        }

        private void doNetworkResetIfNecessary(
            long traceId)
        {
            if (!TlsState.initialClosed(state))
            {
                doReset(network, routeId, initialId, traceId, authorization);
                state = TlsState.closeInitial(state);
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

            initialBudget += credit;

            doWindow(network, routeId, initialId, traceId, authorization, budgetId, credit, padding);
        }

        private void flushNetworkWindow(
            long traceId,
            long budgetId,
            int initialBudgetMax,
            int initialPadding)
        {
            int initialCredit = Math.min(initialBudgetMax, decodeBudgetMax) - initialBudget - decodeSlotOffset;
            if (initialCredit > 0)
            {
                doNetworkWindow(traceId, budgetId, initialCredit, initialPadding);
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
            final int length = Math.max(Math.min(replyBudget - replyPadding, maxLength), 0);

            if (length > 0)
            {
                final int reserved = length + replyPadding;

                replyBudget -= reserved;

                assert replyBudget >= 0 : String.format("%d >= 0", replyBudget);

                doData(network, routeId, replyId, traceId, authorization, budgetId,
                       reserved, buffer, offset, length, EMPTY_EXTENSION);
            }

            final int remaining = maxLength - length;
            if (remaining > 0)
            {
                if (encodeSlot == NO_SLOT)
                {
                    encodeSlot = encodePool.acquire(replyId);
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

                if (TlsState.replyClosing(state))
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
            TlsServerDecoder previous = null;
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
            }
            else
            {
                cleanupDecodeSlotIfNecessary();

                if (TlsState.initialClosed(state))
                {
                    closeInboundQuietly(tlsEngine);

                    // TODO: support half-closed in-bound plus close-on-flush out-bound
                    stream.ifPresent(s -> s.doApplicationAbortIfNecessary(traceId));
                    stream.ifPresent(s -> s.doApplicationResetIfNecessary(traceId));

                    doEncodeCloseOutbound(traceId, budgetId);

                    decoder = decodeIgnoreAll;
                }
            }

            if (tlsEngine == null || !tlsEngine.isInboundDone())
            {
                final int decodeCreditMax = decodeBudgetMax - decodeSlotOffset - initialBudget;

                final int credit = stream.isPresent() ? decodeCreditMax : Math.min(handshakeBudgetMax, decodeCreditMax);
                if (credit > 0)
                {
                    doNetworkWindow(traceId, budgetId, credit, 0);
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
                handshakeTaskFutureId = signaler.signalTask(task, routeId, replyId, HANDSHAKE_TASK_COMPLETE_SIGNAL);
            }
        }

        private void onDecodeHandshakeFinished(
            long traceId,
            long budgetId)
        {
            ExtendedSSLSession tlsSession = (ExtendedSSLSession) tlsEngine.getSession();
            List<SNIServerName> serverNames = tlsSession.getRequestedServerNames();
            String alpn = tlsEngine.getApplicationProtocol();

            String tlsHostname = serverNames.stream()
                                            .filter(SNIHostName.class::isInstance)
                                            .map(SNIHostName.class::cast)
                                            .map(SNIHostName::getAsciiName)
                                            .findFirst()
                                            .orElse(null);

            String tlsProtocol = "".equals(alpn) ? null : alpn;

            final MessagePredicate filter = (t, b, i, l) ->
            {
                final TlsRouteExFW routeEx = wrapRouteEx.apply(t, b, i, l);

                final String hostname = routeEx.hostname().asString();
                final String protocol = routeEx.protocol().asString();

                return (hostname == null || Objects.equals(tlsHostname, hostname)) &&
                       (protocol == null || Objects.equals(tlsProtocol, protocol));
            };

            final RouteFW route = router.resolve(routeId, authorization, filter, wrapRoute);

            if (route != null)
            {
                final long routeId = route.correlationId();

                final TlsStream stream = new TlsStream(routeId, tlsEngine);
                correlations.put(stream.replyId, stream);

                stream.doApplicationBegin(traceId, tlsHostname, tlsProtocol);
            }
            else
            {
                tlsEngine.closeOutbound();
            }
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
            catch (SSLException | RuntimeException ex)
            {
                cleanupNetwork(traceId);
            }
        }

        private void doEncodeCloseOutbound(
            long traceId,
            long budgetId)
        {
            if (tlsEngine != null)
            {
                tlsEngine.closeOutbound();
            }
            state = TlsState.closingReply(state);

            doEncodeWrapIfNecessary(traceId, budgetId);

            doNetworkEndIfNecessary(traceId);
        }

        private void doEncodeWrapIfNecessary(
            long traceId,
            long budgetId)
        {
            if (tlsEngine != null &&
                tlsEngine.getHandshakeStatus() == HandshakeStatus.NEED_WRAP)
            {
                doEncodeWrap(traceId, budgetId, EMPTY_OCTETS);
            }
        }

        private void cleanupNetwork(
            long traceId)
        {
            doNetworkResetIfNecessary(traceId);
            doNetworkAbortIfNecessary(traceId);

            stream.ifPresent(s -> s.cleanupApplication(traceId));
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

        final class TlsStream
        {
            private final MessageConsumer application;
            private final long routeId;
            private final long initialId;
            private final long replyId;
            private final long authorization;

            private int state;

            private int initialBudget;
            private int initialPadding;
            private int replyBudget;

            private TlsStream(
                long routeId,
                SSLEngine tlsEngine)
            {
                this.routeId = routeId;
                this.initialId = supplyInitialId.applyAsLong(routeId);
                this.application = router.supplyReceiver(initialId);
                this.replyId = supplyReplyId.applyAsLong(initialId);
                this.authorization = authorization(tlsEngine.getSession());
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
                final long traceId = begin.traceId();

                state = TlsState.openReply(state);

                flushApplicationWindow(traceId);
            }

            private void onApplicationData(
                DataFW data)
            {
                final long traceId = data.traceId();

                replyBudget -= data.reserved();

                if (replyBudget < 0)
                {
                    cleanupApplication(traceId);
                    doNetworkAbortIfNecessary(traceId);
                }
                else if (data.length() > 0)
                {
                    final long budgetId = data.budgetId();
                    final OctetsFW payload = data.payload();

                    doEncodeWrap(traceId, budgetId, payload);
                }
            }

            private void onApplicationEnd(
                EndFW end)
            {
                final long traceId = end.traceId();
                final long budgetId = 0L; // TODO

                state = TlsState.closeReply(state);
                stream = nullIfClosed(state, stream);

                doEncodeCloseOutbound(traceId, budgetId);
            }

            private void onApplicationAbort(
                AbortFW abort)
            {
                final long traceId = abort.traceId();

                state = TlsState.closeReply(state);
                stream = nullIfClosed(state, stream);

                doNetworkAbortIfNecessary(traceId);

                doApplicationAbortIfNecessary(traceId);
                doNetworkResetIfNecessary(traceId);
            }

            private void onApplicationWindow(
                WindowFW window)
            {
                final long traceId = window.traceId();
                final long budgetId = window.budgetId();

                initialBudget += window.credit();
                initialPadding = window.padding();

                state = TlsState.openInitial(state);

                flushNetworkWindow(traceId, budgetId, initialBudget, initialPadding);
            }

            private void onApplicationReset(
                ResetFW reset)
            {
                final long traceId = reset.traceId();

                state = TlsState.closeInitial(state);
                stream = nullIfClosed(state, stream);

                doNetworkResetIfNecessary(traceId);

                doApplicationResetIfNecessary(traceId);
                doNetworkAbortIfNecessary(traceId);
            }

            private void doApplicationBegin(
                long traceId,
                String hostname,
                String protocol)
            {
                stream = Optional.of(this);
                state = TlsState.openingInitial(state);

                router.setThrottle(initialId, this::onApplication);
                doBegin(application, routeId, initialId, traceId, authorization, affinity,
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
                assert reserved >= length + initialPadding : String.format("%d >= %d", reserved, length + initialPadding);

                initialBudget -= reserved;

                if (initialBudget < 0)
                {
                    doNetworkResetIfNecessary(traceId);
                    cleanupApplication(traceId);
                }
                else
                {
                    doData(application, routeId, initialId, traceId, authorization, budgetId,
                           reserved, buffer, offset, length, EMPTY_EXTENSION);
                }
            }

            private void doApplicationEnd(
                long traceId)
            {
                state = TlsState.closeInitial(state);
                stream = nullIfClosed(state, stream);
                doEnd(application, routeId, initialId, traceId, authorization, EMPTY_EXTENSION);
            }

            private void doApplicationAbort(
                long traceId)
            {
                state = TlsState.closeInitial(state);
                stream = nullIfClosed(state, stream);
                doAbort(application, routeId, initialId, traceId, authorization, EMPTY_EXTENSION);
            }

            private void doApplicationReset(
                long traceId)
            {
                state = TlsState.closeReply(state);
                stream = nullIfClosed(state, stream);

                correlations.remove(replyId);
                doReset(application, routeId, replyId, traceId, authorization);
            }

            private void doApplicationAbortIfNecessary(
                long traceId)
            {
                if (!TlsState.initialClosed(state))
                {
                    doApplicationAbort(traceId);
                }
            }

            private void doApplicationResetIfNecessary(
                long traceId)
            {
                if (!TlsState.replyClosed(state))
                {
                    doApplicationReset(traceId);
                }
            }

            private void flushApplicationWindow(
                long traceId)
            {
                int replyCredit = TlsServer.this.replyBudget - TlsServer.this.encodeSlotOffset - replyBudget;
                if (replyCredit > 0 && TlsState.replyOpened(state))
                {
                    final int replyPadding = TlsServer.this.replyPadding + replyPaddingAdjust;
                    replyBudget += replyCredit;
                    doWindow(application, routeId, replyId, traceId, authorization,
                             replyBudgetId, replyCredit, replyPadding);
                }
            }

            private void cleanupApplication(
                long traceId)
            {
                doApplicationAbortIfNecessary(traceId);
                doApplicationResetIfNecessary(traceId);
            }
        }

        private long authorization(
            SSLSession tlsSession)
        {
            long authorization = 0L;

            try
            {
                Certificate[] certs = tlsSession.getPeerCertificates();
                if (certs.length > 1)
                {
                    Certificate signingCaCert = certs[1];
                    X509Certificate signingCaX509Cert = (X509Certificate) signingCaCert;
                    X500Principal x500Principal = signingCaX509Cert.getSubjectX500Principal();
                    String distinguishedName = x500Principal.getName();
                    authorization = supplyAuthorization.applyAsLong(distinguishedName);
                }
            }
            catch (SSLPeerUnverifiedException e)
            {
                // ignore
            }

            return authorization;
        }
    }

    private static void closeInboundQuietly(
        SSLEngine tlsEngine)
    {
        try
        {
            if (tlsEngine != null)
            {
                tlsEngine.closeInbound();
            }
        }
        catch (SSLException | RuntimeException ex)
        {
            // ignore
        }
    }

    private static Optional<TlsServer.TlsStream> nullIfClosed(
        int state,
        Optional<TlsServer.TlsStream> stream)
    {
        return TlsState.initialClosed(state) && TlsState.replyClosed(state) ? NULL_STREAM : stream;
    }
}
