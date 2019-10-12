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

import static java.util.Objects.requireNonNull;
import static org.reaktivity.nukleus.buffer.BufferPool.NO_SLOT;

import java.nio.ByteBuffer;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.Future;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.LongUnaryOperator;
import java.util.function.ToIntFunction;

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
import org.reaktivity.nukleus.concurrent.SignalingExecutor;
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
import org.reaktivity.nukleus.tls.internal.types.StringFW;
import org.reaktivity.nukleus.tls.internal.types.codec.TlsClientHelloFW;
import org.reaktivity.nukleus.tls.internal.types.codec.TlsContentType;
import org.reaktivity.nukleus.tls.internal.types.codec.TlsExtensionFW;
import org.reaktivity.nukleus.tls.internal.types.codec.TlsExtensionType;
import org.reaktivity.nukleus.tls.internal.types.codec.TlsHandshakeFW;
import org.reaktivity.nukleus.tls.internal.types.codec.TlsHandshakeType;
import org.reaktivity.nukleus.tls.internal.types.codec.TlsNameType;
import org.reaktivity.nukleus.tls.internal.types.codec.TlsProtocolVersionFW;
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

    private static final Optional<TlsServer.TlsStream> NULL_STREAM = Optional.ofNullable(null);

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
    private final TlsHandshakeFW tlsHandshakeRO = new TlsHandshakeFW();
    private final TlsClientHelloFW tlsClientHelloRO = new TlsClientHelloFW();
    private final TlsExtensionFW tlsExtensionRO = new TlsExtensionFW();
    private final TlsVector16FW tlsVector16RO = new TlsVector16FW();
    private final TlsServerNameExtensionFW tlsServerNameExtensionRO = new TlsServerNameExtensionFW();
    private final TlsServerNameFW tlsServerNameRO = new TlsServerNameFW();
    private final StringFW tlsProtocolNameRO = new StringFW();

    private final TlsUnwrappedInfoFW.Builder tlsUnwrappedInfoRW = new TlsUnwrappedInfoFW.Builder();
    private final TlsUnwrappedDataFW tlsUnwrappedDataRO = new TlsUnwrappedDataFW();
    private final TlsUnwrappedDataFW.Builder tlsUnwrappedDataRW = new TlsUnwrappedDataFW.Builder();

    private final TlsServerDecoder decodeClientHello = this::decodeClientHello;
    private final TlsServerDecoder decodeHandshake = this::decodeHandshake;
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
    private final SignalingExecutor executor;
    private final RouteManager router;
    private final MutableDirectBuffer writeBuffer;
    private final BufferPool decodePool;
    private final BufferPool encodePool;
    private final LongUnaryOperator supplyInitialId;
    private final LongUnaryOperator supplyReplyId;
    private final int replyPaddingAdjust;

    private final Long2ObjectHashMap<TlsServer.TlsStream> correlations;
    private final Function<String, TlsStoreInfo> lookupContext;
    private final TlsCounters counters;

    private final ByteBuffer inNetByteBuffer;
    private final MutableDirectBuffer inNetBuffer;
    private final ByteBuffer outNetByteBuffer;
    private final DirectBuffer outNetBuffer;
    private final ByteBuffer inAppByteBuffer;
    private final MutableDirectBuffer inAppBuffer;
    private final ByteBuffer outAppByteBuffer;
    private final DirectBuffer outAppBuffer;

    public TlsServerFactory(
        TlsConfiguration config,
        SignalingExecutor executor,
        RouteManager router,
        MutableDirectBuffer writeBuffer,
        BufferPool bufferPool,
        LongUnaryOperator supplyInitialId,
        LongUnaryOperator supplyReplyId,
        ToIntFunction<String> supplyTypeId,
        Function<String, TlsStoreInfo> lookupContext,
        TlsCounters counters)
    {
        this.tlsTypeId = supplyTypeId.applyAsInt(TlsNukleus.NAME);
        this.executor = requireNonNull(executor);
        this.lookupContext = requireNonNull(lookupContext);
        this.counters = requireNonNull(counters);
        this.router = requireNonNull(router);
        this.writeBuffer = requireNonNull(writeBuffer);
        this.decodePool = new CountingBufferPool(bufferPool, counters.serverDecodeAcquires, counters.serverDecodeReleases);
        this.encodePool = new CountingBufferPool(bufferPool, counters.serverEncodeAcquires, counters.serverEncodeReleases);
        this.supplyInitialId = requireNonNull(supplyInitialId);
        this.supplyReplyId = requireNonNull(supplyReplyId);
        this.replyPaddingAdjust = Math.min(bufferPool.slotCapacity() >> 14, 1) * MAXIMUM_HEADER_SIZE;
        this.correlations = new Long2ObjectHashMap<>();

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

        final MessagePredicate filter = (t, b, o, l) -> true;
        final RouteFW route = router.resolve(routeId, authorization, filter, wrapRoute);

        MessageConsumer newStream = null;

        if (route != null)
        {
            final long initialId = begin.streamId();

            final TlsServer server = new TlsServer(network, routeId, initialId, authorization);

            newStream = server::onNetwork;
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
        Consumer<OctetsFW.Builder> extension)
    {
        final BeginFW begin = beginRW.wrap(writeBuffer, 0, writeBuffer.capacity())
                .routeId(routeId)
                .streamId(streamId)
                .trace(traceId)
                .authorization(authorization)
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
        long groupId,
        int reserved,
        DirectBuffer buffer,
        int offset,
        int length,
        Consumer<OctetsFW.Builder> extension)
    {
        final DataFW data = dataRW.wrap(writeBuffer, 0, writeBuffer.capacity())
                .routeId(routeId)
                .streamId(streamId)
                .trace(traceId)
                .authorization(authorization)
                .groupId(groupId)
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
                .trace(traceId)
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
                .trace(traceId)
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
        int credit,
        int padding,
        long groupId)
    {
        final WindowFW window = windowRW.wrap(writeBuffer, 0, writeBuffer.capacity())
                .routeId(routeId)
                .streamId(streamId)
                .trace(traceId)
                .authorization(authorization)
                .credit(credit)
                .padding(padding)
                .groupId(groupId)
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
                .trace(traceId)
                .authorization(authorization)
                .build();

        receiver.accept(reset.typeId(), reset.buffer(), reset.offset(), reset.sizeof());
    }

    private int decodeClientHello(
        TlsServer server,
        long traceId,
        long authorization,
        long groupId,
        int reserved,
        DirectBuffer buffer,
        int offset,
        int progress,
        int limit)
    {
        TlsRecordInfoFW tlsRecordInfo = tlsRecordInfoRO.tryWrap(buffer, progress, limit);

        if (tlsRecordInfo != null)
        {
            final TlsProtocolVersionFW version = tlsRecordInfo.version();
            if (version.major() > 3)
            {
                tlsRecordInfo = null;
                server.cleanupNetwork(traceId);
                server.decoder = decodeIgnoreAll;
            }
        }

        if (tlsRecordInfo != null)
        {
            final int tlsFragmentOffset = tlsRecordInfo.limit();
            final int tlsRecordLimit = tlsFragmentOffset + tlsRecordInfo.length();

            if (limit >= tlsRecordLimit)
            {
                if (tlsRecordInfo.type() == TlsContentType.HANDSHAKE.value())
                {
                    final TlsHandshakeFW tlsHandshake = tlsHandshakeRO.tryWrap(buffer, tlsFragmentOffset, tlsRecordLimit);

                    if (tlsHandshake != null && tlsHandshake.type() == TlsHandshakeType.CLIENT_HELLO.value())
                    {
                        final TlsClientHelloFW tlsClientHello = tlsHandshake.body().get(tlsClientHelloRO::tryWrap);

                        if (tlsClientHello != null)
                        {
                            server.onDecodeClientHello(traceId, authorization, tlsClientHello);
                        }
                    }
                }

                if (server.tlsEngine == null)
                {
                    counters.serverDecodeNoClientHello.getAsLong();
                }
                else
                {
                    try
                    {
                        server.tlsEngine.beginHandshake();
                        server.decoder = decodeHandshake;
                    }
                    catch (SSLException ex)
                    {
                        server.tlsEngine = null;
                    }
                }

                if (server.tlsEngine == null)
                {
                    server.cleanupNetwork(traceId);
                    server.decoder = decodeIgnoreAll;
                }
            }
        }

        return progress;
    }

    private int decodeHandshake(
        TlsServer server,
        long traceId,
        long authorization,
        long groupId,
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
        long groupId,
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
                        final SSLEngineResult result = server.tlsEngine.unwrap(inNetByteBuffer, outAppByteBuffer);
                        final int bytesProduced = result.bytesProduced();
                        final int bytesConsumed = result.bytesConsumed();

                        switch (result.getStatus())
                        {
                        case BUFFER_UNDERFLOW:
                            server.decoder = decodeHandshake;
                            break;
                        case BUFFER_OVERFLOW:
                            assert false;
                            break;
                        case OK:
                            if (bytesProduced == 0)
                            {
                                server.decoder = decodeHandshake;
                            }
                            else
                            {
                                assert bytesConsumed == tlsRecordDataLimit - tlsRecordOffset;
                                assert bytesProduced <= bytesConsumed;

                                tlsUnwrappedDataRW.wrap(buffer, tlsRecordDataOffset, tlsRecordDataLimit)
                                                  .payload(outAppBuffer, 0, bytesProduced)
                                                  .build();

                                server.decoder = decodeNotHandshakingUnwrapped;
                            }
                            break;
                        case CLOSED:
                            assert bytesProduced == 0;
                            server.onDecodeInboundClosed(traceId);
                            server.decoder = decodeHandshake;
                            progress += bytesConsumed;
                            break;
                        }
                    }
                    catch (SSLException ex)
                    {
                        server.cleanupNetwork(traceId);
                        server.decoder = decodeIgnoreAll;
                    }
                }
            }
        }

        return progress;
    }

    private int decodeNotHandshakingUnwrapped(
        TlsServer server,
        long traceId,
        long authorization,
        long groupId,
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
            final TlsServer.TlsStream stream = server.stream.orElse(null);
            final int initialBudget = stream != null ? stream.initialBudget : 0;

            final int bytesOffset = tlsRecordInfo.sizeof();
            final int bytesConsumed = bytesOffset + tlsRecordInfo.length();
            final int bytesProduced = tlsUnwrappedData.length();
            final int bytesReserved = reserved * bytesConsumed / (limit - offset);

            final int bytesPosition = tlsUnwrappedData.info().position();
            final int bytesProgress = bytesOffset + bytesPosition;
            final int bytesLimit = bytesOffset + bytesProduced;

            assert bytesPosition < bytesProduced;
            assert bytesReserved >= bytesOffset;
            assert bytesReserved >= bytesProduced;

            final int bytesReservedOffset =
                    bytesPosition != 0 ? bytesOffset + (bytesReserved - bytesOffset) * bytesPosition / bytesProduced : 0;
            final int bytesReservedLimit = bytesReservedOffset + Math.min(bytesReserved - bytesReservedOffset, initialBudget);

            final int maxBytesReserved = bytesReservedLimit - bytesReservedOffset;

            final int maxBytesLimit = bytesOffset + bytesProduced * bytesReservedLimit / bytesReserved;
            final int maxBytesProduced = maxBytesLimit - bytesProgress;

            assert maxBytesReserved >= maxBytesProduced;
            assert maxBytesLimit <= bytesLimit;

            if (maxBytesProduced > 0)
            {
                final OctetsFW payload = tlsUnwrappedData.payload();

                server.onDecodeUnwrapped(traceId, authorization, groupId, maxBytesReserved,
                        payload.buffer(), payload.offset() + bytesPosition, maxBytesProduced);

                final int newBytesPosition = bytesPosition + maxBytesProduced;
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
        long groupId,
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
        long groupId,
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
        long groupId,
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
                    break;
                case BUFFER_OVERFLOW:
                    assert false;
                    break;
                case OK:
                    assert bytesProduced == 0;
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
            catch (SSLException ex)
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
        long groupId,
        int reserved,
        DirectBuffer buffer,
        int offset,
        int progress,
        int limit)
    {
        server.doEncodeWrap(traceId, groupId, EMPTY_OCTETS);
        server.decoder = decodeHandshake;
        return progress;
    }

    private int decodeIgnoreAll(
        TlsServer server,
        long traceId,
        long authorization,
        long groupId,
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

        final TlsServerNameExtensionFW tlsServerNameExtension = tlsExtension.data().get(tlsServerNameExtensionRO::wrap);
        final TlsVector16FW tlsServerNames = tlsServerNameExtension.serverNames();
        final OctetsFW tlsServerNamesData = tlsServerNames.data();
        final DirectBuffer dataBuffer = tlsServerNamesData.buffer();
        final int dataLimit = tlsServerNamesData.limit();
        for (int dataOffset = tlsServerNamesData.offset(); dataOffset < dataLimit; )
        {
            final TlsServerNameFW tlsServerName = tlsServerNameRO.wrap(dataBuffer, dataOffset, dataLimit);
            if (tlsServerName.kind() == TlsNameType.HOSTNAME.value())
            {
                serverName = tlsServerName.hostname().asString();
                break;
            }
            dataOffset = tlsServerName.limit();
        }

        return serverName;
    }

    private List<String> decodeApplicationLayerProtocolNegotiation(
        TlsExtensionFW tlsExtension)
    {
        final List<String> protocolNames = new ArrayList<>(3);

        final TlsVector16FW tlsExtensionData = tlsExtension.data().get(tlsVector16RO::wrap);
        final OctetsFW tlsAlpnData = tlsExtensionData.data();
        final DirectBuffer dataBuffer = tlsAlpnData.buffer();
        final int dataLimit = tlsAlpnData.limit();
        for (int dataOffset = tlsAlpnData.offset(); dataOffset < dataLimit; )
        {
            final StringFW tlsProtocolName = tlsProtocolNameRO.wrap(dataBuffer, dataOffset, dataLimit);
            final String protocolName = tlsProtocolName.asString();
            if (protocolName != null && !protocolName.isEmpty())
            {
                protocolNames.add(protocolName);
            }
            dataOffset = tlsProtocolName.limit();
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
            long groupId,
            int reserved,
            MutableDirectBuffer buffer,
            int offset,
            int progress,
            int limit);
    }

    private final class TlsServer
    {
        private final MessageConsumer network;
        private final long routeId;
        private final long initialId;
        private final long replyId;
        private long authorization;

        private final Set<Future<?>> handshakeTaskFutures;
        private int handshakeTasks;

        private int decodeSlot = NO_SLOT;
        private int decodeSlotOffset;
        private int decodeSlotReserved;
        private long decodeSlotGroupId;

        private int encodeSlot = NO_SLOT;
        private int encodeSlotOffset;
        private long encodeSlotTraceId;

        private int initialBudget;
        private int replyBudget;
        private int replyPadding;

        private int state;
        private TlsServerDecoder decoder;
        private SSLEngine tlsEngine;
        private TlsStoreInfo tlsStoreInfo;
        private Optional<TlsStream> stream;

        private TlsServer(
            MessageConsumer network,
            long networkRouteId,
            long networkInitialId,
            long authorization)
        {
            this.network = network;
            this.routeId = networkRouteId;
            this.initialId = networkInitialId;
            this.replyId = supplyReplyId.applyAsLong(initialId);
            this.decoder = decodeClientHello;
            this.handshakeTaskFutures = new HashSet<>();
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
            final long traceId = begin.trace();

            authorization = begin.authorization();
            state = TlsState.openInitial(state);

            doNetworkWindow(traceId, decodePool.slotCapacity(), 0, 0L);
            doNetworkBegin(traceId);
        }

        private void onNetworkData(
            DataFW data)
        {
            final long traceId = data.trace();
            final long groupId = data.groupId();

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
                    decodeSlotGroupId = groupId;

                    offset = 0;
                    limit = decodeSlotOffset;
                    reserved = decodeSlotReserved;

                    decodeNetwork(traceId, authorization, groupId, reserved, buffer, offset, limit);
                }

            }
        }

        private void onNetworkEnd(
            EndFW end)
        {
            final long traceId = end.trace();
            final long groupId = decodeSlotGroupId; // TODO

            authorization = end.authorization();
            state = TlsState.closeInitial(state);

            if (decodeSlot == NO_SLOT)
            {
                closeInboundQuietly(tlsEngine);

                cleanupDecodeSlotIfNecessary();

                if (stream.isPresent())
                {
                    stream.get().doApplicationAbortIfNecessary(traceId);
                    doEncodeWrapIfNecessary(traceId, groupId);
                }
                else
                {
                    doEncodeCloseOutbound(traceId, groupId);
                }

                decoder = decodeIgnoreAll;
            }
        }

        private void onNetworkAbort(
            AbortFW abort)
        {
            final long traceId = abort.trace();
            final long groupId = decodeSlotGroupId; // TODO

            authorization = abort.authorization();
            state = TlsState.closeInitial(state);

            closeInboundQuietly(tlsEngine);

            cleanupDecodeSlotIfNecessary();

            stream.ifPresent(s -> s.doApplicationAbortIfNecessary(traceId));
            stream.ifPresent(s -> s.doApplicationResetIfNecessary(traceId));

            doEncodeCloseOutbound(traceId, groupId);
        }

        private void onNetworkReset(
            ResetFW reset)
        {
            final long traceId = reset.trace();

            authorization = reset.authorization();
            state = TlsState.closeReply(state);

            cleanupEncodeSlotIfNecessary();

            closeInboundQuietly(tlsEngine);

            stream.ifPresent(s -> s.doApplicationResetIfNecessary(traceId));
            stream.ifPresent(s -> s.doApplicationAbortIfNecessary(traceId));

            doNetworkReset(traceId);
        }

        private void onNetworkWindow(
            WindowFW window)
        {
            final long traceId = window.trace();
            final int credit = window.credit();
            final int padding = window.padding();
            final long groupId = window.groupId();

            authorization = window.authorization();

            replyBudget += credit;
            replyPadding = padding;

            if (encodeSlot != NO_SLOT)
            {
                final MutableDirectBuffer buffer = encodePool.buffer(encodeSlot);
                final int limit = encodeSlotOffset;

                encodeNetwork(encodeSlotTraceId, authorization, groupId, buffer, 0, limit);
            }

            if (encodeSlot == NO_SLOT)
            {
                stream.ifPresent(s -> s.flushReplyWindow(traceId));
            }
        }

        private void onNetworkSignal(
            SignalFW signal)
        {
            switch ((int) signal.signalId())
            {
            case HANDSHAKE_TASK_COMPLETE_SIGNAL:
                onNetworkSignalHandshakeTaskComplete(signal);
                break;
            }
        }

        private void onNetworkSignalHandshakeTaskComplete(
            SignalFW signal)
        {
            handshakeTasks--;

            if (handshakeTasks == 0)
            {
                handshakeTaskFutures.clear();

                final long traceId = signal.trace();
                final long authorization = signal.authorization();
                final long groupId = decodeSlotGroupId; // TODO: signal.groupId ?

                MutableDirectBuffer buffer = EMPTY_MUTABLE_DIRECT_BUFFER;
                int offset = 0;
                int limit = 0;
                int reserved = 0;

                if (decodeSlot != NO_SLOT)
                {
                    buffer = decodePool.buffer(decodeSlot);
                    limit = decodeSlotOffset;
                    reserved = decodeSlotReserved;
                }

                decodeNetwork(traceId, authorization, groupId, reserved, buffer, offset, limit);
            }
        }

        private void doNetworkBegin(
            long traceId)
        {
            doBegin(network, routeId, replyId, traceId, authorization, EMPTY_EXTENSION);
            router.setThrottle(replyId, this::onNetwork);
            state = TlsState.openReply(state);
        }

        private void doNetworkData(
            long traceId,
            long groupId,
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

            encodeNetwork(traceId, authorization, groupId, buffer, offset, limit);
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

        private void doNetworkAbort(
            long traceId)
        {
            cleanupEncodeSlotIfNecessary();
            doAbort(network, routeId, replyId, traceId, authorization, EMPTY_EXTENSION);
            state = TlsState.closeReply(state);
        }

        private void doNetworkReset(
            long traceId)
        {
            cleanupDecodeSlotIfNecessary();
            doReset(network, routeId, initialId, traceId, authorization);
            state = TlsState.closeInitial(state);
        }

        private void doNetworkWindow(
            long traceId,
            int credit,
            int padding,
            long groupId)
        {
            assert credit > 0;

            initialBudget += credit;

            doWindow(network, routeId, initialId, traceId, authorization, credit, padding, groupId);
        }

        private void flushNetworkWindow(
            long traceId,
            long groupId,
            int maxInitialBudget,
            int initialPadding)
        {
            int initialCredit = maxInitialBudget - initialBudget - decodeSlotOffset;
            if (initialCredit > 0)
            {
                doNetworkWindow(traceId, initialCredit, initialPadding, groupId);
            }

            decodeNetworkIfNecessary(traceId);
        }

        private void encodeNetwork(
            long traceId,
            long authorization,
            long groupId,
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

                assert replyBudget >= 0;

                doData(network, routeId, replyId, traceId, authorization, groupId,
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
            long groupId,
            int reserved,
            MutableDirectBuffer buffer,
            int offset,
            int limit)
        {
            TlsServerDecoder previous = null;
            int progress = offset;
            while (progress <= limit && previous != decoder)
            {
                previous = decoder;
                progress = decoder.decode(this, traceId, authorization, groupId, reserved, buffer, offset, progress, limit);
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
                    decodeSlotReserved = (limit - progress) * reserved / (limit - offset);
                }
            }
            else
            {
                cleanupDecodeSlotIfNecessary();

                if (!stream.isPresent())
                {
                    final int credit = progress - offset;
                    if (credit > 0)
                    {
                        doNetworkWindow(traceId, credit, 0, groupId);
                    }
                }
            }
        }

        private void decodeNetworkIfNecessary(
            long traceId)
        {
            if (decodeSlot != NO_SLOT)
            {
                final long groupId = decodeSlotGroupId; // TODO: signal.groupId ?

                final MutableDirectBuffer buffer = decodePool.buffer(decodeSlot);
                final int offset = 0;
                final int limit = decodeSlotOffset;
                final int reserved = decodeSlotReserved;

                decodeNetwork(traceId, authorization, groupId, reserved, buffer, offset, limit);
            }
        }

        private void onDecodeClientHello(
            long traceId,
            long authorization,
            TlsClientHelloFW tlsClientHello)
        {
            String tlsHostname = null;
            List<String> tlsProtocols = null;

            final OctetsFW extensions = tlsClientHello.extensions();
            final TlsVector16FW tlsExtensions = extensions.get(tlsVector16RO::tryWrap);

            if (tlsExtensions != null)
            {
                final OctetsFW tlsExtensionsData = tlsExtensions.data();
                final DirectBuffer buffer = tlsExtensionsData.buffer();
                final int maxLimit = tlsExtensionsData.limit();

                // TODO: reuse TlsRouter instance, with RouteFW resolve(routeId, authorization) method
                for (int offset = tlsExtensionsData.offset(); offset < maxLimit; )
                {
                    final TlsExtensionFW tlsExtension = tlsExtensionRO.wrap(buffer, offset, maxLimit);
                    final TlsExtensionType tlsExtensionType = TlsExtensionType.valueOf(tlsExtension.type());
                    if (tlsExtensionType != null)
                    {
                        switch (tlsExtensionType)
                        {
                        case SERVER_NAME:
                            tlsHostname = decodeServerName(tlsExtension);
                            break;
                        case APPLICATION_LAYER_PROTOCOL_NEGOTIATION:
                            tlsProtocols = decodeApplicationLayerProtocolNegotiation(tlsExtension);
                            break;
                        default:
                            break;
                        }
                    }
                    offset = tlsExtension.limit();
                }
            }

            final String tlsHostname0 = tlsHostname;
            final List<String> tlsProtocols0 = tlsProtocols;
            final MessagePredicate filter = (t, b, i, l) ->
            {
                final TlsRouteExFW routeEx = wrapRouteEx.apply(t, b, i, l);

                final String hostname = routeEx.hostname().asString();
                final String protocol = routeEx.protocol().asString();

                return (hostname == null || Objects.equals(tlsHostname0, hostname)) &&
                        (protocol == null || tlsProtocols0 == null || tlsProtocols0.contains(protocol));
            };

            final RouteFW route = router.resolve(routeId, authorization, filter, wrapRoute);
            if (route != null)
            {
                final TlsRouteExFW routeEx = route.extension().get(tlsRouteExRO.get()::tryWrap);
                final String store = routeEx != null ? routeEx.store().asString() : null;
                final TlsStoreInfo newTlsStoreInfo = lookupContext.apply(store);
                final SSLContext sslContext = newTlsStoreInfo == null ? null : newTlsStoreInfo.context;

                if (sslContext != null)
                {
                    final SSLEngine newTlsEngine = sslContext.createSSLEngine();
                    newTlsEngine.setUseClientMode(false);
                    if (newTlsStoreInfo.supportsClientAuth)
                    {
                        newTlsEngine.setWantClientAuth(true);
                    }

                    final String protocol = routeEx.protocol().asString();
                    if (protocol != null)
                    {
                        newTlsEngine.setHandshakeApplicationProtocolSelector((ex, ps) -> protocol);
                    }

                    tlsEngine = newTlsEngine;
                    tlsStoreInfo = newTlsStoreInfo;
                }
            }
        }

        private void onDecodeHandshakeNeedTask(
            long traceId,
            long authorization)
        {
            for (Runnable runnable = tlsEngine.getDelegatedTask();
                    runnable != null;
                    runnable = tlsEngine.getDelegatedTask())
            {
                final Future<?> future = executor.execute(runnable, routeId, replyId, HANDSHAKE_TASK_COMPLETE_SIGNAL);
                handshakeTaskFutures.add(future);
                handshakeTasks++;
            }
        }

        private void onDecodeHandshakeFinished(
            long traceId,
            long groupId)
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
                doEncodeCloseOutbound(traceId, groupId);
            }
        }

        private void onDecodeUnwrapped(
            long traceId,
            long authorization,
            long groupId,
            int reserved,
            DirectBuffer buffer,
            int offset,
            int length)
        {
            stream.ifPresent(s -> s.doApplicationData(traceId, groupId, reserved, buffer, offset, length));
        }

        private void onDecodeInboundClosed(
            long traceId)
        {
            assert tlsEngine.isInboundDone();
            stream.ifPresent(s -> s.doApplicationEnd(traceId));
        }

        private void doEncodeWrap(
            long traceId,
            long groupId,
            OctetsFW payload)
        {
            inAppByteBuffer.clear();
            inAppBuffer.putBytes(0, payload.buffer(), payload.offset(), payload.sizeof());
            inAppByteBuffer.limit(payload.sizeof());
            outNetByteBuffer.clear();

            try
            {
                int bytesProduced = 0;

                loop:
                do
                {
                    final SSLEngineResult result = tlsEngine.wrap(inAppByteBuffer, outNetByteBuffer);
                    switch (result.getStatus())
                    {
                    case BUFFER_OVERFLOW:
                    case BUFFER_UNDERFLOW:
                        assert false;
                        break;
                    case CLOSED:
                        assert result.bytesProduced() > 0;
                        bytesProduced += result.bytesProduced();
                        stream.ifPresent(s -> s.doApplicationResetIfNecessary(traceId));
                        break loop;
                    case OK:
                        assert result.bytesProduced() > 0;
                        bytesProduced += result.bytesProduced();
                        if (result.getHandshakeStatus() == HandshakeStatus.FINISHED)
                        {
                            onDecodeHandshakeFinished(traceId, groupId);
                        }
                        break;
                    }
                } while (inAppByteBuffer.hasRemaining());

                doNetworkData(traceId, groupId, outNetBuffer, 0, bytesProduced);
            }
            catch (SSLException ex)
            {
                cleanupNetwork(traceId);
            }
        }

        private void doEncodeCloseOutbound(
            long traceId,
            long groupId)
        {
            if (tlsEngine != null)
            {
                tlsEngine.closeOutbound();
            }
            state = TlsState.closingReply(state);

            doEncodeWrapIfNecessary(traceId, groupId);

            doNetworkEndIfNecessary(traceId);
        }

        private void doEncodeWrapIfNecessary(
            long traceId,
            long groupId)
        {
            if (tlsEngine != null &&
                tlsEngine.getHandshakeStatus() == HandshakeStatus.NEED_WRAP)
            {
                doEncodeWrap(traceId, groupId, EMPTY_OCTETS);
            }
        }

        private void cleanupNetwork(
            long traceId)
        {
            doNetworkReset(traceId);
            doNetworkAbort(traceId);

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

        private final class TlsStream
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
                final long traceId = begin.trace();

                state = TlsState.openReply(state);

                flushReplyWindow(traceId);
            }

            private void onApplicationData(
                DataFW data)
            {
                final long traceId = data.trace();

                replyBudget -= data.reserved();

                if (replyBudget < 0)
                {
                    cleanupApplication(traceId);
                    doNetworkAbort(traceId);
                }
                else if (data.length() > 0)
                {
                    final long groupId = data.groupId();
                    final OctetsFW payload = data.payload();

                    doEncodeWrap(traceId, groupId, payload);
                }
            }

            private void onApplicationEnd(
                EndFW end)
            {
                final long traceId = end.trace();
                final long groupId = 0L; // TODO

                state = TlsState.closeReply(state);
                stream = TlsState.nullIfClosed(state, stream);

                doEncodeCloseOutbound(traceId, groupId);
            }

            private void onApplicationAbort(
                AbortFW abort)
            {
                final long traceId = abort.trace();

                state = TlsState.closeReply(state);
                stream = TlsState.nullIfClosed(state, stream);

                doNetworkAbort(traceId);
            }

            private void onApplicationWindow(
                WindowFW window)
            {
                final long traceId = window.trace();
                final long groupId = window.groupId();

                initialBudget += window.credit();
                initialPadding = window.padding();

                state = TlsState.openInitial(state);

                flushNetworkWindow(traceId, groupId, initialBudget, initialPadding);
            }

            private void onApplicationReset(
                ResetFW reset)
            {
                final long traceId = reset.trace();

                state = TlsState.closeInitial(state);
                stream = TlsState.nullIfClosed(state, stream);

                doNetworkReset(traceId);
            }

            private void doApplicationBegin(
                long traceId,
                String hostname,
                String protocol)
            {
                stream = Optional.of(this);
                state = TlsState.openingInitial(state);

                doBegin(application, routeId, initialId, traceId, authorization,
                    ex -> ex.set((b, o, l) -> tlsBeginExRW.wrap(b, o, l)
                                                          .typeId(tlsTypeId)
                                                          .hostname(hostname)
                                                          .protocol(protocol)
                                                          .build()
                                                          .sizeof()));
                router.setThrottle(initialId, this::onApplication);
            }

            private void doApplicationData(
                long traceId,
                long groupId,
                int reserved,
                DirectBuffer buffer,
                int offset,
                int length)
            {
                assert reserved >= length + initialPadding;

                initialBudget -= reserved;

                if (initialBudget < 0)
                {
                    doNetworkReset(traceId);
                    cleanupApplication(traceId);
                }
                else
                {
                    doData(application, routeId, initialId, traceId, authorization, groupId,
                           reserved, buffer, offset, length, EMPTY_EXTENSION);
                }
            }

            private void doApplicationEnd(
                long traceId)
            {
                state = TlsState.closeInitial(state);
                stream = TlsState.nullIfClosed(state, stream);
                doEnd(application, routeId, initialId, traceId, authorization, EMPTY_EXTENSION);
            }

            private void doApplicationAbort(
                long traceId)
            {
                state = TlsState.closeInitial(state);
                stream = TlsState.nullIfClosed(state, stream);
                doAbort(application, routeId, initialId, traceId, authorization, EMPTY_EXTENSION);
            }

            private void doApplicationReset(
                long traceId)
            {
                state = TlsState.closeReply(state);
                stream = TlsState.nullIfClosed(state, stream);

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

            private void flushReplyWindow(
                long traceId)
            {
                final long groupId = 0L; // TODO

                int replyCredit = TlsServer.this.replyBudget - replyBudget;
                if (replyCredit > 0 && TlsState.replyOpened(state))
                {
                    final int replyPadding = TlsServer.this.replyPadding + replyPaddingAdjust;
                    replyBudget += replyCredit;
                    doWindow(application, routeId, replyId, traceId, authorization,
                             replyCredit, replyPadding, groupId);
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
                    authorization = tlsStoreInfo.authorization(distinguishedName);
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
        catch (SSLException ex)
        {
            // ignore
        }
    }

    private static final class TlsState
    {
        private static final int INITIAL_OPENING = 0x10;
        private static final int INITIAL_OPENED = 0x20;
        private static final int INITIAL_CLOSED = 0x40;
        private static final int REPLY_OPENED = 0x01;
        private static final int REPLY_CLOSING = 0x02;
        private static final int REPLY_CLOSED = 0x04;

        static int openingInitial(
            int state)
        {
            return state | INITIAL_OPENING;
        }

        static int openInitial(
            int state)
        {
            return openingInitial(state) | INITIAL_OPENED;
        }

        static int closeInitial(
            int state)
        {
            return state | INITIAL_CLOSED;
        }

        static boolean initialClosed(
            int state)
        {
            return (state & INITIAL_CLOSED) != 0;
        }

        static int openReply(
            int state)
        {
            return state | REPLY_OPENED;
        }

        static boolean replyOpened(
            int state)
        {
            return (state & REPLY_OPENED) != 0;
        }

        static int closingReply(int state)
        {
            return state | REPLY_CLOSING;
        }

        static int closeReply(
            int state)
        {
            return closingReply(state) | REPLY_CLOSED;
        }

        static boolean replyClosing(
            int state)
        {
            return (state & REPLY_CLOSING) != 0;
        }

        static boolean replyClosed(int state)
        {
            return (state & REPLY_CLOSED) != 0;
        }

        static Optional<TlsServer.TlsStream> nullIfClosed(
            int state,
            Optional<TlsServer.TlsStream> stream)
        {
            return initialClosed(state) && replyClosed(state) ? NULL_STREAM : stream;
        }
    }
}
