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

import static java.util.Objects.requireNonNull;
import static javax.net.ssl.SSLEngineResult.HandshakeStatus.FINISHED;
import static javax.net.ssl.SSLEngineResult.HandshakeStatus.NEED_WRAP;
import static javax.net.ssl.SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING;
import static javax.net.ssl.SSLEngineResult.Status.BUFFER_UNDERFLOW;
import static org.agrona.LangUtil.rethrowUnchecked;
import static org.reaktivity.nukleus.buffer.BufferPool.NO_SLOT;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.Future;
import java.util.function.BiConsumer;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.IntConsumer;
import java.util.function.IntSupplier;
import java.util.function.LongConsumer;
import java.util.function.LongSupplier;
import java.util.function.LongUnaryOperator;

import javax.net.ssl.ExtendedSSLSession;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import javax.net.ssl.SSLException;

import org.agrona.DirectBuffer;
import org.agrona.MutableDirectBuffer;
import org.agrona.collections.Long2ObjectHashMap;
import org.agrona.concurrent.UnsafeBuffer;
import org.reaktivity.nukleus.buffer.BufferPool;
import org.reaktivity.nukleus.function.MessageConsumer;
import org.reaktivity.nukleus.function.MessageFunction;
import org.reaktivity.nukleus.function.MessagePredicate;
import org.reaktivity.nukleus.function.SignalingExecutor;
import org.reaktivity.nukleus.route.RouteManager;
import org.reaktivity.nukleus.stream.StreamFactory;
import org.reaktivity.nukleus.tls.internal.TlsConfiguration;
import org.reaktivity.nukleus.tls.internal.TlsCounters;
import org.reaktivity.nukleus.tls.internal.types.Flyweight;
import org.reaktivity.nukleus.tls.internal.types.OctetsFW;
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
import org.reaktivity.reaktor.internal.buffer.CountingBufferPool;

public final class ServerStreamFactory implements StreamFactory
{
    private static final ByteBuffer EMPTY_BYTE_BUFFER = ByteBuffer.allocate(0);
    private static final int MAXIMUM_HEADER_SIZE = 5 + 20 + 256;    // TODO version + MAC + padding
    private static final LongConsumer NOP = x -> {};
    private static final long FLUSH_HANDSHAKE_SIGNAL = 1L;

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

    private final WindowFW windowRO = new WindowFW();
    private final ResetFW resetRO = new ResetFW();

    private final TlsBeginExFW.Builder tlsBeginExRW = new TlsBeginExFW.Builder();

    private final OctetsFW outNetOctetsRO = new OctetsFW();
    private final OctetsFW outAppOctetsRO = new OctetsFW();

    private final WindowFW.Builder windowRW = new WindowFW.Builder();
    private final ResetFW.Builder resetRW = new ResetFW.Builder();

    private final SignalingExecutor executor;
    private final RouteManager router;
    private final MutableDirectBuffer writeBuffer;
    private final BufferPool networkPool;
    private final BufferPool applicationPool;
    private final LongUnaryOperator supplyInitialId;
    private final LongUnaryOperator supplyReplyId;
    private final LongSupplier supplyCorrelationId;
    private final LongSupplier supplyTrace;
    private final int handshakeBudget;

    private final Long2ObjectHashMap<ServerHandshake> correlations;
    private final MessageFunction<RouteFW> wrapRoute;
    private final ByteBuffer inAppByteBuffer;
    private final ByteBuffer outAppByteBuffer;
    private final ByteBuffer outNetByteBuffer;
    private final DirectBuffer outNetBuffer;
    private final Function<String, SSLContext> lookupContext;

    public ServerStreamFactory(
        TlsConfiguration config,
        SignalingExecutor executor,
        RouteManager router,
        MutableDirectBuffer writeBuffer,
        BufferPool bufferPool,
        LongUnaryOperator supplyInitialId,
        LongUnaryOperator supplyReplyId,
        LongSupplier supplyCorrelationId,
        Long2ObjectHashMap<ServerHandshake> correlations,
        LongSupplier supplyTrace,
        Function<String, SSLContext> lookupContext,
        TlsCounters counters)
    {
        this.supplyTrace = requireNonNull(supplyTrace);
        this.executor = requireNonNull(executor);
        this.lookupContext = requireNonNull(lookupContext);
        this.router = requireNonNull(router);
        this.writeBuffer = requireNonNull(writeBuffer);
        this.networkPool = new CountingBufferPool(
                bufferPool, counters.serverNetworkAcquires, counters.serverNetworkReleases);
        this.applicationPool = new CountingBufferPool(
                bufferPool.duplicate(), counters.serverApplicationAcquires, counters.serverApplicationReleases);
        this.supplyInitialId = requireNonNull(supplyInitialId);
        this.supplyReplyId = requireNonNull(supplyReplyId);
        this.supplyCorrelationId = requireNonNull(supplyCorrelationId);
        this.correlations = requireNonNull(correlations);
        this.handshakeBudget = Math.min(config.handshakeWindowBytes(), networkPool.slotCapacity());

        this.wrapRoute = this::wrapRoute;
        this.inAppByteBuffer = ByteBuffer.allocate(writeBuffer.capacity());
        this.outAppByteBuffer = ByteBuffer.allocate(writeBuffer.capacity());
        this.outNetByteBuffer = ByteBuffer.allocate(writeBuffer.capacity());
        this.outNetBuffer = new UnsafeBuffer(outNetByteBuffer);
    }

    @Override
    public MessageConsumer newStream(
        int msgTypeId,
        DirectBuffer buffer,
        int index,
        int length,
        MessageConsumer throttle)
    {
        final BeginFW begin = beginRO.wrap(buffer, index, index + length);
        final long streamId = begin.streamId();

        MessageConsumer newStream;

        if ((streamId & 0x0000_0000_0000_0001L) != 0L)
        {
            newStream = newAcceptStream(begin, throttle);
        }
        else
        {
            newStream = newConnectReplyStream(begin, throttle);
        }

        return newStream;
    }

    private MessageConsumer newAcceptStream(
        final BeginFW begin,
        final MessageConsumer networkReply)
    {
        final long routeId = begin.routeId();
        final long authorization = begin.authorization();

        final MessagePredicate filter = (t, b, o, l) -> true;
        final RouteFW route = router.resolve(routeId, authorization, filter, wrapRoute);

        MessageConsumer newStream = null;

        if (route != null)
        {
            final TlsRouteExFW tlsRouteExRO = this.tlsRouteExRO.get();
            final TlsRouteExFW routeEx = route.extension().get(tlsRouteExRO::wrap);
            String store = routeEx.store().asString();
            final long networkId = begin.streamId();
            final SSLContext sslContext = lookupContext.apply(store);
            if (sslContext != null)
            {
                final long networkRouteId = begin.routeId();

                final SSLEngine tlsEngine = sslContext.createSSLEngine();
                tlsEngine.setUseClientMode(false);
                // tlsEngine.setNeedClientAuth(true);

                newStream = new ServerAcceptStream(
                        tlsEngine,
                        networkReply,
                        networkRouteId,
                        networkId,
                        authorization)::handleStream;
            }
        }

        return newStream;
    }

    private MessageConsumer newConnectReplyStream(
        final BeginFW begin,
        final MessageConsumer sender)
    {
        final long routeId = begin.routeId();
        final long streamId = begin.streamId();

        return new ServerConnectReplyStream(sender, routeId, streamId)::handleStream;
    }

    private RouteFW wrapRoute(
        int msgTypeId,
        DirectBuffer buffer,
        int index,
        int length)
    {
        final RouteFW routeRO = this.routeRO.get();
        return routeRO.wrap(buffer, index, index + length);
    }

    private final class ServerAcceptStream
    {
        private final SSLEngine tlsEngine;

        private final MessageConsumer networkReply;
        private final long networkRouteId;
        private final long networkId;
        private final long authorization;

        private long networkReplyId;

        private int networkSlot = NO_SLOT;
        private int networkSlotOffset;

        private MessageConsumer applicationTarget;
        private long applicationRouteId;
        private long applicationId;

        private MessageConsumer streamState;
        private volatile ServerHandshake handshake;

        private int networkBudget;
        private int networkPadding;

        private int applicationSlot = NO_SLOT;
        private int applicationSlotOffset;

        private int applicationBudget;
        private int applicationPadding;
        private long applicationCorrelationId;

        private long networkCorrelationId;

        private LongConsumer networkReplyDoneHandler = NOP;
        private long networkTraceId;

        private MessageConsumer applicationReplyThrottle;
        private long applicationReplyId;

        @Override
        public String toString()
        {
            return String.format("%s [networkBudget=%d networkPadding=%d]",
                                 getClass().getSimpleName(), networkBudget, networkPadding);
        }

        private ServerAcceptStream(
            SSLEngine tlsEngine,
            MessageConsumer networkReply,
            long networkRouteId,
            long networkId,
            long authorization)
        {
            this.tlsEngine = tlsEngine;
            this.networkReply = networkReply;
            this.networkRouteId = networkRouteId;
            this.networkId = networkId;
            this.authorization = authorization;
            this.streamState = this::beforeBegin;
        }

        private void handleStream(
            int msgTypeId,
            DirectBuffer buffer,
            int index,
            int length)
        {
            streamState.accept(msgTypeId, buffer, index, length);
        }

        private void beforeBegin(
            int msgTypeId,
            DirectBuffer buffer,
            int index,
            int length)
        {
            if (msgTypeId == BeginFW.TYPE_ID)
            {
                final BeginFW begin = beginRO.wrap(buffer, index, index + length);
                handleBegin(begin);
            }
            else
            {
                doNetworkReset(supplyTrace.getAsLong());
            }
        }

        private void handleBegin(
            BeginFW begin)
        {
            try
            {
                this.networkCorrelationId = begin.correlationId();

                final long newNetworkReplyId = supplyReplyId.applyAsLong(networkId);

                final ServerHandshake newHandshake = new ServerHandshake(tlsEngine, networkReply, networkRouteId, networkId,
                        networkReply, newNetworkReplyId,
                        this::handleStatus,
                        this::handleNetworkReplyDone, this::setNetworkReplyDoneHandler,
                        this::getNetworkBudget, this::getNetworkPadding,
                        this::setNetworkBudget,
                        this::setApplicationReply);

                networkBudget += handshakeBudget;
                doWindow(networkReply, networkRouteId, networkId, networkBudget, networkPadding);

                doBegin(networkReply, networkRouteId, newNetworkReplyId, 0L, networkCorrelationId);
                router.setThrottle(newNetworkReplyId, newHandshake::handleThrottle);

                this.streamState = newHandshake::afterBegin;
                this.networkReplyId = newNetworkReplyId;
                this.handshake = newHandshake;

                tlsEngine.setHandshakeApplicationProtocolSelector(this::selectApplicationProtocol);

                tlsEngine.beginHandshake();
            }
            catch (SSLException ex)
            {
                doNetworkReset(supplyTrace.getAsLong());
                doAbort(networkReply, networkRouteId, networkReplyId, begin.trace(), 0L);
            }
        }

        private String selectApplicationProtocol(
            SSLEngine tlsEngine,
            List<String> clientProtocols)
        {
            final MessagePredicate alpnFilter = (t, b, o, l) ->
            {
                final RouteFW routeRO = ServerStreamFactory.this.routeRO.get();
                final RouteFW route = routeRO.wrap(b, o, o + l);
                ExtendedSSLSession tlsSession = (ExtendedSSLSession) tlsEngine.getHandshakeSession();

                List<SNIServerName> sniServerNames = tlsSession.getRequestedServerNames();
                String hostname = null;
                if (sniServerNames.size() > 0)
                {
                    SNIHostName sniHostName = (SNIHostName) sniServerNames.get(0);
                    hostname = sniHostName.getAsciiName();
                }

                final TlsRouteExFW tlsRouteExRO = ServerStreamFactory.this.tlsRouteExRO.get();
                final TlsRouteExFW routeEx = route.extension().get(tlsRouteExRO::wrap);
                final String routeHostname = routeEx.hostname().asString();
                final String routeProtocol = routeEx.applicationProtocol().asString();

                return (routeHostname == null || Objects.equals(hostname, routeHostname)) &&
                       (routeProtocol == null || clientProtocols.contains(routeProtocol));
            };

            RouteFW route = router.resolve(networkRouteId, authorization, alpnFilter, wrapRoute);
            if (route != null)
            {
                final TlsRouteExFW tlsRouteExRO = ServerStreamFactory.this.tlsRouteExRO.get();
                final TlsRouteExFW routeEx = route.extension().get(tlsRouteExRO::wrap);
                String applicationProtocol = routeEx.applicationProtocol().asString();
                // If the route is default (i.e. no application protocol), need to behave as if there is no ALPN
                // So return an empty String to opt out ALPN negotiation
                return applicationProtocol == null ? "" : applicationProtocol;
            }
            return null;
        }

        private void afterHandshake(
            int msgTypeId,
            DirectBuffer buffer,
            int index,
            int length)
        {
            switch (msgTypeId)
            {
            case DataFW.TYPE_ID:
                final DataFW data = dataRO.wrap(buffer, index, index + length);
                handleData(data);
                break;
            case EndFW.TYPE_ID:
                final EndFW end = endRO.wrap(buffer, index, index + length);
                handleEnd(end);
                break;
            case AbortFW.TYPE_ID:
                final AbortFW abort = abortRO.wrap(buffer, index, index + length);
                handleAbort(abort);
                break;
            default:
                doNetworkReset(supplyTrace.getAsLong());
                break;
            }
        }

        private void handleData(
            DataFW data)
        {
            final int dataLength = data.length();
            networkTraceId = data.trace();

            networkBudget -= dataLength + data.padding();

            if (networkSlot == NO_SLOT)
            {
                networkSlot = networkPool.acquire(networkId);
            }

            try
            {
                if (networkSlot == NO_SLOT || networkBudget < 0)
                {
                    doCloseInbound(tlsEngine);
                    doNetworkReset(supplyTrace.getAsLong());
                    doAbort(applicationTarget, applicationRouteId, applicationId, authorization);
                    networkSlotOffset = 0;
                }
                else
                {
                    final OctetsFW payload = data.payload();
                    final int payloadSize = payload.sizeof();

                    final MutableDirectBuffer inNetBuffer = networkPool.buffer(networkSlot);
                    inNetBuffer.putBytes(networkSlotOffset, payload.buffer(), payload.offset(), payloadSize);
                    networkSlotOffset += payloadSize;

                    unwrapNetworkBufferData();
                }
            }
            catch (SSLException ex)
            {
                doNetworkReset(supplyTrace.getAsLong());
                doAbort(applicationTarget, applicationRouteId, applicationId, authorization);
                networkSlotOffset = 0;
            }
            finally
            {
                if (networkSlotOffset == 0 & networkSlot != NO_SLOT)
                {
                    networkPool.release(networkSlot);
                    networkSlot = NO_SLOT;
                }
            }
        }

        private void unwrapNetworkBufferData() throws SSLException
        {
            assert (networkSlotOffset != 0);

            if (applicationSlot == NO_SLOT)
            {
                applicationSlot = applicationPool.acquire(applicationId);
            }

            try
            {
                if (applicationSlot == NO_SLOT)
                {
                    doCloseInbound(tlsEngine);
                    doNetworkReset(supplyTrace.getAsLong());
                    doAbort(applicationTarget, applicationRouteId, applicationId, authorization);
                    networkSlotOffset = 0;
                }
                else
                {
                    final MutableDirectBuffer inNetBuffer = networkPool.buffer(networkSlot);
                    final ByteBuffer inNetByteBuffer = networkPool.byteBuffer(networkSlot);
                    final int inNetByteBufferPosition = inNetByteBuffer.position();
                    inNetByteBuffer.limit(inNetByteBuffer.position() + networkSlotOffset);

                    loop:
                    while (inNetByteBuffer.hasRemaining() && !tlsEngine.isInboundDone())
                    {
                        final ByteBuffer outAppByteBuffer = applicationPool.byteBuffer(applicationSlot);
                        outAppByteBuffer.position(outAppByteBuffer.position() + applicationSlotOffset);

                        SSLEngineResult result = tlsEngine.unwrap(inNetByteBuffer, outAppByteBuffer);

                        switch (result.getStatus())
                        {
                        case BUFFER_OVERFLOW:
                        case BUFFER_UNDERFLOW:
                            final int totalBytesConsumed = inNetByteBuffer.position() - inNetByteBufferPosition;
                            final int totalBytesRemaining = inNetByteBuffer.remaining();
                            alignSlotBuffer(inNetBuffer, totalBytesConsumed, totalBytesRemaining);
                            networkSlotOffset = totalBytesRemaining;
                            if (networkSlotOffset == networkPool.slotCapacity() &&
                                    result.getStatus() == BUFFER_UNDERFLOW)
                            {
                                networkSlotOffset = 0;
                                doNetworkReset(supplyTrace.getAsLong());
                                doAbort(applicationTarget, applicationRouteId, applicationId, authorization);
                                doCloseInbound(tlsEngine);
                            }
                            else if (totalBytesConsumed == 0)
                            {
                                final int networkCredit =
                                        Math.max(networkPool.slotCapacity() - networkSlotOffset - networkBudget, 0);

                                if (networkCredit > 0)
                                {
                                    networkBudget += networkCredit;
                                    doWindow(networkReply, networkRouteId, networkId, networkCredit, networkPadding);
                                }
                            }
                            break loop;
                        default:
                            networkSlotOffset = 0;
                            applicationSlotOffset += result.bytesProduced();
                            handleStatus(result.getHandshakeStatus(), r -> {});
                            break;
                        }
                    }

                    handleFlushAppData();
                }
            }
            catch (SSLException ex)
            {
                networkSlotOffset = 0;
                applicationSlotOffset = 0;
                throw ex;
            }
            finally
            {
                if (applicationSlotOffset == 0 && applicationSlot != NO_SLOT)
                {
                    applicationPool.release(applicationSlot);
                    applicationSlot = NO_SLOT;
                }
            }
        }

        private void handleEnd(
            EndFW end)
        {
            release();
            if (!tlsEngine.isInboundDone())
            {
                // tlsEngine.closeInbound() without CLOSE_NOTIFY is permitted by specification
                // but invalidates TLS session, preventing future abbreviated TLS handshakes from same client

                doEnd(applicationTarget, applicationRouteId, applicationId, end.trace(), authorization);

                if (!tlsEngine.isOutboundDone())
                {
                    doCloseOutbound(tlsEngine, networkReply, networkRouteId, networkReplyId, supplyTrace.getAsLong(),
                            0, end.authorization(), NOP);
                    if (applicationReplyThrottle != null)
                    {
                        doReset(applicationReplyThrottle, applicationRouteId, applicationReplyId, supplyTrace.getAsLong());
                    }
                    else
                    {
                        correlations.remove(applicationCorrelationId);
                    }
                }
            }
        }

        private void handleAbort(
            AbortFW abort)
        {
            release();
            if (!tlsEngine.isInboundDone())
            {
                doAbort(applicationTarget, applicationRouteId, applicationId, abort.trace(), authorization);

                try
                {
                    doCloseInbound(tlsEngine);
                }
                catch (SSLException ex)
                {
                    if (!tlsEngine.isOutboundDone())
                    {
                        doCloseOutbound(tlsEngine, networkReply, networkRouteId, networkReplyId, supplyTrace.getAsLong(),
                                0, abort.authorization(), NOP);
                        if (applicationReplyThrottle != null)
                        {
                            doReset(applicationReplyThrottle, applicationRouteId, applicationReplyId, supplyTrace.getAsLong());
                        }
                        else
                        {
                            correlations.remove(applicationCorrelationId);
                        }
                    }
                }
            }
        }

        private void handleStatus(
            HandshakeStatus status,
            Consumer<SSLEngineResult> resultHandler)
        {
            loop:
            for (;;)
            {
                switch (status)
                {
                case NEED_TASK:
                    for (Runnable runnable = tlsEngine.getDelegatedTask();
                            runnable != null;
                            runnable = tlsEngine.getDelegatedTask())
                    {
                        if (handshake != null)
                        {
                            handshake.pendingTasks++;
                            Future<?> future = executor.execute(runnable, networkRouteId, networkId, FLUSH_HANDSHAKE_SIGNAL);
                            handshake.pendingFutures.add(future);
                        }
                        else
                        {
                            runnable.run();
                        }
                    }

                    if (handshake != null && handshake.pendingTasks != 0)
                    {
                        break loop;
                    }

                    status = tlsEngine.getHandshakeStatus();
                    break;
                case NEED_WRAP:
                    try
                    {
                        outNetByteBuffer.clear();
                        SSLEngineResult result = tlsEngine.wrap(EMPTY_BYTE_BUFFER, outNetByteBuffer);
                        // resultHandler flushes data to network and adjusts networkReplyBudget
                        resultHandler.accept(result);
                        status = result.getHandshakeStatus();

                        if (status == NEED_WRAP && result.bytesProduced() == 0)
                        {
                            break loop;
                        }
                    }
                    catch (SSLException ex)
                    {
                        // lambda interface cannot throw checked exception
                        rethrowUnchecked(ex);
                    }
                    break;
                case FINISHED:
                    handleFinished();
                    status = tlsEngine.getHandshakeStatus();
                    break;
                default:
                    break loop;
                }
            }
        }

        private void handleFinished()
        {
            ExtendedSSLSession tlsSession = (ExtendedSSLSession) tlsEngine.getSession();
            List<SNIServerName> sniServerNames = tlsSession.getRequestedServerNames();

            String tlsHostname0 = null;
            if (sniServerNames.size() > 0)
            {
                SNIHostName sniHostName = (SNIHostName) sniServerNames.get(0);
                tlsHostname0 = sniHostName.getAsciiName();
            }
            String tlsHostname = tlsHostname0;

            String tlsApplicationProtocol0 = tlsEngine.getApplicationProtocol();
            if (tlsApplicationProtocol0 != null && tlsApplicationProtocol0.isEmpty())
            {
                tlsApplicationProtocol0 = null;
            }
            final String tlsApplicationProtocol = tlsApplicationProtocol0;

            final MessagePredicate filter = (t, b, o, l) ->
            {
                final RouteFW routeRO = ServerStreamFactory.this.routeRO.get();
                final TlsRouteExFW tlsRouteExRO = ServerStreamFactory.this.tlsRouteExRO.get();
                final RouteFW route = routeRO.wrap(b, o, o + l);
                final TlsRouteExFW routeEx = route.extension().get(tlsRouteExRO::wrap);
                final String hostname = routeEx.hostname().asString();
                final String applicationProtocol = routeEx.applicationProtocol().asString();

                return (hostname == null || Objects.equals(tlsHostname, hostname)) &&
                        (applicationProtocol == null || Objects.equals(tlsApplicationProtocol, applicationProtocol));
            };

            final RouteFW route = router.resolve(networkRouteId, authorization, filter, wrapRoute);

            if (route != null)
            {
                final long applicationRouteId = route.correlationId();
                final long applicationInitialId = supplyInitialId.applyAsLong(applicationRouteId);
                final MessageConsumer applicationTarget = router.supplyReceiver(applicationInitialId);

                final long newCorrelationId = supplyCorrelationId.getAsLong();
                correlations.put(newCorrelationId, handshake);


                doTlsBegin(applicationTarget, applicationRouteId, applicationInitialId, networkTraceId, authorization,
                        newCorrelationId, tlsHostname, tlsApplicationProtocol);
                router.setThrottle(applicationInitialId, this::handleThrottle);

                handshake.onFinished();

                if (handshake.networkSlotOffset != 0)
                {
                    this.networkSlot = handshake.networkSlot;
                    this.networkSlotOffset = handshake.networkSlotOffset;
                }

                this.applicationTarget = applicationTarget;
                this.applicationRouteId = applicationRouteId;
                this.applicationId = applicationInitialId;
                this.applicationCorrelationId = newCorrelationId;

                this.streamState = this::afterHandshake;
                this.handshake = null;
            }
            else
            {
                doNetworkReset(supplyTrace.getAsLong());
                doAbort(networkReply, networkRouteId, networkReplyId, 0L);
            }
        }

        private void handleFlushAppData()
        {
            if (applicationSlotOffset > 0)
            {
                final MutableDirectBuffer outAppBuffer = applicationPool.buffer(applicationSlot);

                final int applicationWindow = applicationBudget - applicationPadding;

                final int applicationBytesConsumed = Math.min(applicationSlotOffset, applicationWindow);

                if (applicationBytesConsumed > 0)
                {
                    final OctetsFW outAppOctets = outAppOctetsRO.wrap(outAppBuffer, 0, applicationBytesConsumed);

                    doData(applicationTarget, applicationRouteId, applicationId, networkTraceId, applicationPadding,
                            authorization, outAppOctets);

                    applicationBudget -= applicationBytesConsumed + applicationPadding;

                    applicationSlotOffset -= applicationBytesConsumed;

                }

                if (applicationSlotOffset != 0)
                {
                    alignSlotBuffer(outAppBuffer, applicationBytesConsumed, applicationSlotOffset);
                }

            }

            if (applicationSlotOffset == 0 && tlsEngine.isInboundDone())
            {
                doEnd(applicationTarget, applicationRouteId, applicationId, networkTraceId, authorization);
            }
        }

        private void handleThrottle(
            int msgTypeId,
            DirectBuffer buffer,
            int index,
            int length)
        {
            switch (msgTypeId)
            {
            case WindowFW.TYPE_ID:
                final WindowFW window = windowRO.wrap(buffer, index, index + length);
                handleWindow(window);
                break;
            case ResetFW.TYPE_ID:
                final ResetFW reset = resetRO.wrap(buffer, index, index + length);
                handleReset(reset);
                break;
            default:
                // ignore
                break;
            }
        }

        private void handleWindow(
            WindowFW window)
        {
            applicationBudget += window.credit();
            applicationPadding = networkPadding = window.padding();

            if (applicationSlotOffset != 0)
            {
                try
                {
                    handleFlushAppData();
                }
                finally
                {
                    if (applicationSlotOffset == 0)
                    {
                        applicationPool.release(applicationSlot);
                        applicationSlot = NO_SLOT;
                    }
                }
            }

            if (networkSlotOffset != 0)
            {
                try
                {
                    unwrapNetworkBufferData();
                }
                catch (SSLException ex)
                {
                    doNetworkReset(supplyTrace.getAsLong());
                    doAbort(applicationTarget, applicationRouteId, applicationId, authorization);
                }
                finally
                {
                    if (networkSlotOffset == 0 && networkSlot != NO_SLOT)
                    {
                        networkPool.release(networkSlot);
                        networkSlot = NO_SLOT;
                    }
                }
            }

            final int networkCredit = Math.min(applicationBudget, networkPool.slotCapacity())
                    - networkBudget - networkSlotOffset;

            if (networkCredit > 0)
            {
                networkBudget += networkCredit;
                doWindow(networkReply, networkRouteId, networkId, window.trace(), networkCredit, networkPadding);
            }
        }

        private void handleReset(
            ResetFW reset)
        {
            try
            {
                doCloseInbound(tlsEngine);
            }
            catch (SSLException ex)
            {
                // Ignore and clean up
            }
            finally
            {
                doNetworkReset(reset.trace());
            }
        }

        private void handleNetworkReplyDone(
            long traceId)
        {
            release();
            correlations.remove(applicationCorrelationId);

            if (networkReplyDoneHandler != null)
            {
                networkReplyDoneHandler.accept(traceId);
            }
        }

        private void setNetworkReplyDoneHandler(
            LongConsumer networkReplyDoneHandler)
        {
            this.networkReplyDoneHandler = networkReplyDoneHandler;
        }

        private int getNetworkBudget()
        {
            return networkBudget;
        }

        private int getNetworkPadding()
        {
            return networkPadding;
        }

        private void setNetworkBudget(int networkBudget)
        {
            this.networkBudget = networkBudget;
        }

        private void setApplicationReply(MessageConsumer applicationReplyThrottle, long applicationReplyId)
        {
            this.applicationReplyThrottle = applicationReplyThrottle;
            this.applicationReplyId = applicationReplyId;
        }

        private void doNetworkReset(
            long traceId)
        {
            release();
            doReset(networkReply, networkRouteId, networkId, traceId);
        }

        private void release()
        {
            if (networkSlot != NO_SLOT)
            {
                networkPool.release(networkSlot);
                networkSlot = NO_SLOT;
                networkSlotOffset = 0;
            }
            if (applicationSlot != NO_SLOT)
            {
                applicationPool.release(applicationSlot);
                applicationSlot = NO_SLOT;
                applicationSlotOffset = 0;
            }
        }
    }

    public final class ServerHandshake
    {
        private final SSLEngine tlsEngine;
        private final BiConsumer<HandshakeStatus, Consumer<SSLEngineResult>> statusHandler;

        private final MessageConsumer networkThrottle;
        private final long networkRouteId;
        private final long networkId;
        private final MessageConsumer networkReply;
        private final long networkReplyId;
        private final LongConsumer networkReplyDoneHandler;
        private final Consumer<LongConsumer> networkReplyDoneHandlerConsumer;
        private final List<Future<?>> pendingFutures;

        private int pendingTasks;

        private int networkSlot = NO_SLOT;
        private int networkSlotOffset;

        private int networkReplyBudget;
        private int networkReplyPadding;

        private IntSupplier networkBudgetSupplier;
        private IntSupplier networkPaddingSupplier;
        private IntConsumer networkBudgetConsumer;

        private Consumer<ResetFW> resetHandler;
        private long networkTraceId;
        private BiConsumer<MessageConsumer, Long> applicationReplyConsumer;

        private ServerHandshake(
            SSLEngine tlsEngine,
            MessageConsumer networkThrottle,
            long networkRouteId,
            long networkId,
            MessageConsumer networkReply,
            long networkReplyId,
            BiConsumer<HandshakeStatus, Consumer<SSLEngineResult>> statusHandler,
            LongConsumer networkReplyDoneHandler,
            Consumer<LongConsumer> networkReplyDoneHandlerConsumer,
            IntSupplier networkBudgetSupplier,
            IntSupplier networkPaddingSupplier,
            IntConsumer networkBudgetConsumer,
            BiConsumer<MessageConsumer, Long> applicationReplyConsumer)
        {
            this.tlsEngine = tlsEngine;
            this.statusHandler = statusHandler;
            this.resetHandler = this::handleReset;
            this.networkReplyDoneHandler = networkReplyDoneHandler;

            this.networkThrottle = networkThrottle;
            this.networkRouteId = networkRouteId;
            this.networkId = networkId;
            this.networkReply = networkReply;
            this.networkReplyId = networkReplyId;
            this.networkReplyDoneHandlerConsumer = networkReplyDoneHandlerConsumer;
            this.networkBudgetSupplier = networkBudgetSupplier;
            this.networkPaddingSupplier = networkPaddingSupplier;
            this.networkBudgetConsumer = networkBudgetConsumer;
            this.pendingFutures = new ArrayList<>(3);
            this.applicationReplyConsumer = applicationReplyConsumer;
        }

        private void onFinished()
        {
            this.resetHandler = this::handleResetAfterHandshake;
        }

        private void afterBegin(
            int msgTypeId,
            DirectBuffer buffer,
            int index,
            int length)
        {
            switch (msgTypeId)
            {
            case DataFW.TYPE_ID:
                final DataFW data = dataRO.wrap(buffer, index, index + length);
                handleData(data);
                break;
            case EndFW.TYPE_ID:
                final EndFW end = endRO.wrap(buffer, index, index + length);
                handleEnd(end);
                break;
            case AbortFW.TYPE_ID:
                final AbortFW abort = abortRO.wrap(buffer, index, index + length);
                handleAbort(abort);
                break;
            case SignalFW.TYPE_ID:
                final SignalFW signal = signalRO.wrap(buffer, index, index + length);
                handleSignal(signal);
                break;
            default:
                doNetworkReset(supplyTrace.getAsLong());
                break;
            }
        }

        private void handleData(
            DataFW data)
        {
            networkTraceId = data.trace();

            networkBudgetConsumer.accept(networkBudgetSupplier.getAsInt()
                    - data.length() - data.padding());

            if (networkSlot == NO_SLOT)
            {
                networkSlot = networkPool.acquire(networkId);
            }

            if (networkSlot == NO_SLOT || networkBudgetSupplier.getAsInt() < 0)
            {
                doCloseOutbound(tlsEngine, networkReply, networkRouteId, networkReplyId, networkTraceId, networkReplyPadding,
                        data.authorization(), NOP);
                doNetworkReset(supplyTrace.getAsLong());
            }
            else
            {
                try
                {
                    final OctetsFW payload = data.payload();
                    final int payloadSize = payload.sizeof();

                    final MutableDirectBuffer inNetBuffer = networkPool.buffer(networkSlot);
                    inNetBuffer.putBytes(networkSlotOffset, payload.buffer(), payload.offset(), payloadSize);

                    final ByteBuffer inNetByteBuffer = networkPool.byteBuffer(networkSlot);
                    inNetByteBuffer.limit(inNetByteBuffer.position() + networkSlotOffset + payloadSize);

                    processNetwork(inNetBuffer, inNetByteBuffer);

                    networkBudgetConsumer.accept(networkBudgetSupplier.getAsInt() + data.length());

                    doWindow(networkThrottle, networkRouteId, networkId, data.length(), networkPaddingSupplier.getAsInt());
                }
                catch (SSLException | UnsupportedOperationException ex)
                {
                    networkSlotOffset = 0;
                    doNetworkReset(supplyTrace.getAsLong());
                    doAbort(networkReply, networkRouteId, networkReplyId, networkTraceId, 0L);
                }
                finally
                {
                    if (networkSlotOffset == 0 && networkSlot != NO_SLOT)
                    {
                        networkPool.release(networkSlot);
                        networkSlot = NO_SLOT;
                    }
                }
            }
        }

        private void handleEnd(
            EndFW end)
        {
            release();
            pendingFutures.forEach(f -> f.cancel(true));
            tlsEngine.closeOutbound();
            doAbort(networkReply, networkRouteId, networkReplyId, end.trace(), 0L);
        }

        private void handleAbort(
            AbortFW abort)
        {
            release();
            pendingFutures.forEach(f -> f.cancel(true));
            tlsEngine.closeOutbound();
            doAbort(networkReply, networkRouteId, networkReplyId, abort.trace(), 0L);
        }

        private void handleSignal(
            SignalFW signal)
        {
            assert signal.signalId() == FLUSH_HANDSHAKE_SIGNAL;
            flushHandshake();
        }

        private void processNetwork(
            final MutableDirectBuffer inNetBuffer,
            final ByteBuffer inNetByteBuffer) throws SSLException
        {
            final int inNetByteBufferPosition = inNetByteBuffer.position();

            loop:
            while (inNetByteBuffer.hasRemaining() && !tlsEngine.isInboundDone())
            {
                outAppByteBuffer.rewind();
                HandshakeStatus handshakeStatus = NOT_HANDSHAKING;
                SSLEngineResult.Status status = BUFFER_UNDERFLOW;

                if (pendingTasks == 0 &&
                        tlsEngine.getHandshakeStatus() != NOT_HANDSHAKING &&
                        tlsEngine.getHandshakeStatus() != FINISHED)
                {
                    SSLEngineResult result = tlsEngine.unwrap(inNetByteBuffer, outAppByteBuffer);
                    status = result.getStatus();
                    handshakeStatus = result.getHandshakeStatus();
                }

                if (outAppByteBuffer.position() != 0)
                {
                    doNetworkReset(supplyTrace.getAsLong());
                    doAbort(networkReply, networkRouteId, networkReplyId, 0L);
                    break loop;
                }

                switch (status)
                {
                case BUFFER_UNDERFLOW:
                    final int totalBytesConsumed = inNetByteBuffer.position() - inNetByteBufferPosition;
                    final int totalBytesRemaining = inNetByteBuffer.remaining();
                    alignSlotBuffer(inNetBuffer, totalBytesConsumed, totalBytesRemaining);
                    networkSlotOffset = totalBytesRemaining;
                    break loop;
                default:
                    networkSlotOffset = inNetByteBuffer.remaining();
                    statusHandler.accept(handshakeStatus, this::updateNetworkReplyWindow);
                    break;
                }
            }
        }

        private void updateNetworkReplyWindow(
            SSLEngineResult result)
        {
            final int bytesProduced = result.bytesProduced();
            if (bytesProduced != 0)
            {
                flushNetwork(
                    tlsEngine,
                    result.bytesProduced(),
                    networkReply,
                    networkRouteId,
                    networkReplyId,
                    networkTraceId,
                    0,
                    0L,
                    networkReplyDoneHandler);
                networkReplyBudget -= bytesProduced + networkReplyPadding;
            }
        }

        private void setNetworkThrottle(
            MessageConsumer newNetworkThrottle)
        {
            router.setThrottle(networkReplyId, newNetworkThrottle);


            //doWindow(newNetworkThrottle, networkReplyId, outNetworkWindowBudget, outNetworkWindowPadding);
        }

        private void setNetworkReplyDoneHandler(
            LongConsumer networkReplyDoneHandler)
        {
            networkReplyDoneHandlerConsumer.accept(networkReplyDoneHandler);
        }

        @Override
        public String toString()
        {
            return String.format("%s [networkReplyBudget=%d networkReplyPadding=%d]", getClass().getSimpleName(),
                    networkReplyBudget, networkReplyPadding);
        }

        private void handleThrottle(
            int msgTypeId,
            DirectBuffer buffer,
            int index,
            int length)
        {
            switch (msgTypeId)
            {
            case WindowFW.TYPE_ID:
                final WindowFW window = windowRO.wrap(buffer, index, index + length);
                handleWindow(window);
                break;
            case ResetFW.TYPE_ID:
                final ResetFW reset = resetRO.wrap(buffer, index, index + length);
                resetHandler.accept(reset);
                break;
            default:
                // ignore
                break;
            }
        }

        private void handleWindow(
            WindowFW window)
        {
            networkReplyBudget += window.credit();
            networkReplyPadding = window.padding();

            // tlsEngine.getHandshakeStatus() will block if delegated task is executing
            if (pendingTasks == 0)
            {
                statusHandler.accept(tlsEngine.getHandshakeStatus(), this::updateNetworkReplyWindow);
            }
        }

        private void handleReset(
            ResetFW reset)
        {
            release();
            try
            {
                doCloseInbound(tlsEngine);
            }
            catch (SSLException ex)
            {
                // ignore and clean
            }
            finally
            {
                networkReplyDoneHandler.accept(0);
            }
        }

        private void handleResetAfterHandshake(
            ResetFW reset)
        {
            release();
            networkReplyDoneHandler.accept(0);
        }

        private void flushHandshake()
        {
            pendingTasks--;

            if (pendingTasks == 0)
            {
                pendingFutures.clear();

                if (networkSlot != NO_SLOT)
                {
                    try
                    {
                        final MutableDirectBuffer inNetBuffer = networkPool.buffer(networkSlot);
                        final ByteBuffer inNetByteBuffer = networkPool.byteBuffer(networkSlot);
                        inNetByteBuffer.limit(inNetByteBuffer.position() + networkSlotOffset);
                        processNetwork(inNetBuffer, inNetByteBuffer);
                    }
                    catch (SSLException | UnsupportedOperationException ex)
                    {
                        networkSlotOffset = 0;
                        doNetworkReset(supplyTrace.getAsLong());
                        doAbort(networkReply, networkRouteId, networkReplyId, 0L);
                    }
                    finally
                    {
                        if (networkSlotOffset == 0 && networkSlot != NO_SLOT)
                        {
                            networkPool.release(networkSlot);
                            networkSlot = NO_SLOT;
                        }
                    }
                }
                else
                {
                    try
                    {
                        statusHandler.accept(tlsEngine.getHandshakeStatus(), this::updateNetworkReplyWindow);
                    }
                    catch (Exception ex)
                    {
                        // catches SSLException re-thrown as unchecked
                        doNetworkReset(supplyTrace.getAsLong());
                        doAbort(networkReply, networkRouteId, networkReplyId, 0L);
                    }
                }
            }
        }

        private void doNetworkReset(
            long traceId)
        {
            release();
            doReset(networkThrottle, networkRouteId, networkId, traceId);
        }

        private void release()
        {
            if (networkSlot != NO_SLOT)
            {
                networkPool.release(networkSlot);
                networkSlot = NO_SLOT;
                networkSlotOffset = 0;
            }
        }
    }

    private final class ServerConnectReplyStream
    {
        private final long applicationRouteId;
        private final long applicationReplyId;

        private final LongConsumer handleNetworkReplyDone;

        private MessageConsumer applicationReplyThrottle;

        private int applicationReplyBudget;
        private int networkReplyBudget;
        private int networkReplyPadding;

        private MessageConsumer networkReply;
        private long networkRouteId;
        private long networkReplyId;

        private MessageConsumer streamState;
        private SSLEngine tlsEngine;

        private long applicationReplyTraceId;

        @Override
        public String toString()
        {
            return String.format("%s [applicationBudget=%d]",
                                 getClass().getSimpleName(), applicationReplyBudget);
        }

        private ServerConnectReplyStream(
            MessageConsumer applicationReplyThrottle,
            long applicationRouteId,
            long applicationReplyId)
        {
            this.applicationReplyThrottle = applicationReplyThrottle;
            this.applicationRouteId = applicationRouteId;
            this.applicationReplyId = applicationReplyId;
            this.streamState = this::beforeBegin;
            this.handleNetworkReplyDone = this::handleNetworkReplyDone;
        }

        private void handleStream(
            int msgTypeId,
            DirectBuffer buffer,
            int index,
            int length)
        {
            streamState.accept(msgTypeId, buffer, index, length);
        }

        private void beforeBegin(
            int msgTypeId,
            DirectBuffer buffer,
            int index,
            int length)
        {
            if (msgTypeId == BeginFW.TYPE_ID)
            {
                final BeginFW begin = beginRO.wrap(buffer, index, index + length);
                handleBegin(begin);
            }
            else
            {
                doReset(applicationReplyThrottle, applicationRouteId, applicationReplyId);
            }
        }

        private void afterBegin(
            int msgTypeId,
            DirectBuffer buffer,
            int index,
            int length)
        {
            switch (msgTypeId)
            {
            case DataFW.TYPE_ID:
                final DataFW data = dataRO.wrap(buffer, index, index + length);
                handleData(data);
                break;
            case EndFW.TYPE_ID:
                final EndFW end = endRO.wrap(buffer, index, index + length);
                handleEnd(end);
                break;
            case AbortFW.TYPE_ID:
                final AbortFW abort = abortRO.wrap(buffer, index, index + length);
                handleAbort(abort);
                break;
            default:
                doReset(applicationReplyThrottle, applicationRouteId, applicationReplyId);
                break;
            }
        }

        private void handleBegin(
            BeginFW begin)
        {
            final long correlationId = begin.correlationId();

            final ServerHandshake handshake = correlations.remove(correlationId);
            if (handshake != null)
            {
                this.streamState = this::afterBegin;
                this.tlsEngine = handshake.tlsEngine;
                this.networkReply = handshake.networkReply;
                this.networkRouteId = handshake.networkRouteId;
                this.networkReplyId = handshake.networkReplyId;

                this.networkReplyBudget = handshake.networkReplyBudget;
                this.networkReplyPadding = handshake.networkReplyPadding;
                handshake.applicationReplyConsumer.accept(applicationReplyThrottle, applicationReplyId);
                handshake.setNetworkThrottle(this::handleThrottle);
                sendApplicationReplyWindow(0);
                handshake.setNetworkReplyDoneHandler(handleNetworkReplyDone);
            }
            else
            {
                doReset(applicationReplyThrottle, applicationRouteId, applicationReplyId);
            }
        }

        private void handleData(
            DataFW data)
        {
            applicationReplyTraceId = data.trace();
            applicationReplyBudget -= data.length() + data.padding();

            if (applicationReplyBudget < 0)
            {
                doReset(applicationReplyThrottle, applicationRouteId, applicationReplyId);
                doCloseOutbound(tlsEngine, networkReply, networkRouteId, networkReplyId, applicationReplyTraceId,
                        networkReplyPadding, data.authorization(), handleNetworkReplyDone);
            }
            else
            {
                try
                {
                    final OctetsFW payload = data.payload();

                    // Note: inAppBuffer is emptied by SslEngine.wrap(...)
                    //       so should be able to eliminate copy (stateless)
                    inAppByteBuffer.clear();
                    payload.buffer().getBytes(payload.offset(), inAppByteBuffer, payload.sizeof());
                    inAppByteBuffer.flip();

                    int networkReplyBytesProduced = 0;
                    int networkReplyPaddingProduced = 0;

                    outNetByteBuffer.rewind();

                    while (inAppByteBuffer.hasRemaining() && !tlsEngine.isOutboundDone())
                    {
                        final SSLEngineResult result = tlsEngine.wrap(inAppByteBuffer, outNetByteBuffer);
                        final int bytesProduced = result.bytesProduced();

                        networkReplyBudget -= bytesProduced + networkReplyPadding;
                        networkReplyBytesProduced += bytesProduced;
                        networkReplyPaddingProduced += networkReplyPadding;
                    }

                    flushNetwork(tlsEngine, networkReplyBytesProduced, networkReply, networkRouteId, networkReplyId,
                            applicationReplyTraceId, networkReplyPaddingProduced, data.authorization(),
                            handleNetworkReplyDone);
                }
                catch (SSLException ex)
                {
                    doReset(applicationReplyThrottle, applicationRouteId, applicationReplyId);
                    doAbort(networkReply, networkRouteId, networkReplyId, data.trace(), 0L);
                }
            }

        }

        private void handleEnd(
            EndFW end)
        {
            applicationReplyThrottle = null;
            doCloseOutbound(tlsEngine, networkReply, networkRouteId, networkReplyId, end.trace(), networkReplyPadding,
                    end.authorization(), handleNetworkReplyDone);
        }

        private void handleAbort(
            AbortFW abort)
        {
            tlsEngine.closeOutbound();

            // ABORT is from application reply, so no need to clean that stream
            doAbort(networkReply, networkRouteId, networkReplyId, abort.trace(), 0L);
        }

        private void handleThrottle(
            int msgTypeId,
            DirectBuffer buffer,
            int index,
            int length)
        {
            switch (msgTypeId)
            {
            case WindowFW.TYPE_ID:
                final WindowFW window = windowRO.wrap(buffer, index, index + length);
                handleWindow(window);
                break;
            case ResetFW.TYPE_ID:
                final ResetFW reset = resetRO.wrap(buffer, index, index + length);
                handleReset(reset);
                break;
            default:
                // ignore
                break;
            }
        }

        private void sendApplicationReplyWindow(
            long traceId)
        {
            int applicationReplyCredit = networkReplyBudget - applicationReplyBudget;
            if (applicationReplyCredit > 0)
            {
                applicationReplyBudget += applicationReplyCredit;
                final int applicationReplyPadding = networkReplyPadding + MAXIMUM_HEADER_SIZE +
                        ((applicationReplyBudget - 1) >> 14) * MAXIMUM_HEADER_SIZE;
                doWindow(applicationReplyThrottle, applicationRouteId, applicationReplyId, traceId, applicationReplyCredit,
                        applicationReplyPadding);
            }
        }

        private void handleWindow(
            final WindowFW window)
        {
            networkReplyBudget += window.credit();
            networkReplyPadding = window.padding();
            sendApplicationReplyWindow(window.trace());
        }

        private void handleReset(
            ResetFW reset)
        {
            tlsEngine.closeOutbound();

            // RESET is from network reply, so no need to clean that stream
            handleNetworkReplyDone(reset.trace());
        }

        private void handleNetworkReplyDone(
            long traceId)
        {
            if (applicationReplyThrottle != null)
            {
                doReset(applicationReplyThrottle, applicationRouteId, applicationReplyId, traceId);
            }
        }

    }

    private void flushNetwork(
        SSLEngine tlsEngine,
        int bytesProduced,
        MessageConsumer networkReply,
        long networkRouteId,
        long networkReplyId,
        long traceId,
        int padding,
        long authorization,
        LongConsumer networkReplyDoneHandler)
    {
        if (bytesProduced > 0)
        {
            final OctetsFW outNetOctets = outNetOctetsRO.wrap(outNetBuffer, 0, bytesProduced);
            doData(networkReply, networkRouteId, networkReplyId, traceId, padding, authorization, outNetOctets);
        }

        if (tlsEngine.isOutboundDone())
        {
            doEnd(networkReply, networkRouteId, networkReplyId, traceId, authorization);
            networkReplyDoneHandler.accept(0);      // sends RESET to application reply stream (if not received END)
        }
    }

    private void alignSlotBuffer(
        final MutableDirectBuffer slotBuffer,
        final int bytesConsumed,
        final int bytesRemaining)
    {
        if (bytesConsumed > 0)
        {
            writeBuffer.putBytes(0, slotBuffer, bytesConsumed, bytesRemaining);
            slotBuffer.putBytes(0, writeBuffer, 0, bytesRemaining);
        }
    }

    private void doTlsBegin(
        MessageConsumer receiver,
        long routeId,
        long streamId,
        long traceId,
        long authorization,
        long correlationId,
        String hostname,
        String applicationProtocol)
    {
        final BeginFW begin = beginRW.wrap(writeBuffer, 0, writeBuffer.capacity())
                .routeId(routeId)
                .streamId(streamId)
                .trace(traceId)
                .authorization(authorization)
                .correlationId(correlationId)
                .extension(e -> e.set(visitTlsBeginEx(hostname, applicationProtocol)))
                .build();

        receiver.accept(begin.typeId(), begin.buffer(), begin.offset(), begin.sizeof());
    }

    private Flyweight.Builder.Visitor visitTlsBeginEx(
        String hostname,
        String applicationProtocol)
    {
        return (buffer, offset, limit) ->
            tlsBeginExRW.wrap(buffer, offset, limit)
                        .hostname(hostname)
                        .applicationProtocol(applicationProtocol)
                        .build()
                        .sizeof();
    }

    private void doBegin(
        final MessageConsumer receiver,
        final long routeId,
        final long streamId,
        final long authorization,
        final long correlationId)
    {
        final BeginFW begin = beginRW.wrap(writeBuffer, 0, writeBuffer.capacity())
                .routeId(routeId)
                .streamId(streamId)
                .authorization(authorization)
                .correlationId(correlationId)
                .build();

        receiver.accept(begin.typeId(), begin.buffer(), begin.offset(), begin.sizeof());
    }

    private void doData(
        final MessageConsumer receiver,
        final long routeId,
        final long streamId,
        final long traceId,
        final int padding,
        final long authorization,
        final OctetsFW payload)
    {
        final DataFW data = dataRW.wrap(writeBuffer, 0, writeBuffer.capacity())
                .routeId(routeId)
                .streamId(streamId)
                .trace(traceId)
                .authorization(authorization)
                .groupId(0)
                .padding(padding)
                .payload(payload)
                .build();

        receiver.accept(data.typeId(), data.buffer(), data.offset(), data.sizeof());
    }

    private void doEnd(
        final MessageConsumer receiver,
        final long routeId,
        final long streamId,
        final long traceId,
        final long authorization)
    {
        final EndFW end = endRW.wrap(writeBuffer, 0, writeBuffer.capacity())
                .routeId(routeId)
                .streamId(streamId)
                .trace(traceId)
                .authorization(authorization)
                .build();

        receiver.accept(end.typeId(), end.buffer(), end.offset(), end.sizeof());
    }

    private void doAbort(
        final MessageConsumer receiver,
        final long routeId,
        final long streamId,
        final long traceId,
        final long authorization)
    {
        final AbortFW abort = abortRW.wrap(writeBuffer, 0, writeBuffer.capacity())
                .routeId(routeId)
                .streamId(streamId)
                .trace(traceId)
                .authorization(authorization)
                .build();

        receiver.accept(abort.typeId(), abort.buffer(), abort.offset(), abort.sizeof());
    }

    private void doAbort(
        final MessageConsumer receiver,
        final long routeId,
        final long streamId,
        final long authorization)
    {
        doAbort(receiver, routeId, streamId, supplyTrace.getAsLong(), authorization);
    }

    private void doWindow(
        final MessageConsumer sender,
        final long routeId,
        final long streamId,
        final long traceId,
        final int credit,
        final int padding)
    {
        final WindowFW window = windowRW.wrap(writeBuffer, 0, writeBuffer.capacity())
                .routeId(routeId)
                .streamId(streamId)
                .trace(traceId)
                .credit(credit)
                .padding(padding)
                .groupId(0)
                .build();

        sender.accept(window.typeId(), window.buffer(), window.offset(), window.sizeof());
    }

    private void doWindow(
        final MessageConsumer sender,
        final long routeId,
        final long streamId,
        final int credit,
        final int padding)
    {
        doWindow(sender, routeId, streamId, supplyTrace.getAsLong(), credit, padding);
    }

    private void doReset(
        final MessageConsumer sender,
        final long routeId,
        final long streamId,
        final long traceId)
    {
        final ResetFW reset = resetRW.wrap(writeBuffer, 0, writeBuffer.capacity())
                .routeId(routeId)
                .streamId(streamId)
                .trace(traceId)
                .build();

        sender.accept(reset.typeId(), reset.buffer(), reset.offset(), reset.sizeof());
    }

    private void doReset(
        final MessageConsumer sender,
        final long routeId,
        final long streamId)
    {
        doReset(sender, routeId, streamId, supplyTrace.getAsLong());
    }

    private void doCloseInbound(
        final SSLEngine tlsEngine) throws SSLException
    {
        tlsEngine.closeInbound();
    }

    private void doCloseOutbound(
        SSLEngine tlsEngine,
        MessageConsumer networkReply,
        long networkRouteId,
        long networkReplyId,
        long traceId,
        int padding,
        long authorization,
        LongConsumer networkReplyDoneHandler)
    {
        try
        {
            tlsEngine.closeOutbound();
            outNetByteBuffer.rewind();
            SSLEngineResult result = tlsEngine.wrap(inAppByteBuffer, outNetByteBuffer);
            flushNetwork(tlsEngine, result.bytesProduced(), networkReply, networkRouteId, networkReplyId, traceId, padding,
                    authorization, networkReplyDoneHandler);
        }
        catch (SSLException ex)
        {
            doAbort(networkReply, networkRouteId, networkReplyId, traceId, authorization);
        }
    }
}
