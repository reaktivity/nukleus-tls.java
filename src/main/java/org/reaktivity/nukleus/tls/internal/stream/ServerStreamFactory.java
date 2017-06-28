/**
 * Copyright 2016-2017 The Reaktivity Project
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

import static java.nio.ByteBuffer.allocateDirect;
import static java.util.Objects.requireNonNull;
import static javax.net.ssl.SSLEngineResult.HandshakeStatus.NEED_WRAP;
import static org.reaktivity.nukleus.buffer.BufferPool.NO_SLOT;

import java.nio.ByteBuffer;
import java.util.List;
import java.util.Objects;
import java.util.function.BiConsumer;
import java.util.function.Consumer;
import java.util.function.LongSupplier;

import javax.net.ssl.ExtendedSSLSession;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import javax.net.ssl.SSLException;

import org.agrona.DirectBuffer;
import org.agrona.LangUtil;
import org.agrona.MutableDirectBuffer;
import org.agrona.collections.Long2ObjectHashMap;
import org.agrona.concurrent.UnsafeBuffer;
import org.reaktivity.nukleus.buffer.BufferPool;
import org.reaktivity.nukleus.function.MessageConsumer;
import org.reaktivity.nukleus.function.MessageFunction;
import org.reaktivity.nukleus.function.MessagePredicate;
import org.reaktivity.nukleus.route.RouteHandler;
import org.reaktivity.nukleus.stream.StreamFactory;
import org.reaktivity.nukleus.tls.internal.TlsConfiguration;
import org.reaktivity.nukleus.tls.internal.types.Flyweight;
import org.reaktivity.nukleus.tls.internal.types.OctetsFW;
import org.reaktivity.nukleus.tls.internal.types.control.RouteFW;
import org.reaktivity.nukleus.tls.internal.types.control.TlsRouteExFW;
import org.reaktivity.nukleus.tls.internal.types.stream.BeginFW;
import org.reaktivity.nukleus.tls.internal.types.stream.DataFW;
import org.reaktivity.nukleus.tls.internal.types.stream.EndFW;
import org.reaktivity.nukleus.tls.internal.types.stream.ResetFW;
import org.reaktivity.nukleus.tls.internal.types.stream.TlsBeginExFW;
import org.reaktivity.nukleus.tls.internal.types.stream.WindowFW;

public final class ServerStreamFactory implements StreamFactory
{
    private static final ByteBuffer EMPTY_BYTE_BUFFER = ByteBuffer.allocate(0);

    private final RouteFW routeRO = new RouteFW();
    private final TlsRouteExFW tlsRouteExRO = new TlsRouteExFW();

    private final BeginFW beginRO = new BeginFW();
    private final DataFW dataRO = new DataFW();
    private final EndFW endRO = new EndFW();

    private final BeginFW.Builder beginRW = new BeginFW.Builder();
    private final DataFW.Builder dataRW = new DataFW.Builder();
    private final EndFW.Builder endRW = new EndFW.Builder();

    private final WindowFW windowRO = new WindowFW();
    private final ResetFW resetRO = new ResetFW();

    private final TlsBeginExFW.Builder tlsBeginExRW = new TlsBeginExFW.Builder();

    private final OctetsFW outNetOctetsRO = new OctetsFW();
    private final OctetsFW outAppOctetsRO = new OctetsFW();

    private final WindowFW.Builder windowRW = new WindowFW.Builder();
    private final ResetFW.Builder resetRW = new ResetFW.Builder();

    private final SSLContext context;
    private final RouteHandler router;
    private final MutableDirectBuffer writeBuffer;
    private final BufferPool networkPool;
    private final BufferPool applicationPool;
    private final LongSupplier supplyStreamId;
    private final LongSupplier supplyCorrelationId;
    private final int handshakeWindowBytes;
    private final int handshakeWindowFrames;

    private final Long2ObjectHashMap<ServerHandshake> correlations;
    private final MessageFunction<RouteFW> wrapRoute;
    private final ByteBuffer inAppByteBuffer;
    private final ByteBuffer outAppByteBuffer;
    private final ByteBuffer outNetByteBuffer;
    private final DirectBuffer outNetBuffer;

    public ServerStreamFactory(
        TlsConfiguration config,
        SSLContext context,
        RouteHandler router,
        MutableDirectBuffer writeBuffer,
        BufferPool bufferPool,
        LongSupplier supplyStreamId,
        LongSupplier supplyCorrelationId,
        Long2ObjectHashMap<ServerHandshake> correlations)
    {
        this.context = requireNonNull(context);
        this.router = requireNonNull(router);
        this.writeBuffer = requireNonNull(writeBuffer);
        this.networkPool = requireNonNull(bufferPool);
        this.applicationPool = requireNonNull(bufferPool).duplicate();
        this.supplyStreamId = requireNonNull(supplyStreamId);
        this.supplyCorrelationId = requireNonNull(supplyCorrelationId);
        this.correlations = requireNonNull(correlations);
        this.handshakeWindowBytes = Math.min(config.handshakeWindowBytes(), networkPool.slotCapacity());
        this.handshakeWindowFrames = config.handshakeWindowFrames();

        this.wrapRoute = this::wrapRoute;
        this.inAppByteBuffer = allocateDirect(writeBuffer.capacity());
        this.outAppByteBuffer = allocateDirect(writeBuffer.capacity());
        this.outNetByteBuffer = allocateDirect(writeBuffer.capacity());
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
        final long sourceRef = begin.sourceRef();

        MessageConsumer newStream = null;

        if (sourceRef == 0L)
        {
            newStream = newConnectReplyStream(begin, throttle);
        }
        else
        {
            newStream = newAcceptStream(begin, throttle);
        }

        return newStream;
    }

    private MessageConsumer newAcceptStream(
        final BeginFW begin,
        final MessageConsumer networkThrottle)
    {
        final long networkRef = begin.sourceRef();
        final String acceptName = begin.source().asString();

        final MessagePredicate filter = (t, b, o, l) ->
        {
            final RouteFW route = routeRO.wrap(b, o, l);
            return networkRef == route.sourceRef() &&
                    acceptName.equals(route.source().asString());
        };

        final RouteFW route = router.resolve(filter, this::wrapRoute);

        MessageConsumer newStream = null;

        if (route != null)
        {
            final long networkId = begin.streamId();
            final SSLEngine tlsEngine = context.createSSLEngine();

            tlsEngine.setUseClientMode(false);
//            tlsEngine.setNeedClientAuth(true);

            newStream = new ServerAcceptStream(tlsEngine, networkThrottle, networkId, networkRef)::handleStream;
        }

        return newStream;
    }

    private MessageConsumer newConnectReplyStream(
        final BeginFW begin,
        final MessageConsumer throttle)
    {
        final long throttleId = begin.streamId();

        return new ServerConnectReplyStream(throttle, throttleId)::handleStream;
    }

    private RouteFW wrapRoute(
        int msgTypeId,
        DirectBuffer buffer,
        int index,
        int length)
    {
        return routeRO.wrap(buffer, index, index + length);
    }

    private final class ServerAcceptStream
    {
        private final SSLEngine tlsEngine;

        private final MessageConsumer networkThrottle;
        private final long networkId;
        private final long networkRef;

        private String networkReplyName;
        private MessageConsumer networkReply;
        private long networkReplyId;

        private int networkSlot = NO_SLOT;
        private int networkSlotOffset;

        private MessageConsumer applicationTarget;
        private long applicationId;

        private MessageConsumer streamState;
        private ServerHandshake handshake;

        private int networkWindowBytes;
        private int networkWindowFrames;
        private int networkWindowBytesAdjustment;
        private int networkWindowFramesAdjustment;

        private int applicationSlot = NO_SLOT;
        private int applicationSlotOffset;

        private int applicationWindowBytes;
        private int applicationWindowFrames;

        @Override
        public String toString()
        {
            return String.format("%s [networkWindowBytes=%d, networkWindowFrames=%d]",
                                 getClass().getSimpleName(), networkWindowBytes, networkWindowFrames);
        }

        private ServerAcceptStream(
            SSLEngine tlsEngine,
            MessageConsumer networkThrottle,
            long networkId,
            long networkRef)
        {
            this.tlsEngine = tlsEngine;
            this.networkThrottle = networkThrottle;
            this.networkId = networkId;
            this.networkRef = networkRef;
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
                doReset(networkThrottle, networkId);
            }
        }

        private void handleBegin(
            BeginFW begin)
        {
            try
            {
                final String networkReplyName = begin.source().asString();
                final long networkCorrelationId = begin.correlationId();

                final MessageConsumer networkReply = router.supplyTarget(networkReplyName);
                final long newNetworkReplyId = supplyStreamId.getAsLong();

                final ServerHandshake newHandshake = new ServerHandshake(tlsEngine, networkThrottle, networkId,
                        networkReplyName, newNetworkReplyId, networkCorrelationId,
                        this::handleStatus, this::handleFlushAppData, this::handleEnd);

                doWindow(networkThrottle, networkId, handshakeWindowBytes, handshakeWindowFrames);

                doBegin(networkReply, newNetworkReplyId, 0L, networkCorrelationId);
                router.setThrottle(networkReplyName, newNetworkReplyId, newHandshake::handleThrottle);

                tlsEngine.beginHandshake();

                this.streamState = newHandshake::afterBegin;
                this.networkReplyName = networkReplyName;
                this.networkReply = networkReply;
                this.networkReplyId = newNetworkReplyId;
                this.handshake = newHandshake;
            }
            catch (SSLException ex)
            {
                doReset(networkThrottle, networkId);
                LangUtil.rethrowUnchecked(ex);
            }
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
            default:
                doReset(networkThrottle, networkId);
                break;
            }
        }

        private void handleData(
            DataFW data)
        {
            networkWindowBytes -= data.length();
            networkWindowFrames--;

            if (networkSlot == NO_SLOT)
            {
                networkSlot = networkPool.acquire(networkId);
            }

            if (applicationSlot == NO_SLOT)
            {
                applicationSlot = applicationPool.acquire(applicationId);
            }

            try
            {
                if (networkSlot == NO_SLOT || networkWindowBytes < 0 || networkWindowFrames < 0 ||
                        applicationSlot == NO_SLOT)
                {
                    doReset(networkThrottle, networkId);
                }
                else
                {
                    if (networkWindowBytes == 0 || networkWindowFrames == 0)
                    {
                        doZeroWindow(networkThrottle, networkId);
                    }

                    final OctetsFW payload = data.payload();
                    final int payloadSize = payload.sizeof();

                    final MutableDirectBuffer inNetBuffer = networkPool.buffer(networkSlot);
                    inNetBuffer.putBytes(networkSlotOffset, payload.buffer(), payload.offset(), payloadSize);
                    final ByteBuffer inNetByteBuffer = networkPool.byteBuffer(networkSlot);
                    final int inNetByteBufferPosition = inNetByteBuffer.position();
                    inNetByteBuffer.limit(inNetByteBuffer.position() + networkSlotOffset + payloadSize);

                    loop:
                    while (inNetByteBuffer.hasRemaining())
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
                            networkWindowFramesAdjustment--;
                            if (networkSlotOffset == networkPool.slotCapacity())
                            {
                                networkSlotOffset = 0;
                                doReset(networkThrottle, networkId);
                            }
                            else
                            {
                                handleFlushNetworkWindow();
                            }
                            break loop;
                        default:
                            networkSlotOffset = 0;
                            applicationSlotOffset += result.bytesProduced();
                            handleFlushAppData();
                            handleStatus(result.getHandshakeStatus(), r -> {});
                            networkWindowBytesAdjustment += result.bytesConsumed() - result.bytesProduced();
                            break;
                        }
                    }

                    if (tlsEngine.isInboundDone())
                    {
                        doEnd(applicationTarget, applicationId);
                    }
                }
            }
            catch (SSLException ex)
            {
                networkSlotOffset = 0;
                applicationSlotOffset = 0;
                doReset(networkThrottle, networkId);
                LangUtil.rethrowUnchecked(ex);
            }
            finally
            {
                if (networkSlotOffset == 0 && networkSlot != NO_SLOT)
                {
                    networkPool.release(networkSlot);
                    networkSlot = NO_SLOT;
                }

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
            try
            {
                tlsEngine.closeInbound();
                handleStatus(tlsEngine.getHandshakeStatus(), r -> {});
            }
            catch (SSLException ex)
            {
                doReset(networkThrottle, networkId);
                LangUtil.rethrowUnchecked(ex);
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
                        runnable.run();
                    }

                    status = tlsEngine.getHandshakeStatus();
                    break;
                case NEED_WRAP:
                    try
                    {
                        outNetByteBuffer.clear();
                        SSLEngineResult result = tlsEngine.wrap(EMPTY_BYTE_BUFFER, outNetByteBuffer);
                        resultHandler.accept(result);
                        flushNetwork(tlsEngine, result.bytesProduced(), networkReply, networkReplyId);
                        status = result.getHandshakeStatus();

                        if (status == NEED_WRAP)
                        {
                            break loop;
                        }
                    }
                    catch (SSLException ex)
                    {
                        LangUtil.rethrowUnchecked(ex);
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

            String peerHost0 = null;
            if (sniServerNames.size() > 0)
            {
                SNIHostName sniHostName = (SNIHostName) sniServerNames.get(0);
                peerHost0 = sniHostName.getAsciiName();
            }
            String peerHost = peerHost0;

            final MessagePredicate filter = (t, b, o, l) ->
            {
                final RouteFW route = routeRO.wrap(b, o, l);
                final TlsRouteExFW routeEx = route.extension().get(tlsRouteExRO::wrap);
                final String hostname = routeEx.hostname().asString();

                return networkRef == route.sourceRef() &&
                        networkReplyName.equals(route.source().asString()) &&
                        (hostname == null || Objects.equals(peerHost, hostname));
            };

            final RouteFW route = router.resolve(filter, wrapRoute);

            if (route != null)
            {
                final String applicationName = route.target().asString();
                final MessageConsumer applicationTarget = router.supplyTarget(applicationName);

                final TlsRouteExFW tlsRouteEx = route.extension().get(tlsRouteExRO::wrap);
                final String tlsHostname = tlsRouteEx.hostname().asString();

                final long newCorrelationId = supplyCorrelationId.getAsLong();
                correlations.put(newCorrelationId, handshake);

                final long newApplicationId = supplyStreamId.getAsLong();
                final long applicationRef = route.targetRef();

                doTlsBegin(applicationTarget, newApplicationId, applicationRef, newCorrelationId, tlsHostname);
                router.setThrottle(applicationName, newApplicationId, this::handleThrottle);

                if (handshake.networkSlotOffset != 0)
                {
                    this.networkSlot = handshake.networkSlot;
                    this.networkSlotOffset = handshake.networkSlotOffset;
                }

                this.networkWindowBytes += handshakeWindowBytes;
                this.networkWindowBytesAdjustment -= handshakeWindowBytes;
                this.networkWindowFrames += handshakeWindowFrames;
                this.networkWindowFramesAdjustment -= handshakeWindowFrames;

                this.applicationTarget = applicationTarget;
                this.applicationId = newApplicationId;
                this.streamState = this::afterHandshake;
                this.handshake = null;
            }
            else
            {
                doReset(networkThrottle, networkId);
            }
        }

        private void handleFlushAppData()
        {
            if (applicationSlotOffset > 0)
            {
                final MutableDirectBuffer outAppBuffer = applicationPool.buffer(applicationSlot);

                final int applicationWindow = applicationWindowFrames == 0 ? 0 : applicationWindowBytes;
                final int applicationBytesConsumed = Math.min(applicationSlotOffset, applicationWindow);

                if (applicationBytesConsumed > 0)
                {
                    final OctetsFW outAppOctets = outAppOctetsRO.wrap(outAppBuffer, 0, applicationBytesConsumed);

                    doData(applicationTarget, applicationId, outAppOctets);

                    applicationWindowBytes -= applicationBytesConsumed;
                    applicationWindowFrames--;
                }

                applicationSlotOffset -= applicationBytesConsumed;

                if (applicationSlotOffset != 0)
                {
                    alignSlotBuffer(outAppBuffer, applicationBytesConsumed, applicationSlotOffset);
                }
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
            final int applicationWindowBytesDelta = window.update();
            final int applicationWindowFramesDelta = window.frames();

            applicationWindowBytes += applicationWindowBytesDelta;
            applicationWindowFrames += applicationWindowFramesDelta;

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

                        if (networkSlotOffset != 0)
                        {
                            handleFlushNetworkWindow();
                        }
                    }
                }
            }

            final int networkWindowBytesDelta = applicationWindowBytesDelta + networkWindowBytesAdjustment;
            final int networkWindowFramesDelta = applicationWindowFramesDelta + networkWindowFramesAdjustment;

            networkWindowBytes += Math.max(networkWindowBytesDelta, 0);
            networkWindowBytesAdjustment = Math.min(networkWindowBytesDelta, 0);

            networkWindowFrames += Math.max(networkWindowFramesDelta, 0);
            networkWindowFramesAdjustment = Math.min(networkWindowFramesDelta, 0);

            if (networkWindowBytesDelta > 0 || networkWindowFramesDelta > 0)
            {
                doWindow(networkThrottle, networkId, Math.max(networkWindowBytesDelta, 0), Math.max(networkWindowFramesDelta, 0));
            }
        }

        private void handleReset(
            ResetFW reset)
        {
            doReset(networkThrottle, networkId);
        }

        private void handleFlushNetworkWindow()
        {
            final int networkReplySlotAvailable = networkPool.slotCapacity() - networkSlotOffset;
            final int networkReplySlotAdjustment = networkWindowBytesAdjustment - networkWindowBytes;
            final int networkWindowBytesUpdate = Math.max(networkReplySlotAvailable + networkReplySlotAdjustment, 0);

            networkWindowBytes += networkWindowBytesUpdate;
            networkWindowBytesAdjustment -= networkWindowBytesUpdate;
            networkWindowFrames++;
            networkWindowFramesAdjustment--;

            doWindow(networkThrottle, networkId, networkWindowBytesUpdate, 1);
        }
    }

    public final class ServerHandshake
    {
        private final SSLEngine tlsEngine;
        private final BiConsumer<HandshakeStatus, Consumer<SSLEngineResult>> statusHandler;
        private final Runnable flushHandler;
        private final Consumer<EndFW> endHandler;

        private final MessageConsumer networkThrottle;
        private final long networkId;
        private final String networkReplyName;
        private final long networkReplyId;
        private final long networkCorrelationId;

        private int networkSlot = NO_SLOT;
        private int networkSlotOffset;

        private int outNetworkWindowBytes;
        private int outNetworkWindowFrames;

        private ServerHandshake(
            SSLEngine tlsEngine,
            MessageConsumer networkThrottle,
            long networkId,
            String networkReplyName,
            long networkReplyId,
            long networkCorrelationId,
            BiConsumer<HandshakeStatus, Consumer<SSLEngineResult>> statusHandler,
            Runnable flushHandler,
            Consumer<EndFW> endHandler)
        {
            this.tlsEngine = tlsEngine;
            this.statusHandler = statusHandler;
            this.flushHandler = flushHandler;
            this.endHandler = endHandler;

            this.networkThrottle = networkThrottle;
            this.networkId = networkId;
            this.networkReplyName = networkReplyName;
            this.networkReplyId = networkReplyId;
            this.networkCorrelationId = networkCorrelationId;
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
            default:
                doReset(networkThrottle, networkId);
                break;
            }
        }

        private void handleData(
            DataFW data)
        {
            if (networkSlot == NO_SLOT)
            {
                networkSlot = networkPool.acquire(networkId);
            }

            if (networkSlot == NO_SLOT)
            {
                doReset(networkThrottle, networkId);
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
                    final int inNetByteBufferPosition = inNetByteBuffer.position();
                    inNetByteBuffer.limit(inNetByteBuffer.position() + networkSlotOffset + payloadSize);

                    loop:
                    while (inNetByteBuffer.hasRemaining())
                    {
                        outAppByteBuffer.rewind();
                        SSLEngineResult result = tlsEngine.unwrap(inNetByteBuffer, outAppByteBuffer);

                        if (outAppByteBuffer.position() != 0)
                        {
                            doReset(networkThrottle, networkId);
                            break loop;
                        }

                        switch (result.getStatus())
                        {
                        case BUFFER_UNDERFLOW:
                            final int totalBytesConsumed = inNetByteBuffer.position() - inNetByteBufferPosition;
                            final int totalBytesRemaining = inNetByteBuffer.remaining();
                            alignSlotBuffer(inNetBuffer, totalBytesConsumed, totalBytesRemaining);
                            networkSlotOffset = totalBytesRemaining;
                            break loop;
                        default:
                            networkSlotOffset = 0;
                            flushHandler.run();
                            final HandshakeStatus handshakeStatus = result.getHandshakeStatus();
                            statusHandler.accept(handshakeStatus, this::updateNetworkWindow);
                            break;
                        }
                    }

                    doWindow(networkThrottle, networkId, data.length(), 1);
                }
                catch (SSLException ex)
                {
                    networkSlotOffset = 0;
                    doReset(networkThrottle, networkId);
                    LangUtil.rethrowUnchecked(ex);
                }
                finally
                {
                    if (networkSlotOffset == 0)
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
            endHandler.accept(end);
        }

        private void updateNetworkWindow(
            SSLEngineResult result)
        {
            final int bytesProduced = result.bytesProduced();
            if (bytesProduced != 0)
            {
                outNetworkWindowBytes -= bytesProduced;
                outNetworkWindowFrames--;
            }
        }

        private void setNetworkThrottle(
            MessageConsumer newNetworkThrottle)
        {
            router.setThrottle(networkReplyName, networkReplyId, newNetworkThrottle);

            // TODO: improve heuristic to account for TLS protocol framing bytes
            doWindow(newNetworkThrottle, networkReplyId, outNetworkWindowBytes * 80 / 100, outNetworkWindowFrames);
        }

        @Override
        public String toString()
        {
            return String.format("%s [windowBytes=%d, windowFrames=%d]",
                                 getClass().getSimpleName(), outNetworkWindowBytes, outNetworkWindowFrames);
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
            this.outNetworkWindowBytes += window.update();
            this.outNetworkWindowFrames += window.frames();

            statusHandler.accept(tlsEngine.getHandshakeStatus(), this::updateNetworkWindow);
        }

        private void handleReset(
            ResetFW reset)
        {
            doReset(networkThrottle, networkReplyId);
            correlations.remove(networkCorrelationId);
        }
    }

    private final class ServerConnectReplyStream
    {
        private final MessageConsumer applicationReplyThrottle;
        private final long applicationReplyId;

        private int applicationWindowBytes;
        private int applicationWindowBytesAdjustment;
        private int applicationWindowFrames;
        private int applicationWindowFramesAdjustment;

        private MessageConsumer networkReply;
        private long networkReplyId;

        private MessageConsumer streamState;
        private SSLEngine tlsEngine;
        private BiConsumer<HandshakeStatus, Consumer<SSLEngineResult>> statusHandler;

        @Override
        public String toString()
        {
            return String.format("%s [applicationWindowBytes=%d, applicationWindowFrames=%d]",
                                 getClass().getSimpleName(), applicationWindowBytes, applicationWindowFrames);
        }

        private ServerConnectReplyStream(
            MessageConsumer applicationReplyThrottle,
            long applicationReplyId)
        {
            this.applicationReplyThrottle = applicationReplyThrottle;
            this.applicationReplyId = applicationReplyId;
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
                doReset(applicationReplyThrottle, applicationReplyId);
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
            default:
                doReset(applicationReplyThrottle, applicationReplyId);
                break;
            }
        }

        private void handleBegin(
            BeginFW begin)
        {
            final long sourceRef = begin.sourceRef();
            final long correlationId = begin.correlationId();

            final ServerHandshake handshake = sourceRef == 0L ? correlations.remove(correlationId) : null;
            if (handshake != null)
            {
                this.streamState = this::afterBegin;
                this.tlsEngine = handshake.tlsEngine;
                this.networkReply = router.supplyTarget(handshake.networkReplyName);
                this.networkReplyId = handshake.networkReplyId;
                this.statusHandler = handshake.statusHandler;

                handshake.setNetworkThrottle(this::handleThrottle);
            }
            else
            {
                doReset(applicationReplyThrottle, applicationReplyId);
            }
        }

        private void handleData(
            DataFW data)
        {
            applicationWindowBytes -= data.length();
            applicationWindowFrames--;

            if (applicationWindowBytes < 0 || applicationWindowFrames < 0)
            {
                doReset(applicationReplyThrottle, applicationReplyId);
            }
            else
            {
                if (applicationWindowBytes == 0 || applicationWindowFrames == 0)
                {
                    doZeroWindow(applicationReplyThrottle, applicationReplyId);
                }

                try
                {
                    final OctetsFW payload = data.payload();

                    // Note: inAppBuffer is emptied by SslEngine.wrap(...)
                    //       so should be able to eliminate copy (stateless)
                    inAppByteBuffer.clear();
                    payload.buffer().getBytes(payload.offset(), inAppByteBuffer, payload.sizeof());
                    inAppByteBuffer.flip();

                    while (inAppByteBuffer.hasRemaining() && !tlsEngine.isOutboundDone())
                    {
                        outNetByteBuffer.rewind();
                        SSLEngineResult result = tlsEngine.wrap(inAppByteBuffer, outNetByteBuffer);
                        updateNetworkWindow(result);
                        flushNetwork(tlsEngine, result.bytesProduced(), networkReply, networkReplyId);
                        statusHandler.accept(result.getHandshakeStatus(), this::updateNetworkWindow);
                    }

                    applicationWindowFramesAdjustment++;
                }
                catch (SSLException ex)
                {
                    doReset(applicationReplyThrottle, applicationReplyId);
                    LangUtil.rethrowUnchecked(ex);
                }
            }
        }

        private void handleEnd(
            EndFW end)
        {
            tlsEngine.closeOutbound();
            statusHandler.accept(tlsEngine.getHandshakeStatus(), this::updateNetworkWindow);
        }

        private void updateNetworkWindow(
            SSLEngineResult result)
        {
            applicationWindowBytesAdjustment += result.bytesConsumed() - result.bytesProduced();
            applicationWindowBytesAdjustment--;
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
            final WindowFW window)
        {
            final int networkWindowBytesDelta = window.update();
            final int networkWindowFramesDelta = window.frames();

            final int applicationWindowBytesDelta = networkWindowBytesDelta + applicationWindowBytesAdjustment;
            final int applicationWindowFramesDelta = networkWindowFramesDelta + applicationWindowFramesAdjustment;

            applicationWindowBytes += Math.max(applicationWindowBytesDelta, 0);
            applicationWindowBytesAdjustment = Math.abs(Math.min(applicationWindowBytesDelta, 0));

            applicationWindowFrames += Math.max(applicationWindowFramesDelta, 0);
            applicationWindowFramesAdjustment = Math.abs(Math.min(applicationWindowFramesDelta, 0));

            if (applicationWindowBytesDelta > 0 || applicationWindowFramesDelta > 0)
            {
                doWindow(applicationReplyThrottle, applicationReplyId,
                         applicationWindowBytesDelta, Math.max(applicationWindowFramesDelta, 0));
            }
        }

        private void handleReset(
            ResetFW reset)
        {
            doReset(applicationReplyThrottle, applicationReplyId);
        }
    }

    private void flushNetwork(
        SSLEngine tlsEngine,
        int bytesProduced,
        MessageConsumer networkReply,
        long networkReplyId)
    {
        if (bytesProduced > 0)
        {
            final OctetsFW outNetOctets = outNetOctetsRO.wrap(outNetBuffer, 0, bytesProduced);
            doData(networkReply, networkReplyId, outNetOctets);
        }

        if (tlsEngine.isOutboundDone())
        {
            doEnd(networkReply, networkReplyId);
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
        MessageConsumer connect,
        long connectId,
        long connectRef,
        long correlationId,
        String hostname)
    {
        final BeginFW begin = beginRW.wrap(writeBuffer, 0, writeBuffer.capacity())
                                     .streamId(connectId)
                                     .source("tls")
                                     .sourceRef(connectRef)
                                     .correlationId(correlationId)
                                     .extension(e -> e.set(visitTlsBeginEx(hostname)))
                                     .build();

        connect.accept(begin.typeId(), begin.buffer(), begin.offset(), begin.sizeof());
    }

    private Flyweight.Builder.Visitor visitTlsBeginEx(
        String hostname)
    {
        return (buffer, offset, limit) ->
            tlsBeginExRW.wrap(buffer, offset, limit)
                       .hostname(hostname)
                       .build()
                       .sizeof();
    }

    private void doBegin(
        final MessageConsumer target,
        final long targetId,
        final long targetRef,
        final long correlationId)
    {
        final BeginFW begin = beginRW.wrap(writeBuffer, 0, writeBuffer.capacity())
                .streamId(targetId)
                .source("tls")
                .sourceRef(targetRef)
                .correlationId(correlationId)
                .extension(e -> e.reset())
                .build();

        target.accept(begin.typeId(), begin.buffer(), begin.offset(), begin.sizeof());
    }

    private void doData(
        final MessageConsumer target,
        final long targetId,
        final OctetsFW payload)
    {
        final DataFW data = dataRW.wrap(writeBuffer, 0, writeBuffer.capacity())
                .streamId(targetId)
                .payload(p -> p.set(payload.buffer(), payload.offset(), payload.sizeof()))
                .extension(e -> e.reset())
                .build();

        target.accept(data.typeId(), data.buffer(), data.offset(), data.sizeof());
    }

    private void doEnd(
        final MessageConsumer target,
        final long targetId)
    {
        final EndFW end = endRW.wrap(writeBuffer, 0, writeBuffer.capacity())
                .streamId(targetId)
                .extension(e -> e.reset())
                .build();

        target.accept(end.typeId(), end.buffer(), end.offset(), end.sizeof());
    }

    private void doWindow(
        final MessageConsumer throttle,
        final long throttleId,
        final int writableBytes,
        final int writableFrames)
    {
        final WindowFW window = windowRW.wrap(writeBuffer, 0, writeBuffer.capacity())
                .streamId(throttleId)
                .update(writableBytes)
                .frames(writableFrames)
                .build();

        throttle.accept(window.typeId(), window.buffer(), window.offset(), window.sizeof());
    }

    private void doZeroWindow(
        final MessageConsumer throttle,
        final long throttleId)
    {
        final WindowFW window = windowRW.wrap(writeBuffer, 0, writeBuffer.capacity())
                .streamId(throttleId)
                .update(0)
                .frames(0)
                .build();

        throttle.accept(window.typeId(), window.buffer(), window.offset(), window.sizeof());
    }

    private void doReset(
        final MessageConsumer throttle,
        final long throttleId)
    {
        final ResetFW reset = resetRW.wrap(writeBuffer, 0, writeBuffer.capacity())
               .streamId(throttleId)
               .build();

        throttle.accept(reset.typeId(), reset.buffer(), reset.offset(), reset.sizeof());
    }
}
