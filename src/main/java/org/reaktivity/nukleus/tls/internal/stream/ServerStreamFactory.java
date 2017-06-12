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

import java.nio.ByteBuffer;
import java.util.List;
import java.util.Objects;
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
import org.reaktivity.nukleus.function.MessageConsumer;
import org.reaktivity.nukleus.function.MessageFunction;
import org.reaktivity.nukleus.function.MessagePredicate;
import org.reaktivity.nukleus.route.RouteHandler;
import org.reaktivity.nukleus.stream.StreamFactory;
import org.reaktivity.nukleus.tls.internal.types.Flyweight;
import org.reaktivity.nukleus.tls.internal.types.OctetsFW;
import org.reaktivity.nukleus.tls.internal.types.control.RouteFW;
import org.reaktivity.nukleus.tls.internal.types.control.TlsRouteExFW;
import org.reaktivity.nukleus.tls.internal.types.stream.BeginFW;
import org.reaktivity.nukleus.tls.internal.types.stream.DataFW;
import org.reaktivity.nukleus.tls.internal.types.stream.EndFW;
import org.reaktivity.nukleus.tls.internal.types.stream.FrameFW;
import org.reaktivity.nukleus.tls.internal.types.stream.ResetFW;
import org.reaktivity.nukleus.tls.internal.types.stream.TlsBeginExFW;
import org.reaktivity.nukleus.tls.internal.types.stream.WindowFW;

public final class ServerStreamFactory implements StreamFactory
{
    private static final ByteBuffer EMPTY_BYTE_BUFFER = ByteBuffer.allocate(0);

    private final RouteFW routeRO = new RouteFW();
    private final TlsRouteExFW tlsRouteExRO = new TlsRouteExFW();

    private final FrameFW frameRO = new FrameFW();

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
    private final LongSupplier supplyStreamId;
    private final LongSupplier supplyCorrelationId;

    private final Long2ObjectHashMap<ServerHandshake> correlations;
    private final MessageFunction<RouteFW> wrapRoute;
    private final ByteBuffer inAppByteBuffer;
    private final ByteBuffer inNetByteBuffer;
    private final ByteBuffer outAppByteBuffer;
    private final ByteBuffer outNetByteBuffer;
    private final DirectBuffer outAppBuffer;
    private final DirectBuffer outNetBuffer;

    public ServerStreamFactory(
        SSLContext context,
        RouteHandler router,
        MutableDirectBuffer writeBuffer,
        LongSupplier supplyStreamId,
        LongSupplier supplyCorrelationId,
        Long2ObjectHashMap<ServerHandshake> correlations)
    {
        this.context = context;
        this.router = router;
        this.writeBuffer = writeBuffer;
        this.supplyStreamId = supplyStreamId;
        this.supplyCorrelationId = supplyCorrelationId;

        this.correlations = correlations;
        this.wrapRoute = this::wrapRoute;
        this.inAppByteBuffer = allocateDirect(writeBuffer.capacity());
        this.inNetByteBuffer = allocateDirect(writeBuffer.capacity());
        this.outAppByteBuffer = allocateDirect(writeBuffer.capacity());
        this.outAppBuffer = new UnsafeBuffer(outAppByteBuffer);
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
        final MessageConsumer throttle)
    {
        final long acceptRef = begin.sourceRef();
        final String acceptName = begin.source().asString();

        final MessagePredicate filter = (t, b, o, l) ->
        {
            final RouteFW route = routeRO.wrap(b, o, l);
            return acceptRef == route.sourceRef() &&
                    acceptName.equals(route.source().asString());
        };

        final RouteFW route = router.resolve(filter, this::wrapRoute);

        MessageConsumer newStream = null;

        if (route != null)
        {
            final long throttleId = begin.streamId();
            final SSLEngine engine = context.createSSLEngine();

            engine.setUseClientMode(false);
//            tlsEngine.setNeedClientAuth(true);

            newStream = new ServerAcceptStream(engine, throttle, throttleId)::handleStream;
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

        private MessageConsumer streamState;
        private ServerHandshake handshake;
        private Consumer<DataFW> decodeState;

        private ServerAcceptStream(
            SSLEngine engine,
            MessageConsumer throttle,
            long throttleId)
        {
            this.tlsEngine = engine;
            this.networkThrottle = throttle;
            this.networkId = throttleId;
            this.streamState = this::beforeBegin;
            this.decodeState = this::decodeHandshake;
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
                final FrameFW frame = frameRO.wrap(buffer, index, index + length);
                handleUnexpected(frame);
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
                decodeState.accept(data);
                break;
            case EndFW.TYPE_ID:
                final EndFW end = endRO.wrap(buffer, index, index + length);
                handleEnd(end);
                break;
            default:
                final FrameFW frame = frameRO.wrap(buffer, index, index + length);
                handleUnexpected(frame);
                break;
            }
        }

        private void handleUnexpected(
            FrameFW frame)
        {
            final long throttleId = frame.streamId();

            doReset(networkThrottle, throttleId);
        }

        private void handleBegin(
            BeginFW begin)
        {
            try
            {
                final String acceptReplyName = requireNonNull(begin.source().asString());
                final long acceptRef = begin.sourceRef();
                final long correlationId = begin.correlationId();

                final long newAcceptReplyId = supplyStreamId.getAsLong();

                final ServerHandshake newHandshake = new ServerHandshake(tlsEngine, acceptReplyName, newAcceptReplyId, acceptRef,
                        correlationId, this::handleThrottle, this::onNetworkFinished);

                newHandshake.openNetwork(correlationId);
                newHandshake.process();

                doWindow(networkThrottle, networkId, 8192, 8192);

                this.handshake = newHandshake;
                this.streamState = this::afterBegin;
            }
            catch (SSLException ex)
            {
                doReset(networkThrottle, networkId);
                LangUtil.rethrowUnchecked(ex);
            }
        }

        private void decodeHandshake(
            DataFW data)
        {
            try
            {
                handshake.unwrap(data);
                handshake.process();

                doWindow(networkThrottle, networkId, data.length(), 1);
            }
            catch (SSLException ex)
            {
                doReset(networkThrottle, networkId);
                LangUtil.rethrowUnchecked(ex);
            }
        }

        private void decodeApplicationData(
            DataFW data)
        {
            try
            {
                handshake.unwrap(data);
                handshake.process();
            }
            catch (SSLException ex)
            {
                doReset(networkThrottle, networkId);
                LangUtil.rethrowUnchecked(ex);
            }
        }

        private void handleEnd(
            EndFW end)
        {
            try
            {
                handshake.onNetworkClosed();
            }
            catch (SSLException ex)
            {
                doReset(networkThrottle, networkId);
                LangUtil.rethrowUnchecked(ex);
            }
        }

        private void onNetworkFinished(
            RouteFW route)
        {
            if (route != null)
            {
                this.decodeState = this::decodeApplicationData;
            }
            else
            {
                doReset(networkThrottle, networkId);
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
            final int writableBytes = window.update();
            final int writableFrames = window.frames();
            final int newWritableBytes = writableBytes; // TODO: consider TLS Record padding

            doWindow(networkThrottle, networkId, newWritableBytes, writableFrames);
        }

        private void handleReset(
            ResetFW reset)
        {
            doReset(networkThrottle, networkId);
        }
    }

    public final class ServerHandshake
    {
        private final SSLEngine tlsEngine;
        private final String networkName;
        private final MessageConsumer networkTarget;
        private final long networkId;
        private final MessageConsumer applicationThrottle;
        private final Consumer<RouteFW> networkFinished;

        private final long acceptRef;
        private final long acceptCorrelationId;

        private HandshakeStatus status;
        private MessageConsumer applicationTarget;
        private long applicationId;

        private int writableBytes;
        private int writableFrames;
        private boolean reset;

        private ServerHandshake(
            SSLEngine engine,
            String acceptReplyName,
            long acceptReplyId,
            long acceptRef,
            long acceptCorrelation,
            MessageConsumer applicationThrottle,
            Consumer<RouteFW> networkFinished)
        {
            this.tlsEngine = engine;
            this.networkName = acceptReplyName;
            this.networkTarget = router.supplyTarget(acceptReplyName);
            this.networkId = acceptReplyId;
            this.acceptRef = acceptRef;
            this.acceptCorrelationId = acceptCorrelation;
            this.applicationThrottle = applicationThrottle;
            this.networkFinished = networkFinished;
            this.status = engine.getHandshakeStatus();
        }

        private void openNetwork(
            long correlationId) throws SSLException
        {
            doBegin(networkTarget, networkId, 0L, correlationId);
            router.setThrottle(networkName, networkId, this::handleThrottle);

            tlsEngine.beginHandshake();
        }

        private void wrap(
            DataFW data) throws SSLException
        {
            final OctetsFW payload = data.payload();

            // Note: inAppBuffer is emptied by SslEngine.wrap(...)
            //       so should be able to eliminate allocation+copy (stateless)
            payload.buffer().getBytes(payload.offset(), inAppByteBuffer, payload.sizeof());
            inAppByteBuffer.flip();

            SSLEngineResult result = tlsEngine.wrap(inAppByteBuffer, outNetByteBuffer);

            flushNetwork();

            inAppByteBuffer.clear();

            status = result.getHandshakeStatus();
        }

        private void unwrap(
            DataFW data) throws SSLException
        {
            final OctetsFW payload = data.payload();

            // Note: inNetByteBuffer is emptied by SslEngine.unwrap(...)
            //       so should be able to eliminate copy (stateless)
            payload.buffer().getBytes(payload.offset(), inNetByteBuffer, payload.sizeof());
            inNetByteBuffer.flip();

            SSLEngineResult result = tlsEngine.unwrap(inNetByteBuffer, outAppByteBuffer);

            inNetByteBuffer.clear();

            flushApplicationData();

            status = result.getHandshakeStatus();
        }

        private HandshakeStatus process() throws SSLException
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
                    // TODO: limit outNetByteBuffer by writableBytes and writableFrames
                    SSLEngineResult result = tlsEngine.wrap(EMPTY_BYTE_BUFFER, outNetByteBuffer);
                    flushNetwork();
                    status = result.getHandshakeStatus();
                    break;
                case FINISHED:
                    handleFinished();
                    status = tlsEngine.getHandshakeStatus();
                    break loop;
                default:
                    break loop;
                }
            }

            return status;
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

                return acceptRef == route.sourceRef() &&
                        networkName.equals(route.source().asString()) &&
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
                correlations.put(newCorrelationId, this);

                final long newApplicationId = supplyStreamId.getAsLong();
                final long applicationRef = route.targetRef();

                doTlsBegin(applicationTarget, newApplicationId, applicationRef, newCorrelationId, tlsHostname);
                router.setThrottle(applicationName, newApplicationId, applicationThrottle);

                this.applicationTarget = applicationTarget;
                this.applicationId = newApplicationId;
            }

            networkFinished.accept(route);
        }

        private void applicationFinished(
            MessageConsumer applicationThrottle,
            long applicationId,
            MessageConsumer networkThrottle)
        {
            if (reset)
            {
                doReset(applicationThrottle, applicationId);
            }
            else
            {
                router.setThrottle(networkName, networkId, networkThrottle);
                doWindow(applicationThrottle, applicationId, writableBytes, writableFrames);
            }
        }

        private void flushApplicationData()
        {
            if (applicationTarget != null)
            {
                outAppByteBuffer.flip();
                if (outAppByteBuffer.hasRemaining())
                {
                    final OctetsFW outAppOctets =
                            outAppOctetsRO.wrap(outAppBuffer, outAppByteBuffer.position(), outAppByteBuffer.remaining());

                    doData(applicationTarget, applicationId, outAppOctets);
                }
                outAppByteBuffer.clear();

                if (tlsEngine.isInboundDone())
                {
                    doEnd(applicationTarget, applicationId);
                }
            }
        }

        private void flushNetwork()
        {
            outNetByteBuffer.flip();
            if (outNetByteBuffer.hasRemaining())
            {
                final OctetsFW outNetOctets = outNetOctetsRO.wrap(outNetBuffer, 0, outNetByteBuffer.remaining());
                doData(networkTarget, networkId, outNetOctets);
            }
            outNetByteBuffer.clear();

            if (tlsEngine.isOutboundDone())
            {
                doEnd(networkTarget, networkId);
            }
        }

        private void onApplicationClosed()
        {
            tlsEngine.closeOutbound();
            flushNetwork();
        }

        private void onNetworkClosed() throws SSLException
        {
            tlsEngine.closeInbound();
        }

        @Override
        public String toString()
        {
            return String.format("[networkName=\"%s\", acceptRef=%d, acceptCorrelationId=%d, networkId=%d]",
                    networkName, acceptRef, acceptCorrelationId, networkId);
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
            this.writableBytes += window.update();
            this.writableFrames += window.frames();

            try
            {
                process();
                flushNetwork();
            }
            catch (SSLException ex)
            {
                LangUtil.rethrowUnchecked(ex);
            }
        }

        private void handleReset(
            ResetFW reset)
        {
            this.reset = true;
        }
    }

    private final class ServerConnectReplyStream
    {
        private final MessageConsumer applicationThrottle;
        private final long applicationId;

        private ServerHandshake handshake;
        private MessageConsumer streamState;

        private ServerConnectReplyStream(
            MessageConsumer throttle,
            long throttleId)
        {
            this.applicationThrottle = throttle;
            this.applicationId = throttleId;
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
                final FrameFW frame = frameRO.wrap(buffer, index, index + length);
                handleUnexpected(frame);
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
                final FrameFW frame = frameRO.wrap(buffer, index, index + length);
                handleUnexpected(frame);
                break;
            }
        }

        private void handleUnexpected(
            FrameFW frame)
        {
            final long throttleId = frame.streamId();
            doReset(applicationThrottle, throttleId);
        }

        private void handleBegin(
            BeginFW begin)
        {
            final long sourceRef = begin.sourceRef();
            final long correlationId = begin.correlationId();

            final ServerHandshake handshake = sourceRef == 0L ? correlations.remove(correlationId) : null;
            if (handshake != null)
            {
                handshake.applicationFinished(applicationThrottle, applicationId, this::handleThrottle);

                this.handshake = handshake;
                this.streamState = this::afterBegin;
            }
            else
            {
                final FrameFW frame = frameRO.wrap(begin.buffer(), begin.offset(), begin.limit());
                handleUnexpected(frame);
            }
        }

        private void handleData(
            DataFW data)
        {
            try
            {
                handshake.wrap(data);

                // TODO: delta between windows
            }
            catch (SSLException ex)
            {
                doReset(applicationThrottle, applicationId);
                LangUtil.rethrowUnchecked(ex);
            }
        }

        private void handleEnd(
            EndFW end)
        {
            handshake.onApplicationClosed();
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
                processWindow(window);
                break;
            case ResetFW.TYPE_ID:
                final ResetFW reset = resetRO.wrap(buffer, index, index + length);
                processReset(reset);
                break;
            default:
                // ignore
                break;
            }
        }

        private void processWindow(
            final WindowFW window)
        {
            final int writableBytes = window.update();
            final int writableFrames = window.frames();
            final int newWritableBytes = writableBytes; // TODO: consider TLS Record padding

            doWindow(applicationThrottle, applicationId, newWritableBytes, writableFrames);
        }

        private void processReset(
            ResetFW reset)
        {
            doReset(applicationThrottle, applicationId);
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
