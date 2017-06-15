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
import static java.util.Arrays.asList;
import static java.util.Objects.requireNonNull;

import java.nio.ByteBuffer;
import java.util.Objects;
import java.util.function.Consumer;
import java.util.function.LongSupplier;

import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;

import org.agrona.DirectBuffer;
import org.agrona.LangUtil;
import org.agrona.MutableDirectBuffer;
import org.agrona.collections.IntIntConsumer;
import org.agrona.collections.Long2ObjectHashMap;
import org.agrona.concurrent.UnsafeBuffer;
import org.reaktivity.nukleus.function.MessageConsumer;
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

public final class ClientStreamFactory implements StreamFactory
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

    private final TlsBeginExFW tlsBeginExRO = new TlsBeginExFW();
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

    private final Long2ObjectHashMap<ClientHandshake> correlations;
    private final ByteBuffer inAppByteBuffer;
    private final ByteBuffer inNetByteBuffer;
    private final ByteBuffer outAppByteBuffer;
    private final ByteBuffer outNetByteBuffer;
    private final DirectBuffer outAppBuffer;
    private final DirectBuffer outNetBuffer;

    public ClientStreamFactory(
        SSLContext context,
        RouteHandler router,
        MutableDirectBuffer writeBuffer,
        LongSupplier supplyStreamId,
        LongSupplier supplyCorrelationId,
        Long2ObjectHashMap<ClientHandshake> correlations)
    {
        this.context = context;
        this.router = router;
        this.writeBuffer = writeBuffer;
        this.supplyStreamId = supplyStreamId;
        this.supplyCorrelationId = supplyCorrelationId;

        this.correlations = correlations;
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
        final OctetsFW extension = begin.extension();
        final TlsBeginExFW tlsBeginEx = extension.get(tlsBeginExRO::wrap);

        final MessagePredicate filter = (t, b, o, l) ->
        {
            final RouteFW route = routeRO.wrap(b, o, l);
            final TlsRouteExFW routeEx = route.extension().get(tlsRouteExRO::wrap);
            final String hostname = routeEx.hostname().asString();
            final String tlsHostname = tlsBeginEx.hostname().asString();

            return acceptRef == route.sourceRef() &&
                    acceptName.equals(route.source().asString()) &&
                    (tlsHostname == null || Objects.equals(tlsHostname, hostname));
        };

        final RouteFW route = router.resolve(filter, this::wrapRoute);

        MessageConsumer newStream = null;

        if (route != null)
        {
            String tlsHostname = tlsBeginEx.hostname().asString();
            if (tlsHostname == null)
            {
                final TlsRouteExFW routeEx = route.extension().get(tlsRouteExRO::wrap);
                tlsHostname = routeEx.hostname().asString();
            }

            final String connectName = route.target().asString();
            final long connectRef = route.targetRef();

            final long throttleId = begin.streamId();

            newStream = new ClientAcceptStream(tlsHostname, throttle, throttleId, connectName, connectRef)::handleStream;
        }

        return newStream;
    }

    private MessageConsumer newConnectReplyStream(
        final BeginFW begin,
        final MessageConsumer throttle)
    {
        final long throttleId = begin.streamId();

        return new ClientConnectReplyStream(throttle, throttleId)::handleStream;
    }

    private RouteFW wrapRoute(
        int msgTypeId,
        DirectBuffer buffer,
        int index,
        int length)
    {
        return routeRO.wrap(buffer, index, index + length);
    }

    private final class ClientAcceptStream
    {
        private final String tlsHostname;
        private final MessageConsumer throttle;
        private final long throttleId;
        private final String connectName;
        private final long connectRef;

        private ClientHandshake handshake;
        private MessageConsumer streamState;

        private ClientAcceptStream(
            String tlsHostname,
            MessageConsumer throttle,
            long throttleId,
            String connectName,
            long connectRef)
        {
            this.tlsHostname = tlsHostname;
            this.throttle = throttle;
            this.throttleId = throttleId;
            this.connectName = connectName;
            this.connectRef = connectRef;
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
            doReset(throttle, throttleId);
        }

        private void handleBegin(
            BeginFW begin)
        {
            try
            {
                final String acceptReplyName = requireNonNull(begin.source().asString());
                final long acceptCorrelationId = begin.correlationId();

                final long newConnectId = supplyStreamId.getAsLong();
                final long newCorrelationId = supplyCorrelationId.getAsLong();
                final long newAcceptReplyId = supplyStreamId.getAsLong();

                final MessageConsumer connectThrottle = this::handleThrottle;
                final IntIntConsumer finishedHandler = this::onHandshakeFinished;
                final Consumer<ResetFW> resetHandler = this::handleReset;

                final SSLEngine tlsEngine = context.createSSLEngine(tlsHostname, -1);
                tlsEngine.setUseClientMode(true);

                final SSLParameters tlsParameters = tlsEngine.getSSLParameters();
                tlsParameters.setEndpointIdentificationAlgorithm("HTTPS");
                if (tlsHostname != null)
                {
                    tlsParameters.setServerNames(asList(new SNIHostName(tlsHostname)));
                }
                tlsEngine.setSSLParameters(tlsParameters);

                final ClientHandshake newHandshake = new ClientHandshake(tlsEngine, connectName, newConnectId, connectThrottle,
                        acceptReplyName, newAcceptReplyId, acceptCorrelationId, finishedHandler, resetHandler);

                correlations.put(newCorrelationId, newHandshake);

                newHandshake.openNetwork(connectRef, newCorrelationId);

                this.handshake = newHandshake;
                this.streamState = this::afterBegin;
            }
            catch (SSLException ex)
            {
                doReset(throttle, throttleId);
                LangUtil.rethrowUnchecked(ex);
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
                doReset(throttle, throttleId);
                LangUtil.rethrowUnchecked(ex);
            }
        }

        private void handleEnd(
            EndFW end)
        {
            handshake.onApplicationClosed();
        }

        private void onHandshakeFinished(
            int writableBytes,
            int writableFrames)
        {
            final int newWritableBytes = writableBytes;   // TODO: consider TLS Record padding
            final int newWritableFrames = writableFrames; // TODO: consider TLS Record frames

            doWindow(throttle, throttleId, newWritableBytes, newWritableFrames);
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
            final int writableBytes = window.update();
            final int writableFrames = window.frames();
            final int newWritableBytes = writableBytes;   // TODO: consider TLS Record padding
            final int newWritableFrames = writableFrames; // TODO: consider TLS Record frames

            doWindow(throttle, throttleId, newWritableBytes, newWritableFrames);
        }

        private void handleReset(
            ResetFW reset)
        {
            doReset(throttle, throttleId);
        }
    }

    public final class ClientHandshake
    {
        private final SSLEngine tlsEngine;
        private final String networkName;
        private final MessageConsumer networkTarget;
        private final long networkId;
        private final MessageConsumer connectThrottle;
        private final String acceptReplyName;
        private final MessageConsumer applicationTarget;
        private final long applicationId;
        private final long acceptCorrelationId;
        private final Consumer<ResetFW> resetHandler;
        private final IntIntConsumer applicationFinished;
        public Runnable networkFinished;

        private HandshakeStatus status;

        private int writableBytes;
        private int writableFrames;

        private ClientHandshake(
            SSLEngine tlsEngine,
            String connectName,
            long connectId,
            MessageConsumer connectThrottle,
            String applicationName,
            long acceptReplyId,
            long acceptCorrelationId,
            IntIntConsumer applicationFinished,
            Consumer<ResetFW> resetHandler)
        {
            this.tlsEngine = tlsEngine;
            this.networkName = connectName;
            this.networkTarget = router.supplyTarget(connectName);
            this.networkId = connectId;
            this.connectThrottle = connectThrottle;
            this.acceptReplyName = applicationName;
            this.applicationTarget = router.supplyTarget(applicationName);
            this.applicationId = acceptReplyId;
            this.acceptCorrelationId = acceptCorrelationId;
            this.applicationFinished = applicationFinished;
            this.resetHandler = resetHandler;
            this.status = tlsEngine.getHandshakeStatus();
        }

        @Override
        public String toString()
        {
            return String.format("[acceptReplyName=\"%s\", acceptCorrelationId=%d]", acceptReplyName, acceptCorrelationId);
        }

        private void openNetwork(
            long connectRef,
            long correlationId) throws SSLException
        {
            doBegin(networkTarget, networkId, connectRef, correlationId);
            router.setThrottle(networkName, networkId, this::handleThrottle);

            tlsEngine.beginHandshake();
            status = tlsEngine.getHandshakeStatus();
        }

        private void wrap(
            DataFW data) throws SSLException
        {
            final OctetsFW payload = data.payload();

            // Note: inAppBuffer is emptied by SslEngine.wrap(...)
            //       so should be able to eliminate allocation+copy (stateless)
            payload.buffer().getBytes(payload.offset(), inAppByteBuffer, payload.sizeof());
            inAppByteBuffer.flip();

            // TODO: limit outNetByteBuffer by writableBytes and writableFrames
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

            this.status = result.getHandshakeStatus();
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
            String peerHost = tlsEngine.getPeerHost();

            doTlsBegin(applicationTarget, applicationId, 0L, acceptCorrelationId, peerHost);

            router.setThrottle(networkName, networkId, connectThrottle);

            networkFinished.run();
            applicationFinished.accept(writableBytes, writableFrames);
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

        private void flushApplicationData()
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

        private void onApplicationClosed()
        {
            tlsEngine.closeOutbound();
            flushNetwork();
        }

        private void onNetworkClosed() throws SSLException
        {
            tlsEngine.closeInbound();
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
            }
            catch (SSLException ex)
            {
                LangUtil.rethrowUnchecked(ex);
            }
        }

        private void handleReset(
            ResetFW reset)
        {
            resetHandler.accept(reset);
        }
    }

    private final class ClientConnectReplyStream
    {
        private final MessageConsumer networkThrottle;
        private final long networkId;

        private MessageConsumer streamState;
        private Consumer<DataFW> decodeState;

        private ClientHandshake handshake;

        private ClientConnectReplyStream(
            MessageConsumer throttle,
            long throttleId)
        {
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
            final long sourceRef = begin.sourceRef();
            final long correlationId = begin.correlationId();

            final ClientHandshake handshake = sourceRef == 0L ? correlations.remove(correlationId) : null;
            if (handshake != null)
            {
                final String acceptReplyName = handshake.acceptReplyName;
                final long acceptReplyId = handshake.applicationId;

                router.setThrottle(acceptReplyName, acceptReplyId, this::handleThrottle);

                handshake.networkFinished = this::onHandshakeFinished;
                this.handshake = handshake;
                this.streamState = this::afterBegin;

                doWindow(networkThrottle, networkId, 8192, 8192);
            }
            else
            {
                final FrameFW frame = frameRO.wrap(begin.buffer(), begin.offset(), begin.limit());
                handleUnexpected(frame);
            }
        }

        private void onHandshakeFinished()
        {
            this.decodeState = this::decodeApplicationData;
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
                handshake.process();
            }
            catch (SSLException ex)
            {
                doReset(networkThrottle, networkId);
                LangUtil.rethrowUnchecked(ex);
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

            // sizeof(payload) -> sizeof(payload + MAC + padding)
            final int newWritableBytes = writableBytes;   // TODO: consider TLS Record padding
            final int newWritableFrames = writableFrames; // TODO: consider TLS Record frames

            doWindow(networkThrottle, networkId, newWritableBytes, newWritableFrames);
        }

        private void handleReset(
            ResetFW reset)
        {
            doReset(networkThrottle, networkId);
        }
    }

    private void doTlsBegin(
        MessageConsumer target,
        long targetId,
        long targetRef,
        long correlationId,
        String hostname)
    {
        final BeginFW begin = beginRW.wrap(writeBuffer, 0, writeBuffer.capacity())
                                     .streamId(targetId)
                                     .source("tls")
                                     .sourceRef(targetRef)
                                     .correlationId(correlationId)
                                     .extension(e -> e.set(visitTlsBeginEx(hostname)))
                                     .build();

        target.accept(begin.typeId(), begin.buffer(), begin.offset(), begin.sizeof());
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
