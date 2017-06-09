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
import java.util.function.UnaryOperator;

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
        final String tlsHostname = tlsBeginEx.hostname().asString();

        final MessagePredicate filter = (t, b, o, l) ->
        {
            final RouteFW route = routeRO.wrap(b, o, l);
            final TlsRouteExFW routeEx = route.extension().get(tlsRouteExRO::wrap);
            final String hostname = routeEx.hostname().asString();

            return acceptRef == route.sourceRef() &&
                    acceptName.equals(route.source().asString()) &&
                    Objects.equals(tlsHostname, hostname);
        };

        final RouteFW route = router.resolve(filter, this::wrapRoute);

        MessageConsumer newStream = null;

        if (route != null)
        {
            final long throttleId = begin.streamId();

            final SSLEngine engine = context.createSSLEngine(tlsHostname, -1);
            engine.setUseClientMode(true);

            SSLParameters tlsParameters = engine.getSSLParameters();
            tlsParameters.setEndpointIdentificationAlgorithm("HTTPS");
            tlsParameters.setServerNames(asList(new SNIHostName(tlsHostname)));
            engine.setSSLParameters(tlsParameters);

            final String connectName = route.target().asString();
            final long connectRef = route.targetRef();

            newStream = new ClientAcceptStream(engine, throttle, throttleId, connectName, connectRef)::handleStream;
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
        private final MessageConsumer throttle;
        private final long throttleId;
        private final SSLEngine engine;
        private final String connectName;
        private final MessageConsumer connectTarget;
        private final long connectRef;

        private long connectId;
        private MessageConsumer streamState;

        private ClientAcceptStream(
            SSLEngine engine,
            MessageConsumer throttle,
            long throttleId,
            String connectName,
            long connectRef)
        {
            this.engine = engine;
            this.throttle = throttle;
            this.throttleId = throttleId;
            this.connectName = connectName;
            this.connectTarget = router.supplyTarget(connectName);
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
                processBegin(begin);
            }
            else
            {
                final FrameFW frame = frameRO.wrap(buffer, index, index + length);
                processUnexpected(frame);
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
                processData(data);
                break;
            case EndFW.TYPE_ID:
                final EndFW end = endRO.wrap(buffer, index, index + length);
                processEnd(end);
                break;
            default:
                final FrameFW frame = frameRO.wrap(buffer, index, index + length);
                processUnexpected(frame);
                break;
            }
        }

        private void processUnexpected(
            FrameFW frame)
        {
            final long throttleId = frame.streamId();
            doReset(throttle, throttleId);
        }

        private void processBegin(
            BeginFW begin)
        {
            try
            {
                final String acceptName = requireNonNull(begin.source().asString());
                final long acceptCorrelationId = begin.correlationId();

                final long newConnectId = supplyStreamId.getAsLong();
                final long newCorrelationId = supplyCorrelationId.getAsLong();

                final UnaryOperator<HandshakeStatus> handshaker = this::processHandshake;
                final Consumer<WindowFW> windowHandler = this::adoptThrottle;
                final Consumer<ResetFW> resetHandler = this::processReset;

                engine.beginHandshake();

                final ClientHandshake newHandshake =
                        new ClientHandshake(engine, acceptName, acceptCorrelationId, handshaker, windowHandler, resetHandler);

                correlations.put(newCorrelationId, newHandshake);

                doBegin(connectTarget, newConnectId, connectRef, newCorrelationId);
                router.setThrottle(connectName, newConnectId, newHandshake::handleThrottle);

                this.connectId = newConnectId;
                this.streamState = this::afterBegin;
            }
            catch (SSLException ex)
            {
                doReset(throttle, throttleId);
                LangUtil.rethrowUnchecked(ex);
            }
        }

        private void processData(
            DataFW data)
        {
            try
            {
                final OctetsFW payload = data.payload();

                // Note: inAppBuffer is emptied by SslEngine.wrap(...)
                //       so should be able to eliminate allocation+copy (stateless)
                ByteBuffer inAppByteBuffer = ByteBuffer.allocate(payload.sizeof());
                payload.buffer().getBytes(payload.offset(), inAppByteBuffer, payload.sizeof());
                inAppByteBuffer.flip();

                wrapEngine(engine, inAppByteBuffer, connectTarget, connectId);

                // TODO: delta between windows
            }
            catch (SSLException ex)
            {
                doReset(throttle, throttleId);
                LangUtil.rethrowUnchecked(ex);
            }
        }

        private void processEnd(
            EndFW end)
        {
            try
            {
                engine.closeOutbound();

                wrapEngine(engine, EMPTY_BYTE_BUFFER, connectTarget, connectId);

                doEnd(connectTarget, connectId);
            }
            catch (SSLException ex)
            {
                doReset(throttle, throttleId);
                LangUtil.rethrowUnchecked(ex);
            }
        }

        private void adoptThrottle(
            final WindowFW window)
        {
            final int writableBytes = window.update();
            final int writableFrames = window.frames();

            router.setThrottle(connectName, connectId, this::handleThrottle);

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
            final int newWritableBytes = writableBytes;   // TODO: consider TLS Record padding
            final int newWritableFrames = writableFrames; // TODO: consider TLS Record frames

            doWindow(throttle, throttleId, newWritableBytes, newWritableFrames);
        }

        private void processReset(
            ResetFW reset)
        {
            doReset(throttle, throttleId);
        }

        private HandshakeStatus processHandshake(
            HandshakeStatus handshakeStatus)
        {
            loop:
            for (;;)
            {
                switch (handshakeStatus)
                {
                case NEED_TASK:
                    for (Runnable runnable = engine.getDelegatedTask();
                            runnable != null;
                            runnable = engine.getDelegatedTask())
                    {
                        runnable.run();
                    }

                    handshakeStatus = engine.getHandshakeStatus();
                    break;
                case NEED_WRAP:
                    try
                    {
                        handshakeStatus = wrapEngine(engine, EMPTY_BYTE_BUFFER, connectTarget, connectId);
                    }
                    catch (SSLException ex)
                    {
                        LangUtil.rethrowUnchecked(ex);
                    }
                    break;
                default:
                    break loop;
                }
            }

            return handshakeStatus;
        }
    }

    public final class ClientHandshake
    {
        private final SSLEngine engine;
        private final String acceptReplyName;
        private final long acceptCorrelationId;
        private final UnaryOperator<HandshakeStatus> handshaker;
        private final Consumer<ResetFW> resetHandler;
        private final Consumer<WindowFW> windowHandler;

        private HandshakeStatus handshakeStatus;

        private int writableBytes;
        private int writableFrames;

        private ClientHandshake(
            SSLEngine engine,
            String acceptName,
            long acceptCorrelationId,
            UnaryOperator<HandshakeStatus> handshaker,
            Consumer<WindowFW> windowHandler,
            Consumer<ResetFW> resetHandler)
        {
            this.engine = engine;
            this.acceptReplyName = acceptName;
            this.acceptCorrelationId = acceptCorrelationId;
            this.handshaker = handshaker;
            this.windowHandler = windowHandler;
            this.resetHandler = resetHandler;
            this.handshakeStatus = engine.getHandshakeStatus();
        }

        @Override
        public String toString()
        {
            return String.format("[acceptReplyName=\"%s\", acceptCorrelationId=%d]", acceptReplyName, acceptCorrelationId);
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
            WindowFW window)
        {
            this.writableBytes += window.update();
            this.writableFrames += window.frames();

            handshakeStatus = handshaker.apply(handshakeStatus);
        }

        private void processReset(
            ResetFW reset)
        {
            resetHandler.accept(reset);
        }
    }

    private final class ClientConnectReplyStream
    {
        private final MessageConsumer throttle;
        private final long throttleId;

        private SSLEngine engine;
        private MessageConsumer streamState;
        private Consumer<DataFW> decodeState;

        private ClientHandshake correlation;
        private MessageConsumer acceptReplyTarget;
        private long acceptReplyId;

        private ClientConnectReplyStream(
            MessageConsumer throttle,
            long throttleId)
        {
            this.throttle = throttle;
            this.throttleId = throttleId;
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
                processBegin(begin);
            }
            else
            {
                final FrameFW frame = frameRO.wrap(buffer, index, index + length);
                processUnexpected(frame);
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
                processEnd(end);
                break;
            default:
                final FrameFW frame = frameRO.wrap(buffer, index, index + length);
                processUnexpected(frame);
                break;
            }
        }

        private void processUnexpected(
            FrameFW frame)
        {
            final long throttleId = frame.streamId();

            doReset(throttle, throttleId);
        }

        private void processBegin(
            BeginFW begin)
        {
            final long sourceRef = begin.sourceRef();
            final long correlationId = begin.correlationId();

            final ClientHandshake correlation = sourceRef == 0L ? correlations.remove(correlationId) : null;
            if (correlation != null)
            {
                final long newAcceptReplyId = supplyStreamId.getAsLong();
                final String acceptReplyName = correlation.acceptReplyName;
                final MessageConsumer newAcceptReplyTarget = router.supplyTarget(acceptReplyName);

                router.setThrottle(acceptReplyName, newAcceptReplyId, this::handleThrottle);

                this.engine = correlation.engine;
                this.correlation = correlation;
                this.acceptReplyTarget = newAcceptReplyTarget;
                this.acceptReplyId = newAcceptReplyId;

                this.streamState = this::afterBegin;

                doWindow(throttle, throttleId, 8192, 8192);
            }
            else
            {
                final FrameFW frame = frameRO.wrap(begin.buffer(), begin.offset(), begin.limit());
                processUnexpected(frame);
            }
        }

        private void processEnd(
            EndFW end)
        {
            // TODO: detect truncation attack
            doEnd(acceptReplyTarget, acceptReplyId);
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
            WindowFW window)
        {
            final int writableBytes = window.update();
            final int writableFrames = window.frames();

            final int newWritableBytes = writableBytes;   // TODO: consider TLS Record padding
            final int newWritableFrames = writableFrames; // TODO: consider TLS Record frames

            doWindow(throttle, throttleId, newWritableBytes, newWritableFrames);
        }

        private void processReset(
            ResetFW reset)
        {
            doReset(throttle, throttleId);
        }

        private void decodeHandshake(
            DataFW data)
        {
            try
            {
                assert correlation.handshakeStatus == HandshakeStatus.NEED_UNWRAP;

                SSLEngineResult result = unwrapData(data);
                HandshakeStatus handshakeStatus = result.getHandshakeStatus();

                correlation.handshakeStatus = correlation.handshaker.apply(handshakeStatus);

                if (correlation.handshakeStatus == HandshakeStatus.FINISHED)
                {
                    String peerHost = engine.getPeerHost();

                    doTlsBegin(acceptReplyTarget, acceptReplyId, 0L, correlation.acceptCorrelationId, peerHost);

                    final WindowFW window = windowRW.wrap(writeBuffer, 0, writeBuffer.capacity())
                                                    .update(correlation.writableBytes)
                                                    .frames(correlation.writableFrames)
                                                    .build();
                    correlation.windowHandler.accept(window);

                    this.decodeState = this::decodeData;
                    this.correlation = null;
                }

                doWindow(throttle, throttleId, data.length(), 1);
            }
            catch (SSLException ex)
            {
                doReset(throttle, throttleId);
                LangUtil.rethrowUnchecked(ex);
            }
        }

        private void decodeData(
            DataFW data)
        {
            try
            {
                unwrapData(data);

                if (engine.isInboundDone())
                {
                    doEnd(acceptReplyTarget, acceptReplyId);
                }
            }
            catch (SSLException ex)
            {
                doReset(throttle, throttleId);
                LangUtil.rethrowUnchecked(ex);
            }
        }

        private SSLEngineResult unwrapData(
            DataFW data) throws SSLException
        {
            final OctetsFW payload = data.payload();

            // Note: inNetBuffer is emptied by SslEngine.unwrap(...)
            //       so should be able to eliminate allocation+copy (stateless)
            ByteBuffer inNetByteBuffer = ByteBuffer.allocate(payload.sizeof());
            payload.buffer().getBytes(payload.offset(), inNetByteBuffer, payload.sizeof());
            inNetByteBuffer.flip();

            return unwrapEngine(engine, inNetByteBuffer, acceptReplyTarget, acceptReplyId);
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

    private HandshakeStatus wrapEngine(
        SSLEngine engine,
        ByteBuffer inAppByteBuffer,
        MessageConsumer target,
        long targetId) throws SSLException
    {
        SSLEngineResult result = engine.wrap(inAppByteBuffer, outNetByteBuffer);

        // TODO: bound outNetBuffer by WINDOW
        outNetByteBuffer.flip();
        if (outNetByteBuffer.hasRemaining())
        {
            OctetsFW outNetOctets = outNetOctetsRO.wrap(outNetBuffer, outNetByteBuffer.position(), outNetByteBuffer.limit());
            doData(target, targetId, outNetOctets);
        }
        outNetByteBuffer.clear();

        return result.getHandshakeStatus();
    }

    private SSLEngineResult unwrapEngine(
        SSLEngine engine,
        ByteBuffer inNetByteBuffer,
        MessageConsumer target,
        long targetId) throws SSLException
    {
        SSLEngineResult result = engine.unwrap(inNetByteBuffer, outAppByteBuffer);

        outAppByteBuffer.flip();
        if (outAppByteBuffer.hasRemaining())
        {
            OctetsFW outAppOctets = outAppOctetsRO.wrap(outAppBuffer, outAppByteBuffer.position(), outAppByteBuffer.limit());
            doData(target, targetId, outAppOctets);
        }
        outAppByteBuffer.clear();

        return result;
    }
}
