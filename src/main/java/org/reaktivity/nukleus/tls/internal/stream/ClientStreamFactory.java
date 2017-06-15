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

import java.nio.ByteBuffer;
import java.util.Objects;
import java.util.function.Consumer;
import java.util.function.IntConsumer;
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
import org.reaktivity.nukleus.tls.internal.types.stream.ResetFW;
import org.reaktivity.nukleus.tls.internal.types.stream.TlsBeginExFW;
import org.reaktivity.nukleus.tls.internal.types.stream.WindowFW;
import org.reaktivity.nukleus.tls.internal.util.function.ObjectLongBiFunction;

public final class ClientStreamFactory implements StreamFactory
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
        final MessageConsumer applicationThrottle)
    {
        final long applicationRef = begin.sourceRef();
        final String applicationName = begin.source().asString();
        final OctetsFW extension = begin.extension();
        final TlsBeginExFW tlsBeginEx = extension.get(tlsBeginExRO::wrap);

        final MessagePredicate filter = (t, b, o, l) ->
        {
            final RouteFW route = routeRO.wrap(b, o, l);
            final TlsRouteExFW routeEx = route.extension().get(tlsRouteExRO::wrap);
            final String hostname = routeEx.hostname().asString();
            final String tlsHostname = tlsBeginEx.hostname().asString();

            return applicationRef == route.sourceRef() &&
                    applicationName.equals(route.source().asString()) &&
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

            final String networkName = route.target().asString();
            final long networkRef = route.targetRef();

            final long applicationId = begin.streamId();

            newStream = new ClientAcceptStream(tlsHostname, applicationThrottle, applicationId,
                                               networkName, networkRef)::handleStream;
        }

        return newStream;
    }

    private MessageConsumer newConnectReplyStream(
        final BeginFW begin,
        final MessageConsumer networkReplyThrottle)
    {
        final long networkReplyId = begin.streamId();

        return new ClientConnectReplyStream(networkReplyThrottle, networkReplyId)::handleStream;
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

        private final MessageConsumer applicationThrottle;
        private final long applicationId;

        private final String networkName;
        private final MessageConsumer networkTarget;
        private final long networkRef;

        private SSLEngine tlsEngine;
        private MessageConsumer streamState;

        private long networkId;

        private ClientAcceptStream(
            String tlsHostname,
            MessageConsumer applicationThrottle,
            long applicationId,
            String networkName,
            long networkRef)
        {
            this.tlsHostname = tlsHostname;
            this.applicationThrottle = applicationThrottle;
            this.applicationId = applicationId;
            this.networkName = networkName;
            this.networkTarget = router.supplyTarget(networkName);
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
                doReset(applicationThrottle, applicationId);
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
                doReset(applicationThrottle, applicationId);
                break;
            }
        }

        private void handleBegin(
            BeginFW begin)
        {
            try
            {
                final String applicationName = begin.source().asString();
                final long applicationCorrelationId = begin.correlationId();

                final long newNetworkId = supplyStreamId.getAsLong();
                final long newCorrelationId = supplyCorrelationId.getAsLong();

                final SSLEngine tlsEngine = context.createSSLEngine(tlsHostname, -1);
                tlsEngine.setUseClientMode(true);

                final SSLParameters tlsParameters = tlsEngine.getSSLParameters();
                tlsParameters.setEndpointIdentificationAlgorithm("HTTPS");
                if (tlsHostname != null)
                {
                    tlsParameters.setServerNames(asList(new SNIHostName(tlsHostname)));
                }
                tlsEngine.setSSLParameters(tlsParameters);

                final ClientHandshake newHandshake = new ClientHandshake(tlsEngine, networkName, newNetworkId,
                        applicationName, applicationCorrelationId, this::handleThrottle);

                correlations.put(newCorrelationId, newHandshake);

                doBegin(networkTarget, newNetworkId, networkRef, newCorrelationId);
                router.setThrottle(networkName, newNetworkId, newHandshake::handleThrottle);

                this.tlsEngine = tlsEngine;
                this.networkId = newNetworkId;
                this.streamState = this::afterBegin;

                tlsEngine.beginHandshake();
            }
            catch (SSLException ex)
            {
                doReset(applicationThrottle, applicationId);
                LangUtil.rethrowUnchecked(ex);
            }
        }

        private void handleData(
            DataFW data)
        {
            try
            {
                final OctetsFW payload = data.payload();

                // Note: inAppBuffer is emptied by SslEngine.wrap(...)
                //       so should be able to eliminate allocation+copy (stateless)
                inAppByteBuffer.clear();
                payload.buffer().getBytes(payload.offset(), inAppByteBuffer, payload.sizeof());
                inAppByteBuffer.flip();

                while (inAppByteBuffer.hasRemaining())
                {
                    outNetByteBuffer.rewind();
                    SSLEngineResult result = tlsEngine.wrap(inAppByteBuffer, outNetByteBuffer);
                    flushNetwork(tlsEngine, result.bytesProduced(), networkTarget, networkId);
                }

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
            try
            {
                tlsEngine.closeOutbound();
                outNetByteBuffer.rewind();
                SSLEngineResult result = tlsEngine.wrap(inAppByteBuffer, outNetByteBuffer);
                flushNetwork(tlsEngine, result.bytesProduced(), networkTarget, networkId);
            }
            catch (SSLException ex)
            {
                doReset(applicationThrottle, applicationId);
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
            final WindowFW window)
        {
            final int writableBytes = window.update();
            final int writableFrames = window.frames();
            final int newWritableBytes = writableBytes;   // TODO: consider TLS Record padding
            final int newWritableFrames = writableFrames; // TODO: consider TLS Record frames

            doWindow(applicationThrottle, applicationId, newWritableBytes, newWritableFrames);
        }

        private void handleReset(
            ResetFW reset)
        {
            doReset(applicationThrottle, applicationId);
        }
    }

    public final class ClientHandshake
    {
        private final SSLEngine tlsEngine;

        private final String networkName;
        private final MessageConsumer networkTarget;
        private final long networkId;

        private final String applicationName;
        private final long applicationCorrelationId;
        private final MessageConsumer networkThrottle;

        private Consumer<WindowFW> windowHandler;

        private MessageConsumer networkReplyThrottle;
        private long networkReplyId;

        private IntConsumer flushHandler;
        private Consumer<HandshakeStatus> statusHandler;

        private int networkBytes;
        private int networkFrames;

        private ClientHandshake(
            SSLEngine tlsEngine,
            String networkName,
            long networkId,
            String applicationName,
            long applicationCorrelationId,
            MessageConsumer applicationThrottle)
        {
            this.tlsEngine = tlsEngine;
            this.networkName = networkName;
            this.networkTarget = router.supplyTarget(networkName);
            this.networkId = networkId;
            this.applicationName = applicationName;
            this.applicationCorrelationId = applicationCorrelationId;
            this.networkThrottle = applicationThrottle;
            this.windowHandler = this::beforeNetworkReply;
        }

        @Override
        public String toString()
        {
            return String.format("%s [tlsEngine=%s]", getClass().getSimpleName(), tlsEngine);
        }

        private void onNetworkReply(
            MessageConsumer networkReplyThrottle,
            long networkReplyId,
            IntConsumer flushHandler,
            Consumer<HandshakeStatus> statusHandler)
        {
            this.networkReplyThrottle = networkReplyThrottle;
            this.networkReplyId = networkReplyId;
            this.flushHandler = flushHandler;
            this.statusHandler = statusHandler;
            this.windowHandler = this::afterNetworkReply;

            statusHandler.accept(tlsEngine.getHandshakeStatus());
        }

        private MessageConsumer doBeginApplicationReply(
            MessageConsumer applicationThrottle,
            long applicationReplyId)
        {
            final String applicationReplyName = applicationName;
            final String peerHost = tlsEngine.getPeerHost();

            final MessageConsumer applicationReply = router.supplyTarget(applicationReplyName);

            doTlsBegin(applicationReply, applicationReplyId, 0L, applicationCorrelationId, peerHost);
            router.setThrottle(applicationReplyName, applicationReplyId, applicationThrottle);

            router.setThrottle(networkName, networkId, networkThrottle);

            doWindow(networkThrottle, networkId, networkBytes, networkFrames);

            return applicationReply;
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
                windowHandler.accept(window);
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

        private void beforeNetworkReply(
            WindowFW window)
        {
            this.networkBytes += window.update();
            this.networkFrames += window.frames();
        }

        private void afterNetworkReply(
            WindowFW window)
        {
            this.networkBytes += window.update();
            this.networkFrames += window.frames();

            statusHandler.accept(tlsEngine.getHandshakeStatus());
        }

        private void handleReset(
            ResetFW reset)
        {
            networkThrottle.accept(reset.typeId(), reset.buffer(), reset.offset(), reset.sizeof());
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
                doReset(networkReplyThrottle, networkReplyId);
                break;
            }
        }

        private void handleData(
            DataFW data)
        {
            try
            {
                final OctetsFW payload = data.payload();

                // Note: inNetByteBuffer is emptied by SslEngine.unwrap(...)
                //       so should be able to eliminate copy (stateless)
                inNetByteBuffer.clear();
                payload.buffer().getBytes(payload.offset(), inNetByteBuffer, payload.sizeof());
                inNetByteBuffer.flip();

                while (inNetByteBuffer.hasRemaining())
                {
                    outAppByteBuffer.rewind();
                    SSLEngineResult result = tlsEngine.unwrap(inNetByteBuffer, outAppByteBuffer);

                    flushHandler.accept(result.bytesProduced());
                    statusHandler.accept(result.getHandshakeStatus());
                }
            }
            catch (SSLException ex)
            {
                doReset(networkReplyThrottle, networkReplyId);
                LangUtil.rethrowUnchecked(ex);
            }

            doWindow(networkReplyThrottle, networkReplyId, data.length(), 1);
        }

        private void handleEnd(
            EndFW end)
        {
            try
            {
                tlsEngine.closeOutbound();
                outNetByteBuffer.rewind();
                SSLEngineResult result = tlsEngine.wrap(inAppByteBuffer, outNetByteBuffer);
                flushNetwork(tlsEngine, result.bytesProduced(), networkTarget, networkId);
            }
            catch (SSLException ex)
            {
                doReset(networkReplyThrottle, networkReplyId);
                LangUtil.rethrowUnchecked(ex);
            }
        }
    }

    private final class ClientConnectReplyStream
    {
        private final MessageConsumer networkReplyThrottle;
        private final long networkReplyId;

        private SSLEngine tlsEngine;

        private MessageConsumer applicationReply;
        private long applicationReplyId;
        private ObjectLongBiFunction<MessageConsumer, MessageConsumer> doBeginApplicationReply;

        private MessageConsumer networkTarget;
        private long networkId;

        private MessageConsumer streamState;

        private ClientConnectReplyStream(
            MessageConsumer networkReplyThrottle,
            long networkReplyId)
        {
            this.networkReplyThrottle = networkReplyThrottle;
            this.networkReplyId = networkReplyId;
            this.streamState = this::beforeHandshake;
        }

        private void handleStream(
            int msgTypeId,
            DirectBuffer buffer,
            int index,
            int length)
        {
            streamState.accept(msgTypeId, buffer, index, length);
        }

        private void beforeHandshake(
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
                doReset(networkReplyThrottle, networkReplyId);
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
                doReset(networkReplyThrottle, networkReplyId);
                break;
            }
        }

        private void handleBegin(
            BeginFW begin)
        {
            final long sourceRef = begin.sourceRef();
            final long correlationId = begin.correlationId();

            final ClientHandshake handshake = sourceRef == 0L ? correlations.remove(correlationId) : null;
            if (handshake != null)
            {
                this.tlsEngine = handshake.tlsEngine;
                this.networkTarget = handshake.networkTarget;
                this.networkId = handshake.networkId;
                this.doBeginApplicationReply = handshake::doBeginApplicationReply;
                this.streamState = handshake::afterBegin;

                handshake.onNetworkReply(networkReplyThrottle, networkReplyId, this::handleFlush, this::handleStatus);
                doWindow(networkReplyThrottle, networkReplyId, 8192, 8192);
            }
            else
            {
                doReset(networkReplyThrottle, networkReplyId);
            }
        }

        private void handleData(
            DataFW data)
        {
            try
            {
                final OctetsFW payload = data.payload();

                // Note: inNetByteBuffer is emptied by SslEngine.unwrap(...)
                //       so should be able to eliminate copy (stateless)
                inNetByteBuffer.clear();
                payload.buffer().getBytes(payload.offset(), inNetByteBuffer, payload.sizeof());
                inNetByteBuffer.flip();

                while (inNetByteBuffer.hasRemaining())
                {
                    outAppByteBuffer.rewind();
                    SSLEngineResult result = tlsEngine.unwrap(inNetByteBuffer, outAppByteBuffer);

                    handleFlush(result.bytesProduced());
                    handleStatus(result.getHandshakeStatus());
                }

                if (tlsEngine.isInboundDone())
                {
                    doEnd(applicationReply, applicationReplyId);
                }
            }
            catch (SSLException ex)
            {
                doReset(networkReplyThrottle, networkReplyId);
                LangUtil.rethrowUnchecked(ex);
            }
        }

        private void handleEnd(
            EndFW end)
        {
            try
            {
                tlsEngine.closeInbound();
                handleStatus(tlsEngine.getHandshakeStatus());
            }
            catch (SSLException ex)
            {
                doReset(networkReplyThrottle, networkReplyId);
                LangUtil.rethrowUnchecked(ex);
            }
        }

        private HandshakeStatus handleStatus(
            HandshakeStatus status)
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
                        // TODO: limit outNetByteBuffer by networkBytes and networkFrames
                        outNetByteBuffer.rewind();
                        SSLEngineResult result = tlsEngine.wrap(EMPTY_BYTE_BUFFER, outNetByteBuffer);
                        flushNetwork(tlsEngine, result.bytesProduced(), networkTarget, networkId);
                        status = result.getHandshakeStatus();
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

            return status;
        }

        private void handleFinished()
        {
            final long newApplicationReplyId = supplyStreamId.getAsLong();
            this.applicationReply = this.doBeginApplicationReply.apply(this::handleThrottle, newApplicationReplyId);
            this.applicationReplyId = newApplicationReplyId;

            this.streamState = this::afterHandshake;
            this.doBeginApplicationReply = null;
        }

        private void handleFlush(
            int bytesProduced)
        {
            if (bytesProduced > 0)
            {
                final OctetsFW outAppOctets = outAppOctetsRO.wrap(outAppBuffer, 0, bytesProduced);

                doData(applicationReply, applicationReplyId, outAppOctets);
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

            doWindow(networkReplyThrottle, networkReplyId, newWritableBytes, newWritableFrames);
        }

        private void handleReset(
            ResetFW reset)
        {
            doReset(networkReplyThrottle, networkReplyId);
        }
    }

    private void flushNetwork(
        SSLEngine tlsEngine,
        int bytesProduced,
        MessageConsumer networkTarget,
        long networkId)
    {
        if (bytesProduced > 0)
        {
            final OctetsFW outNetOctets = outNetOctetsRO.wrap(outNetBuffer, 0, bytesProduced);
            doData(networkTarget, networkId, outNetOctets);
        }

        if (tlsEngine.isOutboundDone())
        {
            doEnd(networkTarget, networkId);
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
