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
import static javax.net.ssl.SSLEngineResult.Status.BUFFER_UNDERFLOW;
import static org.agrona.LangUtil.rethrowUnchecked;
import static org.reaktivity.nukleus.buffer.BufferPool.NO_SLOT;

import java.nio.ByteBuffer;
import java.util.Objects;
import java.util.function.BiConsumer;
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
import org.agrona.MutableDirectBuffer;
import org.agrona.collections.Long2ObjectHashMap;
import org.agrona.concurrent.UnsafeBuffer;
import org.reaktivity.nukleus.buffer.BufferPool;
import org.reaktivity.nukleus.function.MessageConsumer;
import org.reaktivity.nukleus.function.MessagePredicate;
import org.reaktivity.nukleus.route.RouteManager;
import org.reaktivity.nukleus.stream.StreamFactory;
import org.reaktivity.nukleus.tls.internal.TlsConfiguration;
import org.reaktivity.nukleus.tls.internal.types.Flyweight;
import org.reaktivity.nukleus.tls.internal.types.OctetsFW;
import org.reaktivity.nukleus.tls.internal.types.control.RouteFW;
import org.reaktivity.nukleus.tls.internal.types.control.TlsRouteExFW;
import org.reaktivity.nukleus.tls.internal.types.stream.AbortFW;
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
    private static final int MAXIMUM_HEADER_SIZE = 5 + 20 + 256;    // TODO version + MAC + padding
    private static final int MAXIMUM_PAYLOAD_LENGTH = (1 << Short.SIZE) - 1;

    private final RouteFW routeRO = new RouteFW();
    private final TlsRouteExFW tlsRouteExRO = new TlsRouteExFW();

    private final BeginFW beginRO = new BeginFW();
    private final DataFW dataRO = new DataFW();
    private final EndFW endRO = new EndFW();
    private final AbortFW abortRO = new AbortFW();

    private final BeginFW.Builder beginRW = new BeginFW.Builder();
    private final DataFW.Builder dataRW = new DataFW.Builder();
    private final EndFW.Builder endRW = new EndFW.Builder();
    private final AbortFW.Builder abortRW = new AbortFW.Builder();

    private final WindowFW windowRO = new WindowFW();
    private final ResetFW resetRO = new ResetFW();

    private final TlsBeginExFW tlsBeginExRO = new TlsBeginExFW();
    private final TlsBeginExFW.Builder tlsBeginExRW = new TlsBeginExFW.Builder();

    private final OctetsFW outNetOctetsRO = new OctetsFW();
    private final OctetsFW outAppOctetsRO = new OctetsFW();

    private final WindowFW.Builder windowRW = new WindowFW.Builder();
    private final ResetFW.Builder resetRW = new ResetFW.Builder();

    private final TlsConfiguration config;
    private final SSLContext context;
    private final RouteManager router;
    private final MutableDirectBuffer writeBuffer;
    private final BufferPool networkPool;
    private final BufferPool applicationPool;
    private final LongSupplier supplyStreamId;
    private final LongSupplier supplyCorrelationId;
    private final int handshakeWindowBytes;

    private final Long2ObjectHashMap<ClientHandshake> correlations;
    private final ByteBuffer inAppByteBuffer;
    private final ByteBuffer outAppByteBuffer;
    private final ByteBuffer outNetByteBuffer;
    private final DirectBuffer outNetBuffer;

    public ClientStreamFactory(
        TlsConfiguration config,
        SSLContext context,
        RouteManager router,
        MutableDirectBuffer writeBuffer,
        BufferPool bufferPool,
        LongSupplier supplyStreamId,
        LongSupplier supplyCorrelationId,
        Long2ObjectHashMap<ClientHandshake> correlations)
    {
        this.config = requireNonNull(config);
        this.context = requireNonNull(context);
        this.router = requireNonNull(router);
        this.writeBuffer = requireNonNull(writeBuffer);
        this.networkPool = requireNonNull(bufferPool);
        this.applicationPool = requireNonNull(bufferPool).duplicate();
        this.supplyStreamId = requireNonNull(supplyStreamId);
        this.supplyCorrelationId = requireNonNull(supplyCorrelationId);
        this.correlations = requireNonNull(correlations);
        this.handshakeWindowBytes = Math.min(config.handshakeWindowBytes(), networkPool.slotCapacity());

        this.inAppByteBuffer = allocateDirect(writeBuffer.capacity());
        this.outAppByteBuffer = allocateDirect(writeBuffer.capacity());
        this.outNetByteBuffer = allocateDirect(Math.min(writeBuffer.capacity(), MAXIMUM_PAYLOAD_LENGTH));
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
            final String applicationProtocol = tlsBeginEx.applicationProtocol().asString();

            return applicationRef == route.sourceRef() &&
                    applicationName.equals(route.source().asString()) &&
                    (tlsHostname == null || Objects.equals(tlsHostname, hostname)) &&
                    (applicationProtocol == null || applicationProtocol.equals(routeEx.applicationProtocol().asString()));
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

            String applicationProtocol = tlsBeginEx.applicationProtocol().asString();
            if (applicationProtocol == null)
            {
                final TlsRouteExFW routeEx = route.extension().get(tlsRouteExRO::wrap);
                applicationProtocol = routeEx.applicationProtocol().asString();
            }

            final String networkName = route.target().asString();
            final long networkRef = route.targetRef();

            final long applicationId = begin.streamId();

            newStream = new ClientAcceptStream(tlsHostname, applicationProtocol, applicationThrottle, applicationId,
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
        private final String applicationProtocol;

        private final MessageConsumer applicationThrottle;
        private final long applicationId;

        private final String networkName;
        private final MessageConsumer networkTarget;
        private final long networkRef;

        private SSLEngine tlsEngine;
        private MessageConsumer streamState;

        private long networkId;

        private int applicationWindowBudget;
        private int applicationWindowPadding;
        private int applicationWindowBudgetAdjustment;
        private int applicationWindowBudgetMax;

        private int maxHeaderSize;

        private ClientAcceptStream(
            String tlsHostname,
            String applicationProtocol,
            MessageConsumer applicationThrottle,
            long applicationId,
            String networkName,
            long networkRef)
        {
            this.tlsHostname = tlsHostname;
            this.applicationProtocol = applicationProtocol;
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
            case AbortFW.TYPE_ID:
                final AbortFW abort = abortRO.wrap(buffer, index, index + length);
                handleAbort(abort);
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

                String[] applicationProtocols = new String[] { applicationProtocol };
                if (applicationProtocols.length > 0)
                {
                    try
                    {
                        tlsParameters.setApplicationProtocols(applicationProtocols);
                    }
                    catch (Throwable e)
                    {
                        throw new RuntimeException("Use JDK 9 to run this program", e);
                    }
                }

                tlsEngine.setSSLParameters(tlsParameters);

                final ClientHandshake newHandshake = new ClientHandshake(tlsEngine, networkName, newNetworkId,
                        applicationName, applicationCorrelationId, newCorrelationId, this::handleThrottle,
                        applicationThrottle, applicationId, this::handleNetworkReplyDone);

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
                doAbort(networkTarget, networkId);
            }
        }

        private void handleData(
            DataFW data)
        {
            applicationWindowBudget -= data.length() + applicationWindowPadding;

            try
            {
                if (applicationWindowBudget < 0)
                {
                    doReset(applicationThrottle, applicationId);
                    doCloseOutbound(tlsEngine, networkTarget, networkId, this::handleNetworkReplyDone);
                }
                else
                {
                    final OctetsFW payload = data.payload();

                    // Note: inAppBuffer is emptied by SslEngine.wrap(...)
                    //       so should be able to eliminate allocation+copy (stateless)
                    inAppByteBuffer.clear();
                    payload.buffer().getBytes(payload.offset(), inAppByteBuffer, payload.sizeof());
                    inAppByteBuffer.flip();

                    int totalBytesProduced = 0;
                    int totalBytesConsumed = 0;
                    while (inAppByteBuffer.hasRemaining() && !tlsEngine.isOutboundDone())
                    {
                        outNetByteBuffer.rewind();
                        SSLEngineResult result = tlsEngine.wrap(inAppByteBuffer, outNetByteBuffer);
                        totalBytesProduced += result.bytesProduced();
                        totalBytesConsumed += result.bytesConsumed();
                        flushNetwork(tlsEngine, result.bytesProduced(), networkTarget, networkId,
                                this::handleNetworkReplyDone);
                    }

                    applicationWindowBudgetAdjustment += maxHeaderSize - (totalBytesProduced - totalBytesConsumed);
                }
            }
            catch (SSLException ex)
            {
                doReset(applicationThrottle, applicationId);
                doAbort(networkTarget, networkId);
            }
        }

        private void handleEnd(
            EndFW end)
        {
            applicationWindowBudget = -1;

            try
            {
                doCloseOutbound(tlsEngine, networkTarget, networkId, this::handleNetworkReplyDone);
            }
            catch (SSLException ex)
            {
                doAbort(networkTarget, networkId);
            }
        }

        private void handleAbort(
            AbortFW abort)
        {
            tlsEngine.closeOutbound();
            doAbort(networkTarget, networkId);
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

            final int networkWindowCredit = window.credit();
            final int networkWindowPadding = window.padding();

            final int applicationWindowCredit = networkWindowCredit + applicationWindowBudgetAdjustment;

            applicationWindowBudget += Math.max(applicationWindowCredit, 0);
            applicationWindowBudgetAdjustment = Math.min(applicationWindowCredit, 0);

            if (applicationWindowBudget > applicationWindowBudgetMax)
            {
                applicationWindowBudgetMax = applicationWindowBudget;

                final int tlsMaxRecordSize = tlsEngine.getSession().getPacketBufferSize();
                final int tlsMaxRecordCount = Math.max(
                        (int) Math.ceil((double) applicationWindowBudgetMax / tlsMaxRecordSize), 1);

                this.maxHeaderSize = tlsMaxRecordCount * MAXIMUM_HEADER_SIZE;
            }

            applicationWindowPadding = networkWindowPadding + maxHeaderSize;

            if (applicationWindowCredit > 0)
            {
                doWindow(applicationThrottle, applicationId,
                         Math.max(applicationWindowCredit, 0), applicationWindowPadding);
            }
        }

        private void handleReset(
            ResetFW reset)
        {
            doReset(applicationThrottle, applicationId);
            tlsEngine.closeOutbound();
        }

        private void handleNetworkReplyDone()
        {
            if (applicationWindowBudget == -1)
            {
                doReset(applicationThrottle, applicationId);
            }
        }
    }

    public final class ClientHandshake
    {
        private final SSLEngine tlsEngine;

        private final String networkName;
        private final MessageConsumer networkTarget;
        private final long networkId;
        private final MessageConsumer networkThrottle;

        private final MessageConsumer applicationThrottle;
        private final long applicationId;

        private final String applicationName;
        private final long applicationCorrelationId;
        private final long networkCorrelationId;

        private final Runnable networkReplyDoneHandler;

        private MessageConsumer networkReplyThrottle;
        private long networkReplyId;
        private int networkReplySlot = NO_SLOT;
        private int networkReplySlotOffset;

        private Consumer<WindowFW> windowHandler;
        private BiConsumer<HandshakeStatus, Consumer<SSLEngineResult>> statusHandler;

        private int inNetworkWindowBytes;

        private int outNetworkWindowBudget;
        private int outNetworkWindowPadding;

        private ClientHandshake(
            SSLEngine tlsEngine,
            String networkName,
            long networkId,
            String applicationName,
            long applicationCorrelationId,
            long networkCorrelationId,
            MessageConsumer networkThrottle,
            MessageConsumer applicationThrottle,
            long applicationId,
            Runnable networkReplyDoneHandler)
        {
            this.tlsEngine = tlsEngine;
            this.networkName = networkName;
            this.networkTarget = router.supplyTarget(networkName);
            this.networkId = networkId;
            this.applicationName = applicationName;
            this.applicationCorrelationId = applicationCorrelationId;
            this.networkCorrelationId = networkCorrelationId;
            this.networkThrottle = networkThrottle;
            this.windowHandler = this::beforeNetworkReply;
            this.applicationThrottle = applicationThrottle;
            this.applicationId = applicationId;
            this.networkReplyDoneHandler = networkReplyDoneHandler;
        }

        @Override
        public String toString()
        {
            return String.format("%s [tlsEngine=%s]", getClass().getSimpleName(), tlsEngine);
        }

        private void onNetworkReply(
            MessageConsumer networkReplyThrottle,
            long networkReplyId,
            BiConsumer<HandshakeStatus, Consumer<SSLEngineResult>> statusHandler)
        {
            this.networkReplyThrottle = networkReplyThrottle;
            this.networkReplyId = networkReplyId;
            this.statusHandler = statusHandler;
            this.windowHandler = this::afterNetworkReply;

            statusHandler.accept(tlsEngine.getHandshakeStatus(), this::updateNetworkWindow);

            inNetworkWindowBytes += handshakeWindowBytes;
            doWindow(networkReplyThrottle, networkReplyId, handshakeWindowBytes, 0);
        }

        private MessageConsumer doBeginApplicationReply(
            MessageConsumer applicationThrottle,
            long applicationReplyId)
        {
            final String applicationReplyName = applicationName;
            final String peerHost = tlsEngine.getPeerHost();
            final String applicationProtocol = tlsEngine.getApplicationProtocol();

            final MessageConsumer applicationReply = router.supplyTarget(applicationReplyName);

            doTlsBegin(applicationReply, applicationReplyId, 0L, applicationCorrelationId,
                    peerHost, applicationProtocol);
            router.setThrottle(applicationReplyName, applicationReplyId, applicationThrottle);

            router.setThrottle(networkName, networkId, networkThrottle);

            doWindow(networkThrottle, networkId, outNetworkWindowBudget, outNetworkWindowPadding);

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
            this.outNetworkWindowBudget += window.credit();
            this.outNetworkWindowPadding = window.padding();
        }

        private void afterNetworkReply(
            WindowFW window)
        {
            this.outNetworkWindowBudget += window.credit();
            this.outNetworkWindowPadding = window.padding();

            statusHandler.accept(tlsEngine.getHandshakeStatus(), this::updateNetworkWindow);
        }

        private void handleReset(
            ResetFW reset)
        {
            try
            {
                if (correlations.remove(networkCorrelationId) == null)
                {
                    doReset(applicationThrottle, applicationId);
                }
                tlsEngine.closeInbound();
            }
            catch (SSLException ex)
            {
                // ignore
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
                doReset(networkReplyThrottle, networkReplyId);
                break;
            }
        }

        private void handleData(
            DataFW data)
        {
            inNetworkWindowBytes -= data.length();

            if (networkReplySlot == NO_SLOT)
            {
                networkReplySlot = networkPool.acquire(networkReplyId);
            }

            try
            {
                if (networkReplySlot == NO_SLOT || inNetworkWindowBytes < 0)
                {
                    doReset(networkReplyThrottle, networkReplyId);
                    doCloseOutbound(tlsEngine, networkTarget, networkId, networkReplyDoneHandler);
                }
                else
                {
                    final OctetsFW payload = data.payload();
                    final int payloadSize = payload.sizeof();

                    final MutableDirectBuffer inNetBuffer = networkPool.buffer(networkReplySlot);
                    inNetBuffer.putBytes(networkReplySlotOffset, payload.buffer(), payload.offset(), payloadSize);
                    final ByteBuffer inNetByteBuffer = networkPool.byteBuffer(networkReplySlot);
                    final int inNetByteBufferPosition = inNetByteBuffer.position();
                    inNetByteBuffer.limit(inNetByteBuffer.position() + networkReplySlotOffset + payloadSize);

                    loop:
                    while (inNetByteBuffer.hasRemaining())
                    {
                        outAppByteBuffer.rewind();
                        SSLEngineResult result = tlsEngine.unwrap(inNetByteBuffer, outAppByteBuffer);

                        if (outAppByteBuffer.position() != 0)
                        {
                            doReset(networkReplyThrottle, networkReplyId);
                            break loop;
                        }

                        switch (result.getStatus())
                        {
                        case BUFFER_UNDERFLOW:
                            final int totalBytesConsumed = inNetByteBuffer.position() - inNetByteBufferPosition;
                            final int totalBytesRemaining = inNetByteBuffer.remaining();
                            alignSlotBuffer(inNetBuffer, totalBytesConsumed, totalBytesRemaining);
                            networkReplySlotOffset = totalBytesRemaining;
                            break loop;
                        default:
                            networkReplySlotOffset = 0;
                            statusHandler.accept(result.getHandshakeStatus(), this::updateNetworkWindow);
                            break;
                        }
                    }

                    inNetworkWindowBytes += data.length();

                    doWindow(networkReplyThrottle, networkReplyId, data.length(), outNetworkWindowPadding);
                }
            }
            catch (SSLException ex)
            {
                networkReplySlotOffset = 0;
                doReset(networkReplyThrottle, networkReplyId);
                doAbort(networkTarget, networkId);
            }
            finally
            {
                if (networkReplySlotOffset == 0 && networkReplySlot != NO_SLOT)
                {
                    networkPool.release(networkReplySlot);
                    networkReplySlot = NO_SLOT;
                }
            }
        }

        private void handleEnd(
            EndFW end)
        {
            try
            {
                doCloseOutbound(tlsEngine, networkTarget, networkId, networkReplyDoneHandler);
            }
            catch (SSLException ex)
            {
                doAbort(networkTarget, networkId);
            }
            finally
            {
                doReset(networkThrottle, networkId);
            }
        }

        private void handleAbort(
            AbortFW abort)
        {
            correlations.remove(networkCorrelationId);
            tlsEngine.closeOutbound();
            doAbort(networkTarget, networkId);
        }

        private void updateNetworkWindow(
            SSLEngineResult result)
        {
            final int bytesProduced = result.bytesProduced();
            if (bytesProduced != 0)
            {
                outNetworkWindowBudget -= bytesProduced;
            }
        }
    }

    private final class ClientConnectReplyStream
    {
        private final MessageConsumer networkReplyThrottle;
        private final long networkReplyId;

        private MessageConsumer networkTarget;
        private long networkId;

        private int networkWindowBudget;
        private int networkWindowBudgetAdjustment;
        private int networkWindowPadding;

        private int networkReplySlot;
        private int networkReplySlotOffset;

        private SSLEngine tlsEngine;

        private MessageConsumer applicationReply;
        private long applicationReplyId;
        private ObjectLongBiFunction<MessageConsumer, MessageConsumer> doBeginApplicationReply;

        private MessageConsumer streamState;
        private int applicationWindowBudget;
        private int applicationReplySlot = NO_SLOT;
        private int applicationReplySlotOffset;

        private Runnable networkReplyDoneHandler;

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
            case AbortFW.TYPE_ID:
                final AbortFW abort = abortRO.wrap(buffer, index, index + length);
                handleAbort(abort);
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
                this.networkReplySlot = handshake.networkReplySlot;
                this.networkReplySlotOffset = handshake.networkReplySlotOffset;
                this.doBeginApplicationReply = handshake::doBeginApplicationReply;
                this.streamState = handshake::afterBegin;
                this.networkReplyDoneHandler = handshake.networkReplyDoneHandler;

                handshake.onNetworkReply(networkReplyThrottle, networkReplyId, this::handleStatus);
            }
            else
            {
                doReset(networkReplyThrottle, networkReplyId);
            }
        }

        private void handleData(
            DataFW data)
        {
            networkWindowBudget -= data.length() + networkWindowPadding;

            if (networkReplySlot == NO_SLOT)
            {
                networkReplySlot = networkPool.acquire(networkReplyId);
            }

            try
            {
                if (networkReplySlot == NO_SLOT || networkWindowBudget < 0)
                {
                    tlsEngine.closeInbound();
                    doReset(networkReplyThrottle, networkReplyId);
                    doAbort(applicationReply, applicationReplyId);
                }
                else
                {
                    final OctetsFW payload = data.payload();
                    final int payloadSize = payload.sizeof();

                    final MutableDirectBuffer inNetBuffer = networkPool.buffer(networkReplySlot);
                    inNetBuffer.putBytes(networkReplySlotOffset, payload.buffer(), payload.offset(), payloadSize);
                    networkReplySlotOffset += payloadSize;

                    unwrapNetworkBufferData();
                }
            }
            catch (SSLException ex)
            {
                doReset(networkReplyThrottle, networkReplyId);
                doAbort(applicationReply, applicationReplyId);
            }
            finally
            {
                if (networkReplySlotOffset == 0 && networkReplySlot != NO_SLOT)
                {
                    networkPool.release(networkReplySlot);
                    networkReplySlot = NO_SLOT;
                }
            }
        }

        private void unwrapNetworkBufferData()
        {
            assert (networkReplySlotOffset != 0);

            if (applicationReplySlot == NO_SLOT)
            {
                applicationReplySlot = applicationPool.acquire(applicationReplyId);
            }

            try
            {
                if (applicationReplySlot == NO_SLOT)
                {
                    tlsEngine.closeInbound();
                    doReset(networkReplyThrottle, networkReplyId);
                    doAbort(applicationReply, applicationReplyId);
                }
                else
                {
                    final MutableDirectBuffer inNetBuffer = networkPool.buffer(networkReplySlot);
                    final ByteBuffer inNetByteBuffer = networkPool.byteBuffer(networkReplySlot);
                    final int inNetByteBufferPosition = inNetByteBuffer.position();
                    inNetByteBuffer.limit(inNetByteBuffer.position() + networkReplySlotOffset);

                    loop:
                    while (inNetByteBuffer.hasRemaining())
                    {
                        final ByteBuffer outAppByteBuffer = applicationPool.byteBuffer(applicationReplySlot);
                        outAppByteBuffer.position(outAppByteBuffer.position() + applicationReplySlotOffset);

                        SSLEngineResult result = tlsEngine.unwrap(inNetByteBuffer, outAppByteBuffer);

                        switch (result.getStatus())
                        {
                        case BUFFER_OVERFLOW:
                        case BUFFER_UNDERFLOW:
                            final int totalBytesConsumed = inNetByteBuffer.position() - inNetByteBufferPosition;
                            final int totalBytesRemaining = inNetByteBuffer.remaining();
                            alignSlotBuffer(inNetBuffer, totalBytesConsumed, totalBytesRemaining);
                            networkReplySlotOffset = totalBytesRemaining;
                            if (networkReplySlotOffset == networkPool.slotCapacity() &&
                                    result.getStatus() == BUFFER_UNDERFLOW)
                            {
                                networkReplySlotOffset = 0;
                                tlsEngine.closeInbound();
                                doReset(networkReplyThrottle, networkReplyId);
                                doAbort(applicationReply, applicationReplyId);
                            }
                            else
                            {
                                final int networkWindowBytesUpdate =
                                        Math.max(networkPool.slotCapacity() - networkReplySlotOffset - networkWindowBudget, 0);

                                if (networkWindowBytesUpdate > 0)
                                {
                                    networkWindowBudget += networkWindowBytesUpdate;
                                    networkWindowBudgetAdjustment -= networkWindowBytesUpdate;

                                    doWindow(networkReplyThrottle, networkReplyId, networkWindowBytesUpdate,
                                            networkWindowPadding);
                                }
                            }
                            break loop;
                        default:
                            networkReplySlotOffset = 0;
                            applicationReplySlotOffset += result.bytesProduced();
                            handleStatus(result.getHandshakeStatus(), r -> {});
                            networkWindowBudgetAdjustment += result.bytesConsumed() - result.bytesProduced();
                            break;
                        }
                    }

                    handleFlushAppData();
                }
            }
            catch (SSLException ex)
            {
                networkReplySlotOffset = 0;
                applicationReplySlotOffset = 0;
                doReset(networkReplyThrottle, networkReplyId);
                doAbort(applicationReply, applicationReplyId);
            }
            finally
            {
                if (applicationReplySlotOffset == 0 && applicationReplySlot != NO_SLOT)
                {
                    applicationPool.release(applicationReplySlot);
                    applicationReplySlot = NO_SLOT;
                }
            }
        }

        private void handleEnd(
            EndFW end)
        {
            if (!tlsEngine.isInboundDone())
            {
                networkWindowBudget = -1;
                try
                {
                    tlsEngine.closeInbound();
                    doEnd(applicationReply, applicationReplyId);
                }
                catch (SSLException ex)
                {
                    doAbort(applicationReply, applicationReplyId);
                }
            }
        }

        private void handleAbort(
            AbortFW abort)
        {
            try
            {
                tlsEngine.closeInbound();
            }
            catch (SSLException ex)
            {
                // ignore and clean up
            }
            finally
            {
                doAbort(applicationReply, applicationReplyId);
            }
        }

        private HandshakeStatus handleStatus(
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
                        outNetByteBuffer.rewind();
                        SSLEngineResult result = tlsEngine.wrap(EMPTY_BYTE_BUFFER, outNetByteBuffer);
                        resultHandler.accept(result);
                        flushNetwork(tlsEngine, result.bytesProduced(), networkTarget, networkId, networkReplyDoneHandler);
                        status = result.getHandshakeStatus();
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

            return status;
        }

        private void handleFinished()
        {
            this.networkWindowBudget += handshakeWindowBytes;
            this.networkWindowBudgetAdjustment -= handshakeWindowBytes;

            final long newApplicationReplyId = supplyStreamId.getAsLong();
            this.applicationReply = this.doBeginApplicationReply.apply(this::handleThrottle, newApplicationReplyId);
            this.applicationReplyId = newApplicationReplyId;

            this.streamState = this::afterHandshake;
            this.doBeginApplicationReply = null;
        }

        private void handleFlushAppData()
        {
            if (applicationReplySlotOffset > 0)
            {


                final MutableDirectBuffer outAppBuffer = applicationPool.buffer(applicationReplySlot);

                final int applicationWindow = Math.min(applicationWindowBudget - networkWindowPadding, MAXIMUM_PAYLOAD_LENGTH);

                final int applicationBytesConsumed = Math.min(applicationReplySlotOffset, applicationWindow);

                if (applicationBytesConsumed > 0)
                {
                    final OctetsFW outAppOctets = outAppOctetsRO.wrap(outAppBuffer, 0, applicationBytesConsumed);

                    doData(applicationReply, applicationReplyId, outAppOctets);

                    applicationWindowBudget -= applicationBytesConsumed + networkWindowPadding;

                    applicationReplySlotOffset -= applicationBytesConsumed;

                    if (applicationReplySlotOffset != 0)
                    {
                        alignSlotBuffer(outAppBuffer, applicationBytesConsumed, applicationReplySlotOffset);
                    }
                }

            }

            if (applicationReplySlotOffset == 0 && tlsEngine.isInboundDone())
            {
                doEnd(applicationReply, applicationReplyId);
                if (networkWindowBudget == -1)
                {
                    doReset(networkReplyThrottle, networkReplyId);
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
            applicationWindowBudget += window.credit();
            networkWindowPadding = window.padding();

            if (applicationReplySlotOffset != 0)
            {
                try
                {
                    handleFlushAppData();
                }
                finally
                {
                    if (applicationReplySlotOffset == 0)
                    {
                        applicationPool.release(applicationReplySlot);
                        applicationReplySlot = NO_SLOT;
                    }
                }
            }

            if (networkReplySlotOffset != 0)
            {
                try
                {
                    unwrapNetworkBufferData();
                }
                finally
                {
                    if (networkReplySlotOffset == 0)
                    {
                        networkPool.release(networkReplySlot);
                        networkReplySlot = NO_SLOT;
                    }
                }
            }

            final int networkWindowCredit = window.credit() + networkWindowBudgetAdjustment;

            networkWindowBudget += Math.max(networkWindowCredit, 0);
            networkWindowBudgetAdjustment = Math.min(networkWindowCredit, 0);

            if (networkWindowCredit > 0)
            {
                doWindow(networkReplyThrottle, networkReplyId,
                         Math.max(networkWindowCredit, 0), networkWindowPadding);
            }
        }

        private void handleReset(
            ResetFW reset)
        {
            try
            {
                tlsEngine.closeInbound();
            }
            catch (SSLException ex)
            {
                // ignore and clean up
            }
            finally
            {
                doReset(networkReplyThrottle, networkReplyId);
            }
        }
    }

    private void flushNetwork(
        SSLEngine tlsEngine,
        int bytesProduced,
        MessageConsumer networkTarget,
        long networkId,
        Runnable networkReplyDoneHandler)
    {
        if (bytesProduced > 0)
        {
            final OctetsFW outNetOctets = outNetOctetsRO.wrap(outNetBuffer, 0, bytesProduced);
            doData(networkTarget, networkId, outNetOctets);
        }

        if (tlsEngine.isOutboundDone())
        {
            doEnd(networkTarget, networkId);
            networkReplyDoneHandler.run();
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
        MessageConsumer target,
        long targetId,
        long targetRef,
        long correlationId,
        String hostname,
        String applicationProtocol)
    {
        final BeginFW begin = beginRW.wrap(writeBuffer, 0, writeBuffer.capacity())
                                     .streamId(targetId)
                                     .source("tls")
                                     .sourceRef(targetRef)
                                     .correlationId(correlationId)
                                     .extension(e -> e.set(visitTlsBeginEx(hostname, applicationProtocol)))
                                     .build();

        target.accept(begin.typeId(), begin.buffer(), begin.offset(), begin.sizeof());
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
                .build();

        target.accept(data.typeId(), data.buffer(), data.offset(), data.sizeof());
    }

    private void doEnd(
        final MessageConsumer target,
        final long targetId)
    {
        final EndFW end = endRW.wrap(writeBuffer, 0, writeBuffer.capacity())
                .streamId(targetId)
                .build();

        target.accept(end.typeId(), end.buffer(), end.offset(), end.sizeof());
    }

    private void doAbort(
        final MessageConsumer target,
        final long targetId)
    {
        final AbortFW abort = abortRW.wrap(writeBuffer, 0, writeBuffer.capacity())
                .streamId(targetId)
                .build();

        target.accept(abort.typeId(), abort.buffer(), abort.offset(), abort.sizeof());
    }

    private void doWindow(
        final MessageConsumer throttle,
        final long throttleId,
        final int credit,
        final int padding)
    {
        final WindowFW window = windowRW.wrap(writeBuffer, 0, writeBuffer.capacity())
                .streamId(throttleId)
                .credit(credit)
                .padding(padding)
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

    private void doCloseOutbound(
        SSLEngine tlsEngine,
        MessageConsumer networkTarget,
        long networkId,
        Runnable networkReplyDoneHandler) throws SSLException
    {
        tlsEngine.closeOutbound();
        outNetByteBuffer.rewind();
        SSLEngineResult result = tlsEngine.wrap(inAppByteBuffer, outNetByteBuffer);
        flushNetwork(tlsEngine, result.bytesProduced(), networkTarget, networkId, networkReplyDoneHandler);
    }
}
