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
import static javax.net.ssl.SSLEngineResult.HandshakeStatus.FINISHED;
import static javax.net.ssl.SSLEngineResult.HandshakeStatus.NEED_WRAP;
import static javax.net.ssl.SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING;
import static javax.net.ssl.SSLEngineResult.Status.BUFFER_UNDERFLOW;
import static org.agrona.LangUtil.rethrowUnchecked;
import static org.reaktivity.nukleus.tls.internal.FrameFlags.FIN;
import static org.reaktivity.nukleus.tls.internal.FrameFlags.RST;
import static org.reaktivity.nukleus.tls.internal.FrameFlags.isEmpty;
import static org.reaktivity.nukleus.tls.internal.FrameFlags.isFin;
import static org.reaktivity.nukleus.tls.internal.FrameFlags.isReset;

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
import org.agrona.MutableDirectBuffer;
import org.agrona.collections.Long2ObjectHashMap;
import org.agrona.concurrent.UnsafeBuffer;
import org.reaktivity.nukleus.buffer.MemoryManager;
import org.reaktivity.nukleus.function.MessageConsumer;
import org.reaktivity.nukleus.function.MessageFunction;
import org.reaktivity.nukleus.function.MessagePredicate;
import org.reaktivity.nukleus.route.RouteManager;
import org.reaktivity.nukleus.stream.StreamFactory;
import org.reaktivity.nukleus.tls.internal.FrameFlags;
import org.reaktivity.nukleus.tls.internal.TlsConfiguration;
import org.reaktivity.nukleus.tls.internal.types.Flyweight;
import org.reaktivity.nukleus.tls.internal.types.ListFW;
import org.reaktivity.nukleus.tls.internal.types.OctetsFW;
import org.reaktivity.nukleus.tls.internal.types.control.RouteFW;
import org.reaktivity.nukleus.tls.internal.types.control.TlsRouteExFW;
import org.reaktivity.nukleus.tls.internal.types.stream.AckFW;
import org.reaktivity.nukleus.tls.internal.types.stream.BeginFW;
import org.reaktivity.nukleus.tls.internal.types.stream.RegionFW;
import org.reaktivity.nukleus.tls.internal.types.stream.TlsBeginExFW;
import org.reaktivity.nukleus.tls.internal.types.stream.TransferFW;

public final class ServerStreamFactory implements StreamFactory
{
    private static final ByteBuffer EMPTY_BYTE_BUFFER = ByteBuffer.allocate(0);
    private static final int MAXIMUM_HEADER_SIZE = 5 + 20 + 256;    // TODO version + MAC + padding
    private static final int MAXIMUM_PAYLOAD_LENGTH = (1 << Short.SIZE) - 1;
    private static final Runnable NOP = () -> {};

    private final RouteFW routeRO = new RouteFW();
    private final TlsRouteExFW tlsRouteExRO = new TlsRouteExFW();

    private final BeginFW beginRO = new BeginFW();
    private final TransferFW transferRO = new TransferFW();
    private final AckFW ackRO = new AckFW();

    private final BeginFW.Builder beginRW = new BeginFW.Builder();
    private final TransferFW.Builder transferRW = new TransferFW.Builder();
    private final AckFW.Builder ackRW = new AckFW.Builder();

    private final DirectBuffer view = new UnsafeBuffer(new byte[0]);
    private final MutableDirectBuffer directBufferRW = new UnsafeBuffer(new byte[0]);
    private final ByteBuffer inNetBuffer = allocateDirect(100000); // DPW TODO

    private final TlsBeginExFW.Builder tlsBeginExRW = new TlsBeginExFW.Builder();

    private final SSLContext context;
    private final RouteManager router;
    private final MutableDirectBuffer writeBuffer;
    private final LongSupplier supplyStreamId;
    private final LongSupplier supplyCorrelationId;
    private final MemoryManager memoryManager;

    private final Long2ObjectHashMap<ServerHandshake> correlations;
    private final MessageFunction<RouteFW> wrapRoute;
    private final ByteBuffer inAppByteBuffer;
    private final ByteBuffer outAppByteBuffer;
    private final ByteBuffer outNetByteBuffer;

    public ServerStreamFactory(
        TlsConfiguration config,
        SSLContext context,
        RouteManager router,
        MutableDirectBuffer writeBuffer,
        MemoryManager memoryManager,
        LongSupplier supplyStreamId,
        LongSupplier supplyCorrelationId,
        Long2ObjectHashMap<ServerHandshake> correlations)
    {
        this.context = requireNonNull(context);
        this.router = requireNonNull(router);
        this.writeBuffer = requireNonNull(writeBuffer);
        this.memoryManager = requireNonNull(memoryManager);
        this.supplyStreamId = requireNonNull(supplyStreamId);
        this.supplyCorrelationId = requireNonNull(supplyCorrelationId);
        this.correlations = requireNonNull(correlations);

        this.wrapRoute = this::wrapRoute;
        this.inAppByteBuffer = allocateDirect(writeBuffer.capacity());
        this.outAppByteBuffer = allocateDirect(writeBuffer.capacity());
        this.outNetByteBuffer = allocateDirect(Math.min(writeBuffer.capacity(), MAXIMUM_PAYLOAD_LENGTH));
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

        MessageConsumer newStream;

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
        final long authorization = begin.authorization();

        final MessagePredicate filter = (t, b, o, l) ->
        {
            final RouteFW route = routeRO.wrap(b, o, l);
            return networkRef == route.sourceRef() &&
                    acceptName.equals(route.source().asString());
        };

        final RouteFW route = router.resolve(authorization, filter, this::wrapRoute);

        MessageConsumer newStream = null;

        if (route != null)
        {
            final long networkId = begin.streamId();
            final SSLEngine tlsEngine = context.createSSLEngine();

            tlsEngine.setUseClientMode(false);
//            tlsEngine.setNeedClientAuth(true);

            newStream = new ServerAcceptStream(tlsEngine, networkThrottle, networkId, authorization, networkRef)::handleStream;
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

        private MessageConsumer applicationTarget;
        private long applicationId;
        private final long authorization;

        private MessageConsumer streamState;
        private ServerHandshake handshake;

        private long applicationCorrelationId;

        private long networkCorrelationId;

        private Runnable networkReplyDoneHandler = NOP;

        private final int outAppMemorySlotCapacity = 100000; // TODO
        private final long outAppMemorySlotAddress;
        private int outAppMemorySlotUsedOffset;

        private ServerAcceptStream(
            SSLEngine tlsEngine,
            MessageConsumer networkThrottle,
            long networkId,
            long authorization,
            long networkRef)
        {
            this.tlsEngine = tlsEngine;
            this.networkThrottle = networkThrottle;
            this.networkId = networkId;
            this.authorization = authorization;
            this.networkRef = networkRef;
            this.streamState = this::beforeBegin;
            this.outAppMemorySlotAddress = memoryManager.acquire(outAppMemorySlotCapacity);  // DPW TODO late initiation
            this.outAppMemorySlotUsedOffset = 0;
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
            if (isEmpty(begin.flags()))
            {
                try
                {
                    final String networkReplyName = begin.source().asString();
                    this.networkCorrelationId = begin.correlationId();

                    final MessageConsumer networkReply = router.supplyTarget(networkReplyName);
                    final long newNetworkReplyId = supplyStreamId.getAsLong();

                    final ServerHandshake newHandshake = new ServerHandshake(tlsEngine,
                            networkThrottle,
                            networkId,
                            networkReplyName,
                            networkReply,
                            newNetworkReplyId,
                            this::handleStatus,
                            this::handleNetworkReplyDone,
                            this::setNetworkReplyDoneHandler);

    //                doWindow(networkThrottle, networkId)

                    doBegin(networkReply, newNetworkReplyId, 0L, 0L, networkCorrelationId);
                    router.setThrottle(networkReplyName, newNetworkReplyId, newHandshake::handleThrottle);

                    this.streamState = newHandshake::afterBegin;
                    this.networkReplyName = networkReplyName;
                    this.networkReply = networkReply;
                    this.networkReplyId = newNetworkReplyId;
                    this.handshake = newHandshake;

                    tlsEngine.setHandshakeApplicationProtocolSelector(this::selectApplicationProtocol);

                    tlsEngine.beginHandshake();
//                    doAck(networkThrottle, networkId, FrameFlags.FIN);
                }
                catch (SSLException ex)
                {
                    doReset(networkThrottle, networkId);
//                    doTransfer(networkReply, networkReplyId, 0L, RST);
                }
            }
            else
            {
                doReset(networkThrottle, networkId);
            }
        }

        private String selectApplicationProtocol(
            SSLEngine tlsEngine,
            List<String> clientProtocols)
        {
            final MessagePredicate alpnFilter = (t, b, o, l) ->
            {
                final RouteFW route = routeRO.wrap(b, o, l);
                if (networkRef == route.sourceRef() && networkReplyName.equals(route.source().asString()))
                {
                    ExtendedSSLSession tlsSession = (ExtendedSSLSession) tlsEngine.getHandshakeSession();

                    List<SNIServerName> sniServerNames = tlsSession.getRequestedServerNames();
                    String peerHost = null;
                    if (sniServerNames.size() > 0)
                    {
                        SNIHostName sniHostName = (SNIHostName) sniServerNames.get(0);
                        peerHost = sniHostName.getAsciiName();
                    }

                    final TlsRouteExFW routeEx = route.extension().get(tlsRouteExRO::wrap);
                    final String routeHostname = routeEx.hostname().asString();
                    final String routeProtocol = routeEx.applicationProtocol().asString();

                    if (routeHostname == null || Objects.equals(peerHost, routeHostname))
                    {
                        return routeProtocol == null || clientProtocols.contains(routeProtocol);
                    }
                }
                return false;
            };

            RouteFW route = router.resolve(authorization, alpnFilter, wrapRoute);
            if (route != null)
            {
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
            case TransferFW.TYPE_ID:
                final TransferFW transfer = transferRO.wrap(buffer, index, index + length);
                handleTransfer(transfer);
                break;
//            case EndFW.TYPE_ID:
//                final EndFW end = endRO.wrap(buffer, index, index + length);
//                handleEnd(end);
//                break;
//            case AbortFW.TYPE_ID:
//                final AbortFW abort = abortRO.wrap(buffer, index, index + length);
//                handleAbort(abort);
//                break;
            default:
                throw new RuntimeException("Not implemented yet"); // DPW
//                doReset(networkThrottle, networkId);
//                break;
            }
        }

        private void handleTransfer(
            TransferFW transfer)
        {
            ListFW<RegionFW> regions = transfer.regions();
            inNetBuffer.clear();
            outAppByteBuffer.clear();
            if (!regions.isEmpty())
            {
                final ByteBuffer inNetBuffer = stageToInNetBuffer(regions);
                doAck(networkThrottle, networkId, FrameFlags.EMPTY, regions);
                try
                {
                        loop:
                        while (inNetBuffer.hasRemaining() && !tlsEngine.isInboundDone())
                        {
//                            outAppByteBuffer.reset();

                            SSLEngineResult result = tlsEngine.unwrap(inNetBuffer, outAppByteBuffer);

                            int bytesProduced = result.bytesProduced();
                            switch (result.getStatus())
                            {
                            case BUFFER_OVERFLOW:
                            case BUFFER_UNDERFLOW:
                                throw new RuntimeException("Not Implemented");
//                                final int totalBytesConsumed = inNetBuffer.position() - inNetBuffer.limit();
//                                final int totalBytesRemaining = inNetBuffer.remaining();
//                                if (networkSlotOffset == networkPool.slotCapacity() &&
//                                        result.getStatus() == BUFFER_UNDERFLOW)
//                                {
//                                    networkSlotOffset = 0;
//                                    doReset(networkThrottle, networkId);
//                                    doAbort(applicationTarget, applicationId, authorization);
//                                    doCloseInbound(tlsEngine);
//                                }
//                                else
//                                {
//                                    final int networkCredit =
//                                            Math.max(networkPool.slotCapacity() - networkSlotOffset - networkBudget, 0);
//
//                                    if (networkCredit > 0)
//                                    {
//                                        networkBudget += networkCredit;
//                                        doWindow(networkThrottle, networkId, networkCredit, networkPadding);
//                                    }
//                                }
//                                break loop;
                            default:
                                handleStatus(result.getHandshakeStatus(), r -> {});
                                break;
                            }

                            handleFlushAppData(bytesProduced);
                        }
                }
                catch (SSLException ex)
                {
                    doReset(networkThrottle, networkId);
                    doTransfer(applicationTarget, applicationId, authorization, RST);
                }
                finally
                {
                    //
                }
            }
            int flags = transfer.flags();
            if (isReset(flags))
            {
                handleAbort();
            }
            else if(isFin(flags))
            {
                handleEnd();
            }
        }

        private void handleEnd()
        {
            System.out.println("Its an end!");
            if (!tlsEngine.isInboundDone())
            {
                try
                {
                    doCloseInbound(tlsEngine);
                    doEnd(applicationTarget, applicationId, authorization);
                }
                catch (SSLException ex)
                {
                    doTransfer(applicationTarget, applicationId, authorization, RST);
                }
            }
        }

        private void handleAbort()
        {
            try
            {
                doCloseInbound(tlsEngine);
            }
            catch (SSLException ex)
            {
                // Ignore and clean up below
            }
            finally
            {
                doTransfer(applicationTarget, applicationId, authorization, RST);
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
                final RouteFW route = routeRO.wrap(b, o, l);
                final TlsRouteExFW routeEx = route.extension().get(tlsRouteExRO::wrap);
                final String hostname = routeEx.hostname().asString();
                final String applicationProtocol = routeEx.applicationProtocol().asString();

                return networkRef == route.sourceRef() &&
                        networkReplyName.equals(route.source().asString()) &&
                        (hostname == null || Objects.equals(tlsHostname, hostname)) &&
                        (applicationProtocol == null || Objects.equals(tlsApplicationProtocol, applicationProtocol));
            };

            final RouteFW route = router.resolve(authorization, filter, wrapRoute);

            if (route != null)
            {
                final String applicationName = route.target().asString();
                final MessageConsumer applicationTarget = router.supplyTarget(applicationName);
                final long applicationRef = route.targetRef();

                final long newCorrelationId = supplyCorrelationId.getAsLong();
                correlations.put(newCorrelationId, handshake);

                final long newApplicationId = supplyStreamId.getAsLong();

                doTlsBegin(applicationTarget, newApplicationId, authorization, applicationRef, newCorrelationId,
                    tlsHostname, tlsApplicationProtocol);
                router.setThrottle(applicationName, newApplicationId, this::handleThrottle);

                handshake.onFinished();

                this.applicationTarget = applicationTarget;
                this.applicationId = newApplicationId;
                this.applicationCorrelationId = newCorrelationId;

                this.streamState = this::afterHandshake;
                this.handshake = null;
            }
            else
            {
                // DPW TODO
//                doReset(networkThrottle, networkId);
//                doAbort(networkReply, networkReplyId, 0L);
            }
        }

        private void handleFlushAppData(int bytesProduced)
        {
            long unresolvedAddr = outAppMemorySlotAddress + outAppMemorySlotUsedOffset;
            long memoryAddress = memoryManager.resolve(unresolvedAddr);
            if (bytesProduced > 0)
            {
                stageInto(outAppByteBuffer, memoryAddress, 0, bytesProduced);
                doTransfer(
                        applicationTarget,
                        applicationId,
                        0L,
                        unresolvedAddr,
                        bytesProduced);
                outAppMemorySlotUsedOffset += bytesProduced;
            }
//            if (applicationSlotOffset > 0)
//            {
//                final MutableDirectBuffer outAppBuffer = applicationPool.buffer(applicationSlot);
//
//                final int applicationWindow = Math.min(
//                        applicationBudget - applicationPadding, MAXIMUM_PAYLOAD_LENGTH);
//
//                final int applicationBytesConsumed = Math.min(applicationSlotOffset, applicationWindow);
//
//                if (applicationBytesConsumed > 0)
//                {
//                    final OctetsFW outAppOctets = outAppOctetsRO.wrap(outAppBuffer, 0, applicationBytesConsumed);
//
//                    doData(applicationTarget, applicationId, applicationPadding, authorization, outAppOctets);
//
//                    applicationBudget -= applicationBytesConsumed + applicationPadding;
//
//                    applicationSlotOffset -= applicationBytesConsumed;
//
//                }
//
//                if (applicationSlotOffset != 0)
//                {
//                    alignSlotBuffer(outAppBuffer, applicationBytesConsumed, applicationSlotOffset);
//                }
//
//            }

            if (tlsEngine.isInboundDone())
            {
                doTransfer(applicationTarget, applicationId, authorization, FIN);
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
            case AckFW.TYPE_ID:
                final AckFW ack = ackRO.wrap(buffer, index, index + length);
                if (!ack.regions().isEmpty())
                {
                    ackRegions(ack);
                }
                if (isReset(ack.flags()))
                {
                    handleReset();
                    // TODO
                }
                break;
            default:
                // ignore
                break;
            }
        }

        private void ackRegions(AckFW ack)
        {
            // TODO
        }

        private void handleWindow()
        {
//            applicationBudget += window.credit();
//            applicationPadding = networkPadding = window.padding();
//
//            if (applicationSlotOffset != 0)
//            {
//                try
//                {
//                    handleFlushAppData();
//                }
//                finally
//                {
//                    if (applicationSlotOffset == 0)
//                    {
//                        applicationPool.release(applicationSlot);
//                        applicationSlot = NO_SLOT;
//                    }
//                }
//            }
//
//            if (networkSlotOffset != 0)
//            {
//                try
//                {
//                    unwrapNetworkBufferData();
//                }
//                catch (SSLException ex)
//                {
//                    doReset(networkThrottle, networkId);
//                    doAbort(applicationTarget, applicationId, authorization);
//                }
//                finally
//                {
//                    if (networkSlotOffset == 0)
//                    {
//                        networkPool.release(networkSlot);
//                        networkSlot = NO_SLOT;
//                    }
//                }
//            }
//
//            final int networkCredit = applicationBudget - networkBudget - networkSlotOffset;
//
//            if (networkCredit > 0)
//            {
//                networkBudget += networkCredit;
//                doWindow(networkThrottle, networkId, networkCredit, networkPadding);
//            }
        }

        private void handleReset()
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
                doReset(networkThrottle, networkId);
            }
        }

        private void handleNetworkDone()
        {
            doTransfer(applicationTarget, applicationId, authorization, FrameFlags.RST);
        }

        private void handleNetworkReplyDone()
        {
            correlations.remove(applicationCorrelationId);

            if (networkReplyDoneHandler != null)
            {
                networkReplyDoneHandler.run();
            }
        }

        private void setNetworkReplyDoneHandler(
            Runnable networkReplyDoneHandler)
        {
            this.networkReplyDoneHandler = networkReplyDoneHandler;
        }

    }

    public final class ServerHandshake
    {
        private final SSLEngine tlsEngine;
        private final BiConsumer<HandshakeStatus, Consumer<SSLEngineResult>> statusHandler;

        private final MessageConsumer networkThrottle;
        private final long networkId;
        private final String networkReplyName;
        private final MessageConsumer networkReply;
        private final long networkReplyId;
        private final Runnable networkReplyDoneHandler;
        private final Consumer<Runnable> networkReplyDoneHandlerConsumer;
        private final int outNetworkMemorySlotCapacity;
        private final long outNetworkMemorySlotAddress;
        private int outNetworkMemorySlotUsedOffset;

        private Consumer<AckFW> resetHandler;

        private ServerHandshake(
            SSLEngine tlsEngine,
            MessageConsumer networkThrottle,
            long networkId,
            String networkReplyName,
            MessageConsumer networkReply,
            long networkReplyId,
            BiConsumer<HandshakeStatus, Consumer<SSLEngineResult>> statusHandler,
            Runnable networkReplyDoneHandler,
            Consumer<Runnable> networkReplyDoneHandlerConsumer)
        {
            this.tlsEngine = tlsEngine;
            this.statusHandler = statusHandler;
            this.resetHandler = this::handleReset;
            this.networkReplyDoneHandler = networkReplyDoneHandler;

            this.networkThrottle = networkThrottle;
            this.networkId = networkId;
            this.networkReplyName = networkReplyName;
            this.networkReply = networkReply;
            this.networkReplyId = networkReplyId;
            this.networkReplyDoneHandlerConsumer = networkReplyDoneHandlerConsumer;

            this.outNetworkMemorySlotCapacity = 100000; // DPW TODO
            this.outNetworkMemorySlotAddress = memoryManager.acquire(outNetworkMemorySlotCapacity);
            this.outNetworkMemorySlotUsedOffset = 0;
        }

        private void onFinished()
        {
            // DPW TODO, need to be acked first...
            memoryManager.release(outNetworkMemorySlotAddress, outNetworkMemorySlotCapacity);
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
            case TransferFW.TYPE_ID:
                final TransferFW transfer = transferRO.wrap(buffer, index, index + length);
                handleTransfer(transfer);
                break;
//            case EndFW.TYPE_ID:
//                final EndFW end = endRO.wrap(buffer, index, index + length);
//                handleEnd(end);
//                break;
//            case AbortFW.TYPE_ID:
//                final AbortFW abort = abortRO.wrap(buffer, index, index + length);
//                handleAbort(abort);
//                break;
            default:
                doReset(networkThrottle, networkId);
                break;
            }
        }

        private void handleTransfer(
            TransferFW transfer)
        {
            final ListFW<RegionFW> regions = transfer.regions();
            inNetBuffer.clear();
            try
            {
                if (!regions.isEmpty())
                {
                    final ByteBuffer inNetBuffer = stageToInNetBuffer(regions);
                    loop:
                    while (inNetBuffer.hasRemaining() && !tlsEngine.isInboundDone())
                    {

                        inNetBuffer.rewind();
                        HandshakeStatus handshakeStatus = NOT_HANDSHAKING;
                        SSLEngineResult.Status status = BUFFER_UNDERFLOW;
                        if (tlsEngine.getHandshakeStatus() != NOT_HANDSHAKING && tlsEngine.getHandshakeStatus() != FINISHED)
                        {
                            SSLEngineResult result = tlsEngine.unwrap(inNetBuffer, outAppByteBuffer);
                            status = result.getStatus();
                            handshakeStatus = result.getHandshakeStatus();
                        }

                        if (outAppByteBuffer.position() != 0)
                        {
                            doReset(networkThrottle, networkId);
                            doTransfer(networkReply, networkReplyId, transfer.authorization(), RST);
                            break loop;
                        }

                        switch (status)
                        {
                            case BUFFER_UNDERFLOW:
                                throw new RuntimeException("Not implemented");
                            default:
                                statusHandler.accept(handshakeStatus, this::flushNetworkHandshake);
                                break;
                        }
                    }
                    doAck(networkThrottle, networkId, FrameFlags.EMPTY, regions);
                }
                int flags = transfer.flags();
                if (isReset(flags))
                {
                    tlsEngine.closeOutbound();
                }
                else if(FrameFlags.isFin(flags))
                {
                    handleEnd();
                }
            }
            catch (Exception e)
            {
                e.printStackTrace();
                doAck(networkThrottle, networkId, RST, regions);
//                doAbort(target, targetId, authorization); TODO
            }
            if (isReset(transfer.flags()))
            {
                System.out.println("oh really"); // DPW to remove
//                doTransfer(this., targetId, authorization, flags);
            }
            if (isFin(transfer.flags()))
            {
                System.out.println("oh really 2"); // DPW to remove
//                doTransfer(this., targetId, authorization, flags);
            }
        }

        private void flushNetworkHandshake(
            SSLEngineResult result)
        {
            final int bytesProduced = result.bytesProduced();
            if (bytesProduced != 0)
            {
                long unresolvedAddr = outNetworkMemorySlotAddress + outNetworkMemorySlotUsedOffset;
                long memoryAddress = memoryManager.resolve(unresolvedAddr);
                stageInto(
                    outNetByteBuffer,
                    memoryAddress,
                    0,
                    bytesProduced);
                doTransfer(
                    networkReply,
                    networkReplyId,
                    0L,
                    unresolvedAddr,
                    bytesProduced);
                outNetworkMemorySlotUsedOffset += bytesProduced;
            }
        }

        private void handleEnd()
        {
//            try
//            {
//                doCloseOutbound(tlsEngine, networkReply, networkReplyId, networkReplyPadding, end.authorization(), NOP);
//            }
//            catch (SSLException ex)
//            {
//                doAbort(networkReply, networkReplyId, 0L);
//            }
        }

//        private void updateNetworkReplyWindow(// TODO rename
//            SSLEngineResult result)
//        {
//            final int bytesProduced = result.bytesProduced();
//            if (bytesProduced != 0)
//            {
//                flushNetwork(
//                    tlsEngine,
//                    result.bytesProduced(),
//                    networkReply,
//                    networkReplyId,
//                    0,
//                    0L,
//                    networkReplyDoneHandler);
//            }
//        }

        private void setNetworkThrottle(
            MessageConsumer newNetworkThrottle)
        {
            router.setThrottle(networkReplyName, networkReplyId, newNetworkThrottle);


            //doWindow(newNetworkThrottle, networkReplyId, outNetworkWindowBudget, outNetworkWindowPadding);
        }

        private void setNetworkReplyDoneHandler(
            Runnable networkReplyDoneHandler)
        {
            networkReplyDoneHandlerConsumer.accept(networkReplyDoneHandler);
        }

        private void handleThrottle(
            int msgTypeId,
            DirectBuffer buffer,
            int index,
            int length)
        {
                switch (msgTypeId)
                {
                case AckFW.TYPE_ID:
                    final AckFW ack = ackRO.wrap(buffer, index, index + length);
                    if (!ack.regions().isEmpty())
                    {
                        ackRegions(ack);
                    }
                    if (isReset(ack.flags()))
                    {
                        resetHandler.accept(ack);
                    }
                    break;
                default:
                    // ignore
                    break;
                }
        }

        private void ackRegions(AckFW ack)
        {
            // TODO Auto-generated method stub
        }

        private void handleReset(
            AckFW reset)
        {
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
                networkReplyDoneHandler.run();
            }
        }

        private void handleResetAfterHandshake(
            AckFW reset)
        {
            networkReplyDoneHandler.run();
        }
    }

    private final class ServerConnectReplyStream
    {
        private final long applicationReplyId;

        private MessageConsumer applicationReplyThrottle;

        private MessageConsumer networkReply;
        private long networkReplyId;

        private MessageConsumer streamState;
        private SSLEngine tlsEngine;
        private BiConsumer<HandshakeStatus, Consumer<SSLEngineResult>> statusHandler;

        private long outNetworkMemorySlotAddress;
        private int outNetworkMemorySlotUsedOffset;

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
            case TransferFW.TYPE_ID:
                final TransferFW transfer = transferRO.wrap(buffer, index, index + length);
                handleTransfer(transfer);
                break;
//            case EndFW.TYPE_ID:
//                final EndFW end = endRO.wrap(buffer, index, index + length);
//                handleEnd(end);
//                break;
//            case AbortFW.TYPE_ID:
//                final AbortFW abort = abortRO.wrap(buffer, index, index + length);
//                handleAbort(abort);
//                break;
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
                this.networkReply = handshake.networkReply;
                this.networkReplyId = handshake.networkReplyId;
                this.statusHandler = handshake.statusHandler;

                this.outNetworkMemorySlotAddress = handshake.outNetworkMemorySlotCapacity;
                this.outNetworkMemorySlotUsedOffset = handshake.outNetworkMemorySlotUsedOffset;

                doAck(applicationReplyThrottle, applicationReplyId, 0);
                handshake.setNetworkThrottle(this::handleThrottle);
                handshake.setNetworkReplyDoneHandler(this::handleNetworkReplyDone);
            }
            else
            {
                doReset(applicationReplyThrottle, applicationReplyId);
            }
        }

        private void handleTransfer(
            TransferFW transfer)
        {
            ListFW<RegionFW> regions = transfer.regions();
            if (!regions.isEmpty())
            {
                try
                {
                    // Note: inAppBuffer is emptied by SslEngine.wrap(...)
                    //       so should be able to eliminate copy (stateless)
                    inAppByteBuffer.clear();
                    stageToInAppBuffer(regions);

                    while (inAppByteBuffer.hasRemaining() && !tlsEngine.isOutboundDone())
                    {
                        outNetByteBuffer.rewind();
                        SSLEngineResult result = tlsEngine.wrap(inAppByteBuffer, outNetByteBuffer);
//                        flushNetwork(tlsEngine, result.bytesProduced(), networkReply, networkReplyId, networkReplyPadding,
//                                data.authorization(), this::handleNetworkReplyDone); // DPW TODO handle end?
                        int bytesProduced = result.bytesProduced();
                        long unresolvedAddr = outNetworkMemorySlotAddress + outNetworkMemorySlotUsedOffset;
                        long memoryAddress = memoryManager.resolve(unresolvedAddr);
                        stageInto(outNetByteBuffer, memoryAddress, 0, bytesProduced);
                        doTransfer(networkReply, networkReplyId, transfer.authorization(), unresolvedAddr, bytesProduced);
                        statusHandler.accept(result.getHandshakeStatus(), r -> {});
//                        statusHandler.accept(result.getHandshakeStatus(), this::updateNetworkWindow);
                    }
                }
                catch (SSLException ex)
                {
                    // DPW TODO
    //                doReset(applicationReplyThrottle, applicationReplyId);
    //                doAbort(networkReply, networkReplyId, 0L);
                }
            }
            final int flags = transfer.flags();
            if (FrameFlags.isFin(flags))
            {
                handleEnd(transfer);
            }
            if (FrameFlags.isReset(flags))
            {
                handleAbort();
            }
        }

        private void handleEnd(TransferFW transfer)
        {
            applicationReplyThrottle = null;
            try
            {
                doCloseOutbound(
                    tlsEngine,
                    networkReply,
                    networkReplyId,
                    transfer.authorization(),
                    this::handleNetworkReplyDone,
                    this.outNetworkMemorySlotAddress,
                    this.outNetworkMemorySlotUsedOffset);
            }
            catch (SSLException ex)
            {
                // END is from application reply, so no need to clean that stream
                doTransfer(networkReply, networkReplyId, transfer.authorization(), FIN);
            }
        }

        private void handleAbort()
        {
            tlsEngine.closeOutbound();
//
//            // ABORT is from application reply, so no need to clean that stream
            doTransfer(networkReply, networkReplyId, 0L, RST);
        }


        private void handleThrottle(
            int msgTypeId,
            DirectBuffer buffer,
            int index,
            int length)
        {
            switch (msgTypeId)
            {
            case AckFW.TYPE_ID:
                final AckFW ack = ackRO.wrap(buffer, index, index + length);
                if (!ack.regions().isEmpty())
                {
                    ackRegions(ack);
                }
                if (isReset(ack.flags()))
                {
                    handleReset();
                    // TODO
                }
                break;
            default:
                // ignore
                break;
            }
        }

        private void ackRegions(AckFW ack)
        {
            // DPW TODO
        }

        private void sendApplicationReplyWindow()
        {
//            int applicationReplyCredit = networkReplyBudget - applicationReplyBudget;
//            if (applicationReplyCredit > 0)
//            {
//                applicationReplyBudget += applicationReplyCredit;
//                doWindow(applicationReplyThrottle, applicationReplyId, applicationReplyCredit,
//                        applicationReplyPadding);
//            }
        }

        private void handleReset()
        {
            tlsEngine.closeOutbound();

            // RESET is from network reply, so no need to clean that stream
            handleNetworkReplyDone();
        }

        private void handleNetworkReplyDone()
        {
            if (applicationReplyThrottle != null)
            {
                doReset(applicationReplyThrottle, applicationReplyId);
            }
        }

    }

    private void flushNetwork(
        SSLEngine tlsEngine,
        int bytesProduced,
        MessageConsumer networkReply,
        long networkReplyId,
        long authorization,
        Runnable networkReplyDoneHandler,
        long outNetworkMemorySlotAddress,
        int outNetworkMemorySlotUsedOffset)
    {
        if (bytesProduced > 0)
        {
            long unresolvedAddr = outNetworkMemorySlotAddress + outNetworkMemorySlotUsedOffset;
            long memoryAddress = memoryManager.resolve(unresolvedAddr);
            stageInto(outNetByteBuffer, memoryAddress, 0, bytesProduced);
            doTransfer(networkReply, networkReplyId, authorization, unresolvedAddr, bytesProduced);
        }

        if (tlsEngine.isOutboundDone())
        {
            doEnd(networkReply, networkReplyId, authorization);
            networkReplyDoneHandler.run();      // sends RESET to application reply stream (if not received END)
        }
    }

    private void doTlsBegin(
        MessageConsumer connect,
        long connectId,
        long authorization,
        long connectRef,
        long correlationId,
        String hostname,
        String applicationProtocol)
    {
        final BeginFW begin = beginRW.wrap(writeBuffer, 0, writeBuffer.capacity())
                                     .streamId(connectId)
                                     .authorization(authorization)
                                     .source("tls")
                                     .sourceRef(connectRef)
                                     .correlationId(correlationId)
                                     .extension(e -> e.set(visitTlsBeginEx(hostname, applicationProtocol)))
                                     .build();

        connect.accept(begin.typeId(), begin.buffer(), begin.offset(), begin.sizeof());
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
        final long authorization,
        final long targetRef,
        final long correlationId)
    {
        final BeginFW begin = beginRW.wrap(writeBuffer, 0, writeBuffer.capacity())
                .streamId(targetId)
                .authorization(authorization)
                .source("tls")
                .sourceRef(targetRef)
                .correlationId(correlationId)
                .build();

        target.accept(begin.typeId(), begin.buffer(), begin.offset(), begin.sizeof());
    }

    private void doTransfer(
        final MessageConsumer target,
        final long targetId,
        final long authorization,
        long address,
        int length)
    {
        final TransferFW transfer = transferRW.wrap(writeBuffer, 0, writeBuffer.capacity())
            .streamId(targetId)
            .authorization(authorization)
            .regions(b -> b.item(b2 -> b2.address(address).length(length).streamId(targetId)))
            .build();
        target.accept(transfer.typeId(), transfer.buffer(), transfer.offset(), transfer.sizeof());
    }

    private void doData(
        final MessageConsumer target,
        final long targetId,
        final int padding,
        final long authorization,
        final OctetsFW payload)
    {
//        final WriteFW data = writeFW.wrap(writeBuffer, 0, writeBuffer.capacity())
//                .streamId(targetId)
//                .authorization(authorization)
//                .groupId(0)
//                .padding(padding)
//                .payload(p -> p.set(payload.buffer(), payload.offset(), payload.sizeof()))
//                .build();
//
//        target.accept(data.typeId(), data.buffer(), data.offset(), data.sizeof());
    }

    private void doEnd(
        final MessageConsumer target,
        final long targetId,
        final long authorization)
    {
//        final EndFW end = endRW.wrap(writeBuffer, 0, writeBuffer.capacity())
//                .streamId(targetId)
//                .authorization(authorization)
//                .build();
//
//        target.accept(end.typeId(), end.buffer(), end.offset(), end.sizeof());
    }

    private void doTransfer(
        final MessageConsumer target,
        final long targetId,
        final long authorization,
        final int flags)
    {
        final TransferFW transfer = transferRW.wrap(writeBuffer, 0, writeBuffer.capacity())
            .streamId(targetId)
            .authorization(authorization)
            .flags(flags)
            .build();
        target.accept(transfer.typeId(), transfer.buffer(), transfer.offset(), transfer.sizeof());
    }

    private void doWindow(
        final MessageConsumer throttle,
        final long throttleId,
        final int credit,
        final int padding)
    {
//        final WindowFW window = windowRW.wrap(writeBuffer, 0, writeBuffer.capacity())
//                .streamId(throttleId)
//                .credit(credit)
//                .padding(padding)
//                .groupId(0)
//                .build();
//
//        throttle.accept(window.typeId(), window.buffer(), window.offset(), window.sizeof());
    }

    private void doAck(
            final MessageConsumer throttle,
            final long throttleId,
            final int flags,
            final ListFW<RegionFW> regions)
    {
        final AckFW ack = ackRW.wrap(writeBuffer, 0, writeBuffer.capacity())
                               .streamId(throttleId)
                               .flags(flags)
                               .regions(b -> regions.forEach(
                                             r -> b.item(
                                                 b2 -> b2.address(r.address())
                                                         .length(r.length())
                                                         .streamId(r.streamId()))))
                               .build();
        throttle.accept(ack.typeId(), ack.buffer(), ack.offset(), ack.sizeof());
    }

    private void doAck(
        final MessageConsumer throttle,
        final long throttleId,
        final int flags)
    {
        final AckFW ack = ackRW.wrap(writeBuffer, 0, writeBuffer.capacity())
                .streamId(throttleId)
                .flags(flags)
                .build();
        throttle.accept(ack.typeId(), ack.buffer(), ack.offset(), ack.sizeof());
    }

//    private void doAck(
//            final MessageConsumer throttle,
//            final long throttleId,
//            final int flags)
//    {
//        final AckFW ack = ackRW.wrap(writeBuffer, 0, writeBuffer.capacity())
//                .streamId(throttleId)
//                .flags(flags)
//                .build();
//        throttle.accept(ack.typeId(), ack.buffer(), ack.offset(), ack.sizeof());
//    }


    private void doReset(
        final MessageConsumer throttle,
        final long throttleId)
    {
        doAck(throttle, throttleId, RST);
    }

    private void doCloseInbound(
        final SSLEngine tlsEngine) throws SSLException
    {
        tlsEngine.closeInbound();
    }

    private void doCloseOutbound(
        SSLEngine tlsEngine,
        MessageConsumer networkReply,
        long networkReplyId,
        long authorization,
        Runnable networkReplyDoneHandler,
        long outNetworkMemorySlotAddress,
        int outNetworkMemorySlotUsedOffset) throws SSLException
    {
        tlsEngine.closeOutbound();
        outNetByteBuffer.rewind();
        SSLEngineResult result = tlsEngine.wrap(inAppByteBuffer, outNetByteBuffer);
        flushNetwork(tlsEngine, result.bytesProduced(), networkReply, networkReplyId,
                authorization, networkReplyDoneHandler, outNetworkMemorySlotAddress, outNetworkMemorySlotUsedOffset);
    }

    // TODO combine logic DPW
    private void addToInNetBuffer(RegionFW region)
    {
        final int length = region.length();
        final int position = inNetBuffer.position();

        view.wrap(memoryManager.resolve(region.address()), length);
        view.getBytes(0, inNetBuffer, position, length);
        inNetBuffer.position(position + length);
    }

    // TODO combine logic DPW
    private ByteBuffer stageToInNetBuffer(ListFW<RegionFW> regions)
    {
        regions.forEach(this::addToInNetBuffer);
        inNetBuffer.flip();
        return inNetBuffer;
    }

    // TODO combine logic DPW
    private void addToInAppBuffer(RegionFW region)
    {
        final int length = region.length();
        final int position = inAppByteBuffer.position();

        view.wrap(memoryManager.resolve(region.address()), length);
        view.getBytes(0, inAppByteBuffer, position, length);
        inAppByteBuffer.position(position + length);
    }

    // TODO combine logic DPW
    private ByteBuffer stageToInAppBuffer(ListFW<RegionFW> regions)
    {
        regions.forEach(this::addToInAppBuffer);
        inAppByteBuffer.flip();
        return inAppByteBuffer;
    }

    public void stageInto(
        ByteBuffer buf,
        long address,
        int offset,
        int length)
    {
        buf.flip();
        directBufferRW.wrap(address, length);
        directBufferRW.putBytes(0, buf, length);
    }

}
