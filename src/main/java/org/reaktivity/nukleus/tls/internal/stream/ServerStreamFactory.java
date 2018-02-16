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
import static org.reaktivity.nukleus.tls.internal.FrameFlags.EMPTY;
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
import org.agrona.collections.IntArrayList;
import org.agrona.collections.Long2ObjectHashMap;
import org.agrona.collections.LongArrayList;
import org.agrona.concurrent.UnsafeBuffer;
import org.reaktivity.nukleus.buffer.MemoryManager;
import org.reaktivity.nukleus.function.MessageConsumer;
import org.reaktivity.nukleus.function.MessageFunction;
import org.reaktivity.nukleus.function.MessagePredicate;
import org.reaktivity.nukleus.route.RouteManager;
import org.reaktivity.nukleus.stream.StreamFactory;
import org.reaktivity.nukleus.tls.internal.FrameFlags;
import org.reaktivity.nukleus.tls.internal.TlsConfiguration;
import org.reaktivity.nukleus.tls.internal.stream.util.AckedRegionBuilder;
import org.reaktivity.nukleus.tls.internal.types.Flyweight;
import org.reaktivity.nukleus.tls.internal.types.ListFW;
import org.reaktivity.nukleus.tls.internal.types.ListFW.Builder;
import org.reaktivity.nukleus.tls.internal.types.control.RouteFW;
import org.reaktivity.nukleus.tls.internal.types.control.TlsRouteExFW;
import org.reaktivity.nukleus.tls.internal.types.stream.AckFW;
import org.reaktivity.nukleus.tls.internal.types.stream.BeginFW;
import org.reaktivity.nukleus.tls.internal.types.stream.RegionFW;
import org.reaktivity.nukleus.tls.internal.types.stream.TlsBeginExFW;
import org.reaktivity.nukleus.tls.internal.types.stream.TransferFW;

public final class ServerStreamFactory implements StreamFactory
{
    public static final int TRANSFER_CAPACITY = 0x10000;  // TODO: configurable
    private static final ByteBuffer EMPTY_BYTE_BUFFER = ByteBuffer.allocate(0);
    private static final int MAXIMUM_PAYLOAD_LENGTH = (1 << Short.SIZE) - 1;
    private static final Runnable RUNNABLE_NOP = () -> {};
    private static final Consumer<SSLEngineResult> HANDSHAKE_NOOP = (r) -> {};

    private final RouteFW routeRO = new RouteFW();
    private final TlsRouteExFW tlsRouteExRO = new TlsRouteExFW();

    private final BeginFW beginRO = new BeginFW();
    private final TransferFW transferRO = new TransferFW();
    private final AckFW ackRO = new AckFW();
    private final ListFW<RegionFW> regionsRO = new ListFW<RegionFW>(new RegionFW());

    private final BeginFW.Builder beginRW = new BeginFW.Builder();
    private final TransferFW.Builder transferRW = new TransferFW.Builder();
    private final AckFW.Builder ackRW = new AckFW.Builder();
    private final ListFW.Builder<RegionFW.Builder, RegionFW> regionsRW = new Builder<RegionFW.Builder, RegionFW>(
            new RegionFW.Builder(),
            new RegionFW());

    private final DirectBuffer view = new UnsafeBuffer(new byte[0]);
    private final MutableDirectBuffer directBufferRW = new UnsafeBuffer(new byte[0]);
    private final ByteBuffer inNetBuffer = allocateDirect(100000); // TODO: configurable

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

        private MessageConsumer applicationTarget;
        private long applicationId;
        private final long authorization;

        private MessageConsumer streamState;
        private ServerHandshake handshake;

        private long applicationCorrelationId;

        private long networkCorrelationId;

        private Runnable networkReplyDoneHandler = RUNNABLE_NOP;
        private Consumer<SSLEngineResult> closingHandshakeHandler = HANDSHAKE_NOOP;

        private final LongArrayList networkPendingRegionAddresses = new LongArrayList(2, -2);
        private final IntArrayList networkPendingRegionLengths = new IntArrayList(2, -2);

        private NetworkReplyMemoryManager networkReplyMemoryManger;

        private MessageConsumer networkReply;
        private long networkReplyId;

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
                try
                {
                    doCloseInbound(tlsEngine);
                }
                catch (SSLException ex)
                {
                    // NOOP
                }
                finally
                {
                    doAck(networkThrottle, networkId, RST);
                }
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

                    this.networkReply = router.supplyTarget(networkReplyName);
                    this.networkReplyId = supplyStreamId.getAsLong();

                    this.networkReplyMemoryManger = new NetworkReplyMemoryManager();

                    final ServerHandshake newHandshake = new ServerHandshake(
                            tlsEngine,
                            networkThrottle,
                            networkId,
                            networkReplyName,
                            networkReply,
                            networkReplyId,
                            this::handleStatus,
                            this::handleNetworkReplyDone,
                            this::setNetworkReplyDoneHandler,
                            this.networkPendingRegionAddresses,
                            this.networkPendingRegionLengths,
                            this::consumedRegions,
                            networkReplyMemoryManger,
                            this::setOnNetworkClosingHandshakeHandler);

                    doBegin(networkReply, networkReplyId, 0L, 0L, networkCorrelationId);
                    router.setThrottle(networkReplyName, networkReplyId, newHandshake::handleThrottle);

                    this.streamState = newHandshake::afterBegin;
                    this.networkReplyName = networkReplyName;
                    this.handshake = newHandshake;

                    tlsEngine.setHandshakeApplicationProtocolSelector(this::selectApplicationProtocol);

                    tlsEngine.beginHandshake();
                }
                catch (SSLException ex)
                {
                    // TODO testing
                    doTransfer(applicationTarget, applicationId, authorization, RST);
                }
            }
            else
            {
                doAck(networkThrottle, networkId, RST);
            }
        }

        public void setOnNetworkClosingHandshakeHandler(
            Consumer<SSLEngineResult> closingHandshakeHandler)
        {
            this.closingHandshakeHandler = closingHandshakeHandler;
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
            default:
                doAck(networkThrottle, networkId, RST);
            }
        }

        private void handleTransfer(
            TransferFW transfer)
        {
            transfer.regions().forEach(
            r ->
            {
                networkPendingRegionAddresses.add(r.address());
                networkPendingRegionLengths.add(r.length());
            });

            processNetwork();

            final int flags = transfer.flags();
            if (isReset(flags))
            {
                handleAbort();
            }
            else if(isFin(flags))
            {
                handleEnd();
            }
        }

        private void processNetwork()
        {
            if (networkPendingRegionAddresses.isEmpty())
            {
                return;
            }

            inNetBuffer.clear();
            outAppByteBuffer.clear();

            final ByteBuffer inNetBuffer = stageInNetBuffer(
                this.networkPendingRegionAddresses,
                this.networkPendingRegionLengths);
            try
            {
                if (tlsEngine.isOutboundDone())
                {
                    this.closingHandshakeHandler = r -> {};
                }

                int bytesConsumerIter = 0;
                loop:
                while (inNetBuffer.hasRemaining() && !tlsEngine.isInboundDone())
                {
                    SSLEngineResult result = tlsEngine.unwrap(inNetBuffer, outAppByteBuffer);

                    int bytesProduced = result.bytesProduced();
                    switch (result.getStatus())
                    {
                    case BUFFER_OVERFLOW:
                    case BUFFER_UNDERFLOW:
                         break loop;
                    default:
                        handleStatus(result.getHandshakeStatus(), closingHandshakeHandler);
                        break;
                    }

                    int totalBytesConsumed = inNetBuffer.position();
                    final int flags = tlsEngine.isInboundDone()? FIN : EMPTY;
                    if (bytesProduced == 0 && totalBytesConsumed > 0)
                    {
                        assert tlsEngine.isInboundDone();
                        doAck(networkThrottle, networkId, EMPTY, rb ->
                        {
                            while (this.networkPendingRegionAddresses.size() > 0)
                            {
                                rb.item(r -> r.address(networkPendingRegionAddresses.remove(0))
                                              .length(networkPendingRegionLengths.remove(0))
                                              .streamId(networkId));
                            }
                        });
                        doTransfer(applicationTarget, applicationId, authorization, FIN);
                    }
                    else if (bytesProduced > 0)
                    {
                        handleFlushAppData(bytesProduced, totalBytesConsumed - bytesConsumerIter, flags);
                    }
                    bytesConsumerIter = totalBytesConsumed;
                }
            }
            catch (SSLException ex)
            {
                doAck(networkThrottle, networkId, RST);
                doTransfer(applicationTarget, applicationId, authorization, RST);
            }
            finally
            {
                //
            }
        }

        private Consumer<Builder<RegionFW.Builder, RegionFW>> consumedRegions(
            int totalBytesConsumed)
        {
            return b ->
            {
                int toAck = totalBytesConsumed;
                while (toAck > 0)
                {
                    int nextLength = networkPendingRegionLengths.get(0);
                    if (nextLength <= toAck)
                    {
                        b.item(r ->
                            r.address(networkPendingRegionAddresses.remove(0))
                             .length(networkPendingRegionLengths.remove(0))
                             .streamId(networkId));
                    }
                    else
                    {
                        nextLength -= toAck;
                        int length = networkPendingRegionLengths.get(0);
                        b.item(r -> r.address(networkPendingRegionAddresses.get(0))
                                     .length(length)
                                     .streamId(networkId));
                    }
                    toAck -= nextLength;
                }
            };
        }

        private void doApplicationClosingHandshake(SSLEngineResult r)
        {
            final int bytesToWrite = r.bytesProduced();
            if (bytesToWrite > 0)
            {
                final long address = networkReplyMemoryManger.address();
                final long rAddress = networkReplyMemoryManger.resolvedAddress();
                directBufferRW.wrap(rAddress, bytesToWrite);
                directBufferRW.putBytes(0, outNetByteBuffer, 0, outNetByteBuffer.position());
                networkReplyMemoryManger.consumeBytes(bytesToWrite);
                networkReplyMemoryManger.markEmptyRegions();
                doTransfer(
                        networkReply,
                        networkReplyId,
                        0L, // TODO proper authorization
                        rb -> rb.item(r2 -> r2.address(address)
                                              .length(bytesToWrite)
                                              .streamId(networkReplyId)),
                        EMPTY);
            }
        };

        private void handleEnd()
        {
            if (!tlsEngine.isInboundDone())
            {
                try
                {
                    doCloseInbound(tlsEngine);
                    doTransfer(applicationTarget, applicationId, authorization, FrameFlags.FIN);
                }
                catch (SSLException ex)
                {
                    doTransfer(applicationTarget, applicationId, authorization, RST);
                }
            }
            else
            {
                doAck(networkThrottle, networkId, FIN);
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
                    this.setOnNetworkClosingHandshakeHandler(this::doApplicationClosingHandshake);
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
                doTransfer(networkReply, networkReplyId, authorization, RST);
                doAck(networkThrottle, networkId, RST);
            }
        }

        // writes to right and ack back remaining
        private void handleFlushAppData(
            int bytesProduced,
            int bytesConsumed,
            int flags)
        {
            if (bytesConsumed - bytesProduced > 0)
            {
                doAck(
                    networkThrottle,
                    networkId,
                    EMPTY,
                    rb ->
                    {
                        int bytesToAck = bytesConsumed - bytesProduced;
                        while(bytesToAck > 0)
                        {
                            int availableLength = networkPendingRegionLengths.get(0);
                            final boolean ackWholeRegion = bytesToAck > availableLength;
                            final long uAddress = ackWholeRegion ? networkPendingRegionAddresses.remove(0):
                                                                   networkPendingRegionAddresses.get(0);
                            if (ackWholeRegion)
                            {
                                networkPendingRegionLengths.remove(0);
                            }
                            else
                            {
                                networkPendingRegionLengths.set(0, availableLength - bytesToAck);
                                availableLength = bytesToAck;
                            }
                            final int lengthAcked = availableLength;
                            rb.item(r -> r.address(uAddress).length(lengthAcked).streamId(networkId));
                            bytesToAck -= lengthAcked;
                        }
                    }
                );
            }

            doTransfer(
                applicationTarget,
                applicationId,
                0L,
                rb ->
                {
                    int bytesToWrite = bytesProduced;
                    while (bytesToWrite > 0)
                    {
                        int availableLength = networkPendingRegionLengths.get(0);
                        final boolean useWholeRegion = availableLength < bytesToWrite;
                        final Long uAddress = useWholeRegion ? networkPendingRegionAddresses.remove(0):
                                                               networkPendingRegionAddresses.get(0);
                        if (useWholeRegion)
                        {
                            networkPendingRegionLengths.remove(0);
                        }
                        else
                        {
                            networkPendingRegionLengths.set(0, availableLength - bytesToWrite);
                            availableLength = bytesToWrite;
                        }
                        directBufferRW.wrap(
                            memoryManager.resolve(uAddress),
                            availableLength);
                        directBufferRW.putBytes(0, outAppByteBuffer, bytesProduced - bytesToWrite, availableLength);
                        final int lengthWritten = availableLength;
                        rb.item(r -> r.address(uAddress).length(lengthWritten).streamId(networkId));
                        bytesToWrite -= lengthWritten;
                    }
                },
              flags);
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
                    final ListFW<RegionFW> regions = ack.regions();
                    final int flags = ack.flags();
                    if (isReset(flags))
                    {
                        try
                        {
                            doCloseInbound(tlsEngine);
                        }
                        catch (SSLException ex)
                        {
                            // NOOP
                        }
                        doAck(networkThrottle, networkId, RST);
                    }
                    else if (isFin(flags))
                    {
                        doAck(networkThrottle, networkId, FIN);
                    }

                    if (!(regions.isEmpty() && FrameFlags.isEmpty(flags)))
                    {
                        doAck(
                            networkThrottle,
                            networkId,
                            EMPTY,
                            rsb ->
                            {
                                regions.forEach(r ->
                                {
                                    rsb.item(rb -> rb.address(r.address())
                                                      .length(r.length())
                                                      .streamId(r.streamId()));
                                });
                            });
                    }
                    break;
                default:
                    // ignore
                    break;
            }
        }

        private void handleNetworkReplyDone()
        {
            correlations.remove(applicationCorrelationId);

            networkReplyMemoryManger.releaseHard();

            if (networkReplyDoneHandler != null)
            {
                networkReplyDoneHandler.run();
            }

            doTransfer(applicationTarget, applicationId, authorization, RST);
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
        private final Consumer<Consumer<SSLEngineResult>> setOnNetworkClosingHandshakeHandler;
        private NetworkReplyMemoryManager networkReplyMemoryManager;

        private final LongArrayList networkPendingRegions;
        private final IntArrayList networkPendingLengths;

        private final AckedRegionBuilder ackRegionBuilder;

        private Consumer<AckFW> resetHandler;

        private final LongArrayList applicationReplyPendingRegionAddresses = new LongArrayList(2, -2);
        private final LongArrayList applicationReplyPendingRegionIds = new LongArrayList(2, -2);
        private final IntArrayList applicationReplyPendingRegionLengths = new IntArrayList(2, -2);

        private ServerHandshake(
            SSLEngine tlsEngine,
            MessageConsumer networkThrottle,
            long networkId,
            String networkReplyName,
            MessageConsumer networkReply,
            long networkReplyId,
            BiConsumer<HandshakeStatus, Consumer<SSLEngineResult>> statusHandler,
            Runnable networkReplyDoneHandler,
            Consumer<Runnable> networkReplyDoneHandlerConsumer,
            LongArrayList networkPendingRegions,
            IntArrayList networkPendingLengths,
            AckedRegionBuilder ackRegionBuilder,
            NetworkReplyMemoryManager networkReplyMemoryManager,
            Consumer<Consumer<SSLEngineResult>> setOnNetworkClosingHandshakeHandler)
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

            this.networkReplyMemoryManager = networkReplyMemoryManager;

            this.networkPendingRegions = networkPendingRegions;
            this.networkPendingLengths = networkPendingLengths;
            this.ackRegionBuilder = ackRegionBuilder;
            this.setOnNetworkClosingHandshakeHandler = setOnNetworkClosingHandshakeHandler;
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
            case TransferFW.TYPE_ID:
                final TransferFW transfer = transferRO.wrap(buffer, index, index + length);
                handleTransfer(transfer);
                break;
            default:
                doAck(networkThrottle, networkId, RST);
                break;
            }
        }

        private void handleTransfer(
            TransferFW transfer)
        {
            transfer.regions().forEach(
            r ->
            {
                int numStored = networkPendingRegions.size();
                if (numStored > 0)
                {
                    int lastIndex = numStored - 1;
                    long lastAddress = networkPendingRegions.get(lastIndex);
                    int lastLength = networkPendingLengths.get(lastIndex);
                    if (lastAddress + lastLength == r.address())
                    {
                        networkPendingLengths.set(lastIndex, lastLength + r.length());
                    }
                    else
                    {
                        networkPendingRegions.add(r.address());
                        networkPendingLengths.add(r.length());
                    }
                }
                else
                {
                    networkPendingRegions.add(r.address());
                    networkPendingLengths.add(r.length());
                }
            });
            processNetwork();

            int flags = transfer.flags();
            if (isReset(flags))
            {
                tlsEngine.closeOutbound();
            }
            else if(isFin(flags))
            {
                doTransfer(networkReply, networkReplyId, transfer.authorization(), RST);
                doAck(networkThrottle, networkId, FIN);
            }
        }

        private void processNetwork()
        {
            if (networkPendingRegions.isEmpty())
            {
                return;
            }

            inNetBuffer.clear();
            outNetByteBuffer.clear();


            final ByteBuffer inNetBuffer = stageInNetBuffer(
                this.networkPendingRegions,
                this.networkPendingLengths);

            try
            {
                loop:
                while (inNetBuffer.hasRemaining() && !tlsEngine.isInboundDone())
                {
                    outNetByteBuffer.rewind();
                    HandshakeStatus handshakeStatus = NOT_HANDSHAKING;
                    SSLEngineResult.Status status = BUFFER_UNDERFLOW;
                    if (tlsEngine.getHandshakeStatus() != NOT_HANDSHAKING && tlsEngine.getHandshakeStatus() != FINISHED)
                    {
                        SSLEngineResult result = tlsEngine.unwrap(inNetBuffer, outNetByteBuffer);
                        status = result.getStatus();
                        handshakeStatus = result.getHandshakeStatus();
                    }

                    switch (status)
                    {
                        case BUFFER_UNDERFLOW:
                            break loop;
                        default:
                            statusHandler.accept(handshakeStatus, this::flushNetworkHandshake);
                            break;
                    }
                }
                int totalBytesConsumed = inNetBuffer.position();
                doAck(networkThrottle, networkId, EMPTY, ackRegionBuilder.ackRegions(totalBytesConsumed));
            }
            catch (Exception e)
            {
                // TODO no testing
                doAck(networkThrottle, networkId, RST);
                doTransfer(networkReply, networkReplyId, 0L, RST);
            }
        }

        private void flushNetworkHandshake(
            SSLEngineResult result)
        {
            final int bytesProduced = result.bytesProduced();
            if (bytesProduced != 0)
            {
                long uAddress = networkReplyMemoryManager.address();
                long rAddress = networkReplyMemoryManager.resolvedAddress();

                outNetByteBuffer.flip();
                directBufferRW.wrap(rAddress, bytesProduced);
                directBufferRW.putBytes(0, outNetByteBuffer, bytesProduced);

                doTransfer(
                    networkReply,
                    networkReplyId,
                    0L,
                    uAddress,
                    bytesProduced);

                directBufferRW.wrap(rAddress + bytesProduced, 100); // TODO magic variable (just needs to be emply list)
                final int metaDataSize = regionsRW.wrap(directBufferRW, 0, 100).build().sizeof(); //append empty list
                networkReplyMemoryManager.consumeBytes(bytesProduced + metaDataSize);
            }
        }

        private void setNetworkThrottle(
            MessageConsumer newNetworkThrottle)
        {
            router.setThrottle(networkReplyName, networkReplyId, newNetworkThrottle);
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
                    ack.regions().forEach(r ->
                    {
                        final long rAddress = memoryManager.resolve(r.address());
                        view.wrap(rAddress + r.length(), 100); // TODO magic number
                        assert r.streamId() == networkReplyId;
                        final ListFW<RegionFW> regions = regionsRO.wrap(view, 0, 100);
                        assert regions.isEmpty();
                        final int ackedBytes = regions.sizeof() + r.length();
                        networkReplyMemoryManager.releaseBytes(ackedBytes);
                    });
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

        private NetworkReplyMemoryManager networkReplyMemoryManager;
        private Consumer<Consumer<SSLEngineResult>> setOnNetworkClosingHandshakeHandler;

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
                doAck(applicationReplyThrottle, applicationReplyId, RST);
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
                default:
                    doAck(applicationReplyThrottle, applicationReplyId, RST);
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
                this.setOnNetworkClosingHandshakeHandler = handshake.setOnNetworkClosingHandshakeHandler;

                this.networkReplyMemoryManager = handshake.networkReplyMemoryManager;
                doAck(applicationReplyThrottle, applicationReplyId, 0);
                handshake.setNetworkThrottle(this::handleThrottle);
                handshake.setNetworkReplyDoneHandler(this::handleNetworkReplyDone);
            }
            else
            {
                doAck(applicationReplyThrottle, applicationReplyId, RST);
            }
        }

        private void handleTransfer(
            TransferFW transfer)
        {
            final ListFW<RegionFW> regions = transfer.regions();
            final long authorization = transfer.authorization();

            if (!regions.isEmpty()) // TODO combine with flags frome down below?
            {
                processApplication(regions, authorization, EMPTY);
            }

            final int flags = transfer.flags();
            if (isFin(flags))
            {
                handleEnd(transfer);
            }
            if (isReset(flags))
            {
                handleAbort();
            }
        }

        private void processApplication(
            final ListFW<RegionFW> regions,
            final long authorization,
            final int flags)
        {
            // stage into buffer
            inAppByteBuffer.clear();

            regions.forEach(r ->
            {
                final long rAddress = memoryManager.resolve(r.address());
                final int length = r.length();
                view.wrap(rAddress, length);
                final int appByteBufferIndex = inAppByteBuffer.position();
                view.getBytes(0, inAppByteBuffer, appByteBufferIndex, length);
                inAppByteBuffer.position(appByteBufferIndex + length);
            });
            inAppByteBuffer.flip();

            try
            {
                outNetByteBuffer.clear();
                final long uAddressMark = networkReplyMemoryManager.address();
                while (inAppByteBuffer.hasRemaining() && !tlsEngine.isOutboundDone())
                {
                    outNetByteBuffer.rewind();
                    SSLEngineResult result = tlsEngine.wrap(inAppByteBuffer, outNetByteBuffer);
                    final int bytesProduced = result.bytesProduced();

                    final long rAddress = networkReplyMemoryManager.resolvedAddress();

                    directBufferRW.wrap(rAddress, bytesProduced);
                    outNetByteBuffer.flip();
                    directBufferRW.putBytes(0, outNetByteBuffer, bytesProduced);

                    networkReplyMemoryManager.consumeBytes(bytesProduced);
                }

                final long uAddressPos = networkReplyMemoryManager.address();
                final int payloadLength = (int) (uAddressPos - uAddressMark);
                networkReplyMemoryManager.markRegions(regions);

                doTransfer(
                        networkReply,
                        networkReplyId,
                        authorization,
                        rb -> rb.item(r -> r
                                .address(uAddressMark)
                                .length(payloadLength)
                                .streamId(networkReplyId)),
                        flags);
            }
            catch (SSLException ex)
            {
                // TODO testing
                doTransfer(networkReply, networkReplyId, authorization, RST);
            }
        }

        private void handleEnd(TransferFW transfer)
        {
            if(!tlsEngine.isOutboundDone())
            {
                try
                {
                    tlsEngine.closeOutbound();
                    inAppByteBuffer.clear();
                    outNetByteBuffer.clear();
                    SSLEngineResult result = tlsEngine.wrap(inAppByteBuffer, outNetByteBuffer);
                    outNetByteBuffer.flip();

                    final long uAddress = networkReplyMemoryManager.address();
                    final long rAddress = networkReplyMemoryManager.resolvedAddress();

                    final int bytesProduced = result.bytesProduced();
                    directBufferRW.wrap(rAddress, bytesProduced);
                    directBufferRW.putBytes(0, outNetByteBuffer, bytesProduced);

                    doTransfer(
                        networkReply,
                        networkReplyId,
                        0L,
                        uAddress,
                        bytesProduced);

                    networkReplyMemoryManager.consumeBytes(bytesProduced);
                    networkReplyMemoryManager.markEmptyRegions();
                }
                catch (SSLException ex)
                {
                    // END is from application reply, so no need to clean that stream
                    doTransfer(networkReply, networkReplyId, transfer.authorization(), FIN);
                }
            }
            doTransfer(networkReply, networkReplyId, transfer.authorization(), FIN);
        }

        private void handleAbort()
        {
            tlsEngine.closeOutbound();

            setOnNetworkClosingHandshakeHandler.accept(HANDSHAKE_NOOP);
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
                    ack.regions().forEach(r ->
                    {
                        assert r.streamId() == networkReplyId;
                        final ListFW<RegionFW> regions = networkReplyMemoryManager.getRegionsAndAckFrom(r.address(), r.length());
                        if (!regions.isEmpty())
                        {
                            // TODO very unlikely we get multiple regions in ack but would
                            // be better to send one ack back
                            ackApplicationReplyRegions(regions);
                        }
                        networkReplyMemoryManager.releaseBytes(r.length());
                    });
                }
                if (isReset(ack.flags()))
                {
                    handleReset();
                }
                if (isFin(ack.flags()))
                {
                    networkReplyMemoryManager.release();
                    doAck(applicationReplyThrottle, applicationReplyId, FIN);
                }
                break;
            default:
                // ignore
                break;
            }
        }

        private void ackApplicationReplyRegions(
            final ListFW<RegionFW> regions)
        {
            doAck(
                applicationReplyThrottle,
                applicationReplyId,
                EMPTY,
                rb ->
                regions.forEach(r -> rb.item(r2 -> r2.address(r.address())
                                                     .length(r.length())
                                                     .streamId(r.streamId()))));
        }

        private void handleReset()
        {
            tlsEngine.closeOutbound();
            setOnNetworkClosingHandshakeHandler.accept(HANDSHAKE_NOOP);
            // RESET is from network reply, so no need to clean that stream
            handleNetworkReplyDone();

        }

        private void handleNetworkReplyDone()
        {
            if (applicationReplyThrottle != null)
            {
                doAck(applicationReplyThrottle, applicationReplyId, RST);
            }
            networkReplyMemoryManager.releaseHard();
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

    private void doTransfer(
        final MessageConsumer target,
        final long targetId,
        final long authorization,
        final Consumer<Builder<RegionFW.Builder, RegionFW>> mutator,
        final int flags)
    {
        final TransferFW transfer = transferRW.wrap(writeBuffer, 0, writeBuffer.capacity())
            .streamId(targetId)
            .authorization(authorization)
            .flags(flags)
            .regions(mutator)
            .build();
        target.accept(transfer.typeId(), transfer.buffer(), transfer.offset(), transfer.sizeof());
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


    private void doAck(
            final MessageConsumer throttle,
            final long throttleId,
            final int flags,
            Consumer<Builder<RegionFW.Builder, RegionFW>> mutator)
    {
        final AckFW ack = ackRW.wrap(writeBuffer, 0, writeBuffer.capacity())
                               .streamId(throttleId)
                               .flags(flags)
                               .regions(mutator)
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


    private void doCloseInbound(
        final SSLEngine tlsEngine) throws SSLException
    {
        tlsEngine.closeInbound();
    }

    private ByteBuffer stageInNetBuffer(
        LongArrayList regionAddresses,
        IntArrayList regionLengths)
    {
        // TODO better loop
        for (int i = 0; i < regionAddresses.size(); i++)
        {
            int position = inNetBuffer.position();
            long addr = regionAddresses.get(i);
            int length = regionLengths.get(i);
            view.wrap(memoryManager.resolve(addr), length);
            view.getBytes(0, inNetBuffer, position, length);
            inNetBuffer.position(position + length);
        }
        inNetBuffer.flip();
        return inNetBuffer;
    }

    class NetworkReplyMemoryManager
    {
        // TODO handle loop around
        private final long memoryAddress;
        private int networkReplyMemoryPosition;
        private int networkReplyNotAckedBytes;

        NetworkReplyMemoryManager()
        {
            this.memoryAddress = memoryManager.acquire(TRANSFER_CAPACITY);
            if (this.memoryAddress == -1)
            {
                throw new IllegalStateException("Unable to allocate memory block: " + TRANSFER_CAPACITY);
            }
            this.networkReplyMemoryPosition = 0;
            this.networkReplyNotAckedBytes = 0;
        }

        public ListFW<RegionFW> getRegionsAndAckFrom(
            long address,
            int length)
        {
            long raddr = memoryManager.resolve(address + length);
            view.wrap(raddr, availableLength());
            ListFW<RegionFW> regions = regionsRO.wrap(view, 0, availableLength());
            releaseBytes(regions.sizeof());
            return regions;
        }

        public long markRegions(ListFW<RegionFW> regions)
        {
            final int sizeOfRegions = regions.sizeof();
            directBufferRW.wrap(resolvedAddress(), sizeOfRegions);
            directBufferRW.putBytes(0, regions.buffer(), regions.offset(), sizeOfRegions);
            consumeBytes(sizeOfRegions);
            return address();
        }

        private int availableLength()
        {
            return TRANSFER_CAPACITY - networkReplyMemoryPosition;
        }

        public long markEmptyRegions()
        {
            directBufferRW.wrap(resolvedAddress(), availableLength());
            regionsRW.wrap(directBufferRW, 0, availableLength());
            ListFW<RegionFW> regions = regionsRW.build();
            consumeBytes(regions.sizeof());
            return address();
        }

        public long address()
        {
            return memoryAddress + networkReplyMemoryPosition;
        }

        public long resolvedAddress()
        {
            return memoryManager.resolve(address());
        }

        public void consumeBytes(int numOfBytes)
        {
            System.out.println("consumed " + numOfBytes);
            assert networkReplyNotAckedBytes < TRANSFER_CAPACITY;
            networkReplyNotAckedBytes += numOfBytes;
            networkReplyMemoryPosition += numOfBytes;
        }

        public void releaseBytes(int numOfBytes)
        {
            System.out.println("released " + numOfBytes);
            networkReplyNotAckedBytes -= numOfBytes;
            if (networkReplyNotAckedBytes == 0)
            {
                networkReplyMemoryPosition = 0;
            }
        }

        public void release()
        {
            assert networkReplyNotAckedBytes == 0 && networkReplyMemoryPosition == 0;
            releaseHard();
        }

        public void releaseHard()
        {
            memoryManager.release(memoryAddress, TRANSFER_CAPACITY);
        }
    }
}
