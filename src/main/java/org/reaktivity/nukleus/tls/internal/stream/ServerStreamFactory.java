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
import org.reaktivity.nukleus.buffer.DirectBufferBuilder;
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
import org.reaktivity.reaktor.internal.buffer.DefaultDirectBufferBuilder;

public final class ServerStreamFactory implements StreamFactory
{
    private static final int APP_TRANSFER_METADATA_SIZE = Short.BYTES;
    private static final int NETWORK_TRANSFER_METADATA_SIZE = Short.BYTES;
    public static final int TLS_MAX_HANDSHAKE_LENGTH = 0x10000;  // TODO extract to configuration
    private static final ByteBuffer EMPTY_BYTE_BUFFER = ByteBuffer.allocate(0);
    private static final int MAXIMUM_PAYLOAD_LENGTH = (1 << Short.SIZE) - 1;
    private static final Runnable NOP = () -> {};

    private final DirectBufferBuilder directBufferBuilder = new DefaultDirectBufferBuilder();
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
//        private MessageConsumer networkReply;
//        private long networkReplyId;

        private MessageConsumer applicationTarget;
        private long applicationId;
        private final long authorization;

        private MessageConsumer streamState;
        private ServerHandshake handshake;

        private long applicationCorrelationId;

        private long networkCorrelationId;

        private Runnable networkReplyDoneHandler = NOP;

        private final IntArrayList regionLengths = new IntArrayList(2, -2);
        private final LongArrayList regionAddresses = new LongArrayList(2, -2);

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

                    final MessageConsumer networkReply = router.supplyTarget(networkReplyName);
                    final long newNetworkReplyId = supplyStreamId.getAsLong();

                    final ServerHandshake newHandshake = new ServerHandshake(
                            tlsEngine,
                            networkThrottle,
                            networkId,
                            networkReplyName,
                            networkReply,
                            newNetworkReplyId,
                            this::handleStatus,
                            this::handleNetworkReplyDone,
                            this::setNetworkReplyDoneHandler,
                            this.regionAddresses,
                            this.regionLengths,
                            this::consumedRegions);

                    doBegin(networkReply, newNetworkReplyId, 0L, 0L, networkCorrelationId);
                    router.setThrottle(networkReplyName, newNetworkReplyId, newHandshake::handleThrottle);

                    this.streamState = newHandshake::afterBegin;
                    this.networkReplyName = networkReplyName;
//                    this.networkReply = networkReply;
//                    this.networkReplyId = newNetworkReplyId;
                    this.handshake = newHandshake;

                    tlsEngine.setHandshakeApplicationProtocolSelector(this::selectApplicationProtocol);

                    tlsEngine.beginHandshake();
//                    doAck(networkThrottle, networkId, FrameFlags.FIN);
                }
                catch (SSLException ex)
                {
                    doAck(networkThrottle, networkId, RST);
//                    doTransfer(networkReply, networkReplyId, 0L, RST);
                }
            }
            else
            {
                doAck(networkThrottle, networkId, RST);
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
            default:
                throw new RuntimeException("Not implemented yet"); // DPW
//                doReset(networkThrottle, networkId);
//                break;
            }
        }

        private void handleTransfer(
            TransferFW transfer)
        {
            transfer.regions().forEach(
            r ->
            {
                regionAddresses.add(r.address());
                regionLengths.add(r.length());
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
            if (regionAddresses.isEmpty())
            {
                return;
            }

            inNetBuffer.clear();
            outAppByteBuffer.clear();

            final ByteBuffer inNetBuffer = stageInNetBuffer(
                this.regionAddresses,
                this.regionLengths);
                try
                {
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
                            handleStatus(result.getHandshakeStatus(), r -> {});
                            break;
                        }

                        int totalBytesConsumed = inNetBuffer.position();
                        final int flags = tlsEngine.isInboundDone()? FIN : EMPTY;
                        handleFlushAppData(bytesProduced, totalBytesConsumed - bytesConsumerIter, flags);
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
                    int nextLength = regionLengths.get(0);
                    if (nextLength <= toAck)
                    {
                        b.item(r ->
                            r.address(regionAddresses.remove(0))
                             .length(regionLengths.remove(0))
                             .streamId(networkId));
                    }
                    else
                    {
                        nextLength -= toAck;
                        int length = regionLengths.get(0);
                        b.item(r -> r.address(regionAddresses.get(0))
                                     .length(length)
                                     .streamId(networkId));
                    }
                    toAck -= nextLength;
                }
            };
        }

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

        // rewrites in place
        // [encrpyted                              ]
        // [emply-data-length][encrpyted][empty-data]
        // TODO turn into region builder
        private void handleFlushAppData(
            final int bytesProduced,
            final int bytesConsumed,
            int flags)
        {
            if (bytesConsumed <= 0)
            {
                assert bytesProduced == 0;
                return;
            }

            final long unresolvedRegionAddr = regionAddresses.remove(0);
            int availableLength = regionLengths.remove(0);

            if (bytesConsumed < availableLength)
            {
                regionAddresses.add(0, unresolvedRegionAddr + bytesConsumed);
                regionLengths.add(0, availableLength - bytesConsumed);
                availableLength -= bytesConsumed;
            }

            final int remainingBytesConsumed = bytesConsumed - availableLength;

            // DPW TODO write out of order, needs fixing
            final long resolvedAddr = memoryManager.resolve(unresolvedRegionAddr);
            final int toWriteTotal = Math.min(availableLength, bytesProduced + APP_TRANSFER_METADATA_SIZE);
            final int bytesToWrite = toWriteTotal - APP_TRANSFER_METADATA_SIZE;
            final short padding = (short) (availableLength - toWriteTotal);

            outAppByteBuffer.flip();
            directBufferRW.wrap(resolvedAddr, availableLength);
            directBufferRW.putShort(0, padding);
            directBufferRW.putBytes(APP_TRANSFER_METADATA_SIZE, outAppByteBuffer, bytesToWrite);

            if (remainingBytesConsumed > 0 && bytesToWrite < bytesProduced) // wrap over
            {
                throw new RuntimeException("Not implemented");
//                    handleFlushAppData(bytesProduced - bytesToWrite, remainingBytesConsumed);
            }
            else if(remainingBytesConsumed > 0) // wrap over but only empty-data, so send as empty region
            {
                final long wrapAroundAddr = regionAddresses.remove(0);
                int wrapAroundLength = regionLengths.remove(0);

                if (remainingBytesConsumed < wrapAroundLength)
                {
                    regionAddresses.add(0, wrapAroundAddr + remainingBytesConsumed);
                    regionLengths.add(0, wrapAroundLength - remainingBytesConsumed);
                    wrapAroundLength -= remainingBytesConsumed;
                }

                directBufferRW.wrap(memoryManager.resolve(wrapAroundAddr), wrapAroundLength);
                directBufferRW.putShort(0, (short) (wrapAroundLength - APP_TRANSFER_METADATA_SIZE));

                doTransfer(
                    applicationTarget,
                    applicationId,
                    0L,
                    b -> b.item(b2 -> b2.address(unresolvedRegionAddr + APP_TRANSFER_METADATA_SIZE)
                                        .length(bytesToWrite)
                                        .streamId(networkId))
                          .item(b2 -> b2.address(unresolvedRegionAddr + APP_TRANSFER_METADATA_SIZE)
                                        .length(bytesToWrite)
                                        .streamId(networkId)),
                  flags);
            }
            else
            {
                doTransfer(
                    applicationTarget,
                    applicationId,
                    0L,
                    b -> b.item(b2 -> b2.address(unresolvedRegionAddr + APP_TRANSFER_METADATA_SIZE)
                            .length(bytesToWrite)
                            .streamId(networkId)),
                    flags);
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
                    }
                    else if (isFin(flags))
                    {
                        // TODO ?
                    }

                    if (!(regions.isEmpty() && FrameFlags.isEmpty(flags)))
                    {
                        doAck(
                            networkThrottle,
                            networkId,
                            flags,
                            rb ->
                            {
                                regions.forEach(r ->
                                {
                                    final long uAddress = r.address() - APP_TRANSFER_METADATA_SIZE;
                                    final long rAddress = memoryManager.resolve(uAddress);
                                    view.wrap(rAddress, APP_TRANSFER_METADATA_SIZE);
                                    final int regionLength = view.getShort(0) + r.length();
                                    rb.item(r2 -> r2.address(uAddress)
                                            .length(regionLength)
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
        private final long outNetworkMemorySlotAddress;
        private int outNetworkMemorySlotUsedOffset;

        private final LongArrayList regionAddresses;
        private final IntArrayList regionLengths;
        private final AckedRegionBuilder ackRegionBuilder;

        private int outstandingNetworkBytes = 0;

        private Consumer<AckFW> resetHandler;
        private Consumer<RegionFW> ackRegionHandler;

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
            LongArrayList regionAddresses,
            IntArrayList regionLengths,
            AckedRegionBuilder ackRegionBuilder)
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

            this.outNetworkMemorySlotAddress = memoryManager.acquire(TLS_MAX_HANDSHAKE_LENGTH);
            this.outNetworkMemorySlotUsedOffset = 0;

            this.regionAddresses = regionAddresses;
            this.regionLengths = regionLengths;
            this.ackRegionBuilder = ackRegionBuilder;
            this.ackRegionHandler = r ->
            {
                if (r.streamId() == networkId)
                {
                    outstandingNetworkBytes -= r.length();
                }
            };
        }

        private void onFinished()
        {
            if (outstandingNetworkBytes != 0)
            {
                this.ackRegionHandler = r ->
                {
                    outstandingNetworkBytes -= r.length();
                    if (outstandingNetworkBytes == 0)
                    {
                        memoryManager.release(outNetworkMemorySlotAddress, TLS_MAX_HANDSHAKE_LENGTH);
                        this.ackRegionHandler = i ->
                        {
                            /*NOOP*/
                        };
                    }
                };
            }
            else
            {
                memoryManager.release(outNetworkMemorySlotAddress, TLS_MAX_HANDSHAKE_LENGTH);
                this.ackRegionHandler = i ->
                {
                    /*NOOP*/
                };
            }
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
                int numStored = regionAddresses.size();
                if (numStored > 0)
                {
                    int lastIndex = numStored - 1;
                    long lastAddress = regionAddresses.get(lastIndex);
                    int lastLength = regionLengths.get(lastIndex);
                    if (lastAddress + lastLength == r.address())
                    {
                        regionLengths.set(lastIndex, lastLength + r.length());
                    }
                    else
                    {
                        regionAddresses.add(r.address());
                        regionLengths.add(r.length());
                    }
                }
                else
                {
                    regionAddresses.add(r.address());
                    regionLengths.add(r.length());
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
                handleEnd();
            }
        }

        private void processNetwork()
        {
            if (regionAddresses.isEmpty())
            {
                return;
            }

            inNetBuffer.clear();
            outAppByteBuffer.clear();


            final ByteBuffer inNetBuffer = stageInNetBuffer(
                this.regionAddresses,
                this.regionLengths);

            try
            {
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
                        doAck(networkThrottle, networkId, RST);
                        doTransfer(networkReply, networkReplyId, 0L, RST); // TODO authorization
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
                int totalBytesConsumed = inNetBuffer.position();
                doAck(networkThrottle, networkId, EMPTY, ackRegionBuilder.ackRegions(totalBytesConsumed));
            }
            catch (Exception e)
            {
                throw new RuntimeException("Not Implemented: " + e);
//                doAck(networkThrottle, networkId, RST, null); //DPW TODO
//                doAbort(target, targetId, authorization); TODO?
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

                outNetByteBuffer.flip();
                directBufferRW.wrap(memoryAddress, bytesProduced);
                directBufferRW.putBytes(0, outNetByteBuffer, bytesProduced);

                doTransfer(
                    networkReply,
                    networkReplyId,
                    0L,
                    unresolvedAddr,
                    bytesProduced);
                outstandingNetworkBytes += bytesProduced;
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
                    ackRegions(ack);
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

        private void ackRegions(AckFW ack)
        {
            ack.regions().forEach(r -> ackRegionHandler.accept(r));
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

        private Consumer<RegionFW> handshakeThrottle;

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
                this.statusHandler = handshake.statusHandler;
                this.handshakeThrottle = handshake.ackRegionHandler;

//                this.outNetworkMemorySlotAddress = memoryManager; TODO
                this.outNetworkMemorySlotUsedOffset = handshake.outNetworkMemorySlotUsedOffset;

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

            if (!regions.isEmpty()) // TODO combine flags frome down below?
            {
                processApplication(regions, authorization);
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
            ListFW<RegionFW> regions,
            long authorization)
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

            try
            {
                outNetByteBuffer.clear();
                final long uAddressMark = outNetworkMemorySlotAddress + outNetworkMemorySlotUsedOffset;
                while (inAppByteBuffer.hasRemaining() && !tlsEngine.isOutboundDone())
                {
                    outNetByteBuffer.rewind();
                    SSLEngineResult result = tlsEngine.wrap(inAppByteBuffer, outNetByteBuffer);
                    final int bytesProduced = result.bytesProduced();

                    final long uAddress = outNetworkMemorySlotAddress + outNetworkMemorySlotUsedOffset;
                    final long rAddress = memoryManager.resolve(uAddress);

                    directBufferRW.wrap(rAddress, bytesProduced);
                    outNetByteBuffer.flip();
                    directBufferRW.putBytes(0, outNetByteBuffer, bytesProduced);

                    this.outNetworkMemorySlotUsedOffset += bytesProduced;
                }

                final long uAddressPos = outNetworkMemorySlotAddress + outNetworkMemorySlotUsedOffset;
                final int sizeOfRegion = (int) (uAddressMark - uAddressPos);
                final long rAddress = memoryManager.resolve(uAddressPos);
                final int sizeOfRegions = regions.sizeof();
                directBufferRW.wrap(rAddress, sizeOfRegions);
                directBufferRW.putBytes(0, regions.buffer(), regions.offset(), sizeOfRegions);
                this.outNetworkMemorySlotUsedOffset += sizeOfRegions;

                doTransfer(
                        networkReply,
                        networkReplyId,
                        authorization,
                        rb -> rb.item(r -> r.address(uAddressMark).length(sizeOfRegion).streamId(networkReplyId)),
                        EMPTY);
            }
            catch (SSLException ex)
            {
                // DPW TODO
//                    doReset(applicationReplyThrottle, applicationReplyId);
//                    doAbort(networkReply, networkReplyId, 0L);
            }
        }

        private void handleEnd(TransferFW transfer)
        {
            if (tlsEngine.isOutboundDone())
            {
                doCloseOutbound(tlsEngine, networkReply, networkReplyId,
                        transfer.authorization(), this::handleNetworkReplyDone);
            }

            try
            {
//                doAck(applicationReplyThrottle, applicationReplyId, FrameFlags.FIN);
                applicationReplyThrottle = null;
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
                    processAckedRegions(ack.regions(), ack.flags());
                }
                if (isReset(ack.flags()))
                {
                    handleReset();
                }
                break;
            default:
                // ignore
                break;
            }
        }

        private void processAckedRegions(
            ListFW<RegionFW> regions,
            int flags)
        {
            regions.forEach(r -> handshakeThrottle.accept(r));

            if (regions.anyMatch(r -> r.streamId() != this.networkReplyId))
            {
                doAck(
                    applicationReplyThrottle,
                    applicationReplyId,
                    flags,
                    b -> regions.forEach(r -> b.item(rb -> rb.address(r.address())
                                               .length(r.length())
                                               .streamId(r.streamId()))));
            }
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
                doAck(applicationReplyThrottle, applicationReplyId, RST);
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

        // TODO combine with above
        if (tlsEngine.isOutboundDone())
        {
            doTransfer(networkReply, networkReplyId, authorization, FIN);
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
        outNetByteBuffer.rewind(); // DPW TODO
        SSLEngineResult result = tlsEngine.wrap(inAppByteBuffer, outNetByteBuffer);
        flushNetwork(tlsEngine, result.bytesProduced(), networkReply, networkReplyId,
                authorization, networkReplyDoneHandler, outNetworkMemorySlotAddress, outNetworkMemorySlotUsedOffset);
    }

    private ByteBuffer stageInNetBuffer(
        LongArrayList regionAddresses,
        IntArrayList regionLengths)
    {
        int position = 0;
        // TODO better loop
        for (int i = 0; i < regionAddresses.size(); i++)
        {
            long addr = regionAddresses.get(i);
            int length = regionLengths.get(i);
            view.wrap(memoryManager.resolve(addr), length);
            view.getBytes(0, inNetBuffer, position, length);
            inNetBuffer.position(position + length);
        }
        inNetBuffer.flip();
        return inNetBuffer;
    }

}
