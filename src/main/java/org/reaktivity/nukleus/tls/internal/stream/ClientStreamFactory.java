/**
 * Copyright 2016-2019 The Reaktivity Project
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

import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import javax.net.ssl.SSLEngineResult.Status;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;

import org.agrona.DirectBuffer;
import org.agrona.MutableDirectBuffer;
import org.agrona.collections.Long2ObjectHashMap;
import org.agrona.concurrent.UnsafeBuffer;
import org.reaktivity.nukleus.buffer.BufferPool;
import org.reaktivity.nukleus.buffer.CountingBufferPool;
import org.reaktivity.nukleus.concurrent.SignalingExecutor;
import org.reaktivity.nukleus.function.MessageConsumer;
import org.reaktivity.nukleus.function.MessagePredicate;
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
import org.reaktivity.nukleus.tls.internal.util.function.ObjectLongBiFunction;

public final class ClientStreamFactory implements StreamFactory
{
    private static final ByteBuffer EMPTY_BYTE_BUFFER = ByteBuffer.allocate(0);
    private static final int MAXIMUM_HEADER_SIZE = 5 + 20 + 256;    // TODO version + MAC + padding
    private static final DirectBuffer NO_EXTENSION = new UnsafeBuffer(new byte[] {(byte)0xff, (byte)0xff});
    private static final long FLUSH_HANDSHAKE_SIGNAL = 1L;
    private static final Runnable NOP = () -> {};

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

    private final TlsBeginExFW tlsBeginExRO = new TlsBeginExFW();
    private final TlsBeginExFW.Builder tlsBeginExRW = new TlsBeginExFW.Builder();

    private final OctetsFW outNetOctetsRO = new OctetsFW();
    private final OctetsFW outAppOctetsRO = new OctetsFW();

    private final WindowFW.Builder windowRW = new WindowFW.Builder();
    private final ResetFW.Builder resetRW = new ResetFW.Builder();

    private final Function<String, SSLContext> lookupContext;
    private final SignalingExecutor executor;
    private final RouteManager router;
    private final MutableDirectBuffer writeBuffer;
    private final BufferPool networkPool;
    private final BufferPool applicationPool;
    private final LongUnaryOperator supplyInitialId;
    private final LongUnaryOperator supplyReplyId;
    private final LongSupplier supplyTrace;
    private final int handshakeWindowBytes;
    private final int networkPaddingAdjust;

    private final Long2ObjectHashMap<ClientHandshake> correlations;
    private final ByteBuffer inAppByteBuffer;
    private final ByteBuffer outAppByteBuffer;
    private final ByteBuffer outNetByteBuffer;
    private final DirectBuffer outNetBuffer;

    public ClientStreamFactory(
        TlsConfiguration config,
        SignalingExecutor executor,
        RouteManager router,
        MutableDirectBuffer writeBuffer,
        BufferPool bufferPool,
        LongUnaryOperator supplyInitialId,
        LongUnaryOperator supplyReplyId,
        Long2ObjectHashMap<ClientHandshake> correlations,
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
                bufferPool, counters.clientNetworkAcquires, counters.clientNetworkReleases);
        this.applicationPool = new CountingBufferPool(
                bufferPool.duplicate(), counters.clientApplicationAcquires, counters.clientApplicationReleases);
        this.supplyInitialId = requireNonNull(supplyInitialId);
        this.supplyReplyId = requireNonNull(supplyReplyId);
        this.correlations = requireNonNull(correlations);
        this.handshakeWindowBytes = Math.min(config.handshakeWindowBytes(), networkPool.slotCapacity());
        this.networkPaddingAdjust = Math.min(networkPool.slotCapacity() >> 14, 1) * MAXIMUM_HEADER_SIZE;

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
        MessageConsumer sender)
    {
        final BeginFW begin = beginRO.wrap(buffer, index, index + length);
        final long streamId = begin.streamId();

        MessageConsumer newStream = null;

        if ((streamId & 0x0000_0000_0000_0001L) != 0L)
        {
            newStream = newAcceptStream(begin, sender);
        }
        else
        {
            newStream = newConnectReplyStream(begin, sender);
        }

        return newStream;
    }

    private MessageConsumer newAcceptStream(
        final BeginFW begin,
        final MessageConsumer applicationReply)
    {
        final long routeId = begin.routeId();
        final long authorization = begin.authorization();
        // Ignoring extension data, see reaktivity/nukleus-tls.java#47
        final TlsBeginExFW tlsBeginEx = tlsBeginExRO.wrap(NO_EXTENSION, 0, NO_EXTENSION.capacity());

        final boolean defaultRoute;

        final MessagePredicate defaultRouteFilter = (t, b, o, l) ->
        {
            final RouteFW route = routeRO.get().wrap(b, o, o + l);
            final TlsRouteExFW tlsRouteExRO = ClientStreamFactory.this.tlsRouteExRO.get();
            final TlsRouteExFW routeEx = route.extension().get(tlsRouteExRO::wrap);
            final String hostname = routeEx.hostname().asString();
            final String applicationProtocol = routeEx.applicationProtocol().asString();
            final String tlsHostname = tlsBeginEx.hostname().asString();

            return (tlsHostname == null || Objects.equals(tlsHostname, hostname)) &&
                    applicationProtocol == null;
        };

        final MessagePredicate filter = (t, b, o, l) ->
        {
            final RouteFW route = routeRO.get().wrap(b, o, o + l);
            final TlsRouteExFW tlsRouteExRO = ClientStreamFactory.this.tlsRouteExRO.get();
            final TlsRouteExFW routeEx = route.extension().get(tlsRouteExRO::wrap);
            final String hostname = routeEx.hostname().asString();
            final String applicationProtocol = routeEx.applicationProtocol().asString();
            final String tlsHostname = tlsBeginEx.hostname().asString();
            final String tlsApplicationProtocol = tlsBeginEx.applicationProtocol().asString();

            return (tlsHostname == null || Objects.equals(tlsHostname, hostname)) &&
                    (applicationProtocol == null || Objects.equals(tlsApplicationProtocol, applicationProtocol));
        };

        defaultRoute = router.resolve(routeId, authorization, defaultRouteFilter, this::wrapRoute) != null;
        final RouteFW route = router.resolve(routeId, authorization, filter, this::wrapRoute);

        MessageConsumer newStream = null;

        if (route != null)
        {
            final TlsRouteExFW tlsRouteExRO = ClientStreamFactory.this.tlsRouteExRO.get();
            final TlsRouteExFW routeEx = route.extension().get(tlsRouteExRO::wrap);
            String store = routeEx.store().asString();

            String tlsHostname = tlsBeginEx.hostname().asString();
            if (tlsHostname == null)
            {
                tlsHostname = routeEx.hostname().asString();
            }

            String tlsApplicationProtocol = tlsBeginEx.applicationProtocol().asString();
            if (tlsApplicationProtocol == null)
            {
                tlsApplicationProtocol = routeEx.applicationProtocol().asString();
            }

            final long networkRouteId = route.correlationId();

            final long applicationInitialId = begin.streamId();
            final long applicationRouteId = begin.routeId();

            final SSLContext context = lookupContext.apply(store);
            if (context != null)
            {
                final SSLEngine tlsEngine = context.createSSLEngine(tlsHostname, -1);

                newStream = new ClientAcceptStream(
                    tlsEngine,
                    tlsHostname,
                    tlsApplicationProtocol,
                    defaultRoute,
                    applicationRouteId,
                    applicationReply,
                    applicationInitialId,
                    authorization,
                    networkRouteId)::handleStream;
            }
        }

        return newStream;
    }

    private MessageConsumer newConnectReplyStream(
        final BeginFW begin,
        final MessageConsumer networkReplyThrottle)
    {
        final long networkRouteId = begin.routeId();
        final long networkReplyId = begin.streamId();
        final long authorization = begin.authorization();

        return new ClientConnectReplyStream(networkReplyThrottle, networkRouteId, networkReplyId, authorization)::handleStream;
    }

    private RouteFW wrapRoute(
        int msgTypeId,
        DirectBuffer buffer,
        int index,
        int length)
    {
        return routeRO.get().wrap(buffer, index, index + length);
    }

    private final class ClientAcceptStream
    {
        private final String tlsHostname;
        private final String tlsApplicationProtocol;
        private final boolean defaultRoute;

        private final long applicationRouteId;

        private final MessageConsumer applicationReply;
        private final long applicationInitialId;
        private final long authorization;

        private final long networkRouteId;
        private final long networkInitialId;
        private final MessageConsumer networkInitial;

        private final SSLEngine tlsEngine;
        private MessageConsumer streamState;

        private int applicationBudget;
        private int networkBudget;
        private int networkPadding;

        private long applicationTraceId;

        private ClientAcceptStream(
            SSLEngine tlsEngine,
            String tlsHostname,
            String tlsApplicationProtocol,
            boolean defaultRoute,
            long applicationRouteId,
            MessageConsumer applicationReply,
            long applicationInitialId,
            long authorization,
            long networkRouteId)
        {
            this.tlsEngine = tlsEngine;
            this.tlsHostname = tlsHostname;
            this.tlsApplicationProtocol = tlsApplicationProtocol;
            this.defaultRoute = defaultRoute;
            this.applicationRouteId = applicationRouteId;
            this.applicationReply = applicationReply;
            this.applicationInitialId = applicationInitialId;
            this.authorization = authorization;
            this.networkRouteId = networkRouteId;
            this.networkInitialId = supplyInitialId.applyAsLong(networkRouteId);
            this.networkInitial = router.supplyReceiver(networkInitialId);
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
                doReset(applicationReply, applicationRouteId, applicationInitialId);
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
                doReset(applicationReply, applicationRouteId, applicationInitialId);
                break;
            }
        }

        private void handleBegin(
            BeginFW begin)
        {
            try
            {
                final long authorization = begin.authorization();

                final long networkReplyId = supplyReplyId.applyAsLong(networkInitialId);

                tlsEngine.setUseClientMode(true);

                final SSLParameters tlsParameters = tlsEngine.getSSLParameters();
                tlsParameters.setEndpointIdentificationAlgorithm("HTTPS");
                if (tlsHostname != null)
                {
                    tlsParameters.setServerNames(asList(new SNIHostName(tlsHostname)));
                }

                if (tlsApplicationProtocol != null && !tlsApplicationProtocol.isEmpty())
                {
                    String[] applicationProtocols = new String[] { tlsApplicationProtocol };
                    tlsParameters.setApplicationProtocols(applicationProtocols);
                }

                tlsEngine.setSSLParameters(tlsParameters);

                final ClientHandshake newHandshake = new ClientHandshake(tlsEngine, tlsApplicationProtocol, defaultRoute,
                        networkRouteId, networkInitialId,
                        authorization, applicationRouteId,
                        networkReplyId, this::handleThrottle,
                        applicationReply, applicationInitialId, this::handleNetworkReplyDone,
                        this::getNetworkBudget, this::getNetworkPadding,
                        this::setNetworkBudget, this::setNetworkPadding,
                        this::sendApplicationWindow);

                correlations.put(networkReplyId, newHandshake);

                doBegin(networkInitial, networkRouteId, networkInitialId, begin.trace(), authorization, begin.extension());
                router.setThrottle(networkInitialId, newHandshake::handleThrottle);

                this.streamState = this::afterBegin;

                tlsEngine.beginHandshake();
            }
            catch (SSLException ex)
            {
                doReset(applicationReply, applicationRouteId, applicationInitialId);
                doAbort(networkInitial, networkRouteId, networkInitialId, authorization);
            }
        }

        private void handleData(
            DataFW data)
        {
            applicationTraceId = data.trace();
            applicationBudget -= data.length() + data.padding();

            try
            {
                if (applicationBudget < 0)
                {
                    doReset(applicationReply, applicationRouteId, applicationInitialId);
                    doCloseOutbound(tlsEngine, networkInitial, networkRouteId, networkInitialId, applicationTraceId,
                            networkPadding, authorization, this::handleNetworkReplyDone);
                }
                else
                {
                    final OctetsFW payload = data.payload();

                    // Note: inAppBuffer is emptied by SslEngine.wrap(...)
                    //       so should be able to eliminate allocation+copy (stateless)
                    inAppByteBuffer.clear();
                    payload.buffer().getBytes(payload.offset(), inAppByteBuffer, payload.sizeof());
                    inAppByteBuffer.flip();

                    int networkBytesProduced = 0;
                    int networkPaddingProduced = 0;

                    outNetByteBuffer.rewind();

                    while (inAppByteBuffer.hasRemaining() && !tlsEngine.isOutboundDone())
                    {
                        final SSLEngineResult result = tlsEngine.wrap(inAppByteBuffer, outNetByteBuffer);
                        final int bytesProduced = result.bytesProduced();

                        networkBudget -= bytesProduced + networkPadding;
                        networkBytesProduced += bytesProduced;
                        networkPaddingProduced += networkPadding;
                    }

                    flushNetwork(tlsEngine, networkBytesProduced, networkInitial, networkRouteId, networkInitialId,
                            applicationTraceId, networkPaddingProduced, authorization, this::handleNetworkReplyDone);
                }
            }
            catch (SSLException ex)
            {
                doReset(applicationReply, applicationRouteId, applicationInitialId);
                doAbort(networkInitial, networkRouteId, networkInitialId, applicationTraceId, authorization);
            }
        }

        private void handleEnd(
            EndFW end)
        {
            applicationBudget = -1;

            try
            {
                if (!tlsEngine.isOutboundDone())
                {
                    doCloseOutbound(tlsEngine, networkInitial, networkRouteId, networkInitialId, end.trace(), networkPadding,
                            authorization, this::handleNetworkReplyDone);
                }
            }
            catch (SSLException ex)
            {
                doAbort(networkInitial, networkRouteId, networkInitialId, end.trace(), authorization);
            }
        }

        private void handleAbort(
            AbortFW abort)
        {
            tlsEngine.closeOutbound();
            doAbort(networkInitial, networkRouteId, networkInitialId, abort.trace(), authorization);
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

        private void sendApplicationWindow(
            long traceId)
        {
            final int applicationCredit = networkBudget - applicationBudget;

            if (applicationCredit > 0)
            {
                applicationBudget += applicationCredit;
                final int applicationPadding = networkPadding + networkPaddingAdjust;
                doWindow(applicationReply, applicationRouteId, applicationInitialId,
                        traceId, applicationCredit, applicationPadding);
            }
        }

        private void handleWindow(
            final WindowFW window)
        {
            networkBudget += window.credit();
            networkPadding = window.padding();
            sendApplicationWindow(window.trace());
        }

        private void handleReset(
            ResetFW reset)
        {
            doReset(applicationReply, applicationRouteId, applicationInitialId, reset.trace());
            tlsEngine.closeOutbound();
        }

        private void handleNetworkReplyDone()
        {
            if (applicationBudget == -1)
            {
                doReset(applicationReply, applicationRouteId, applicationInitialId);
            }
        }

        int getNetworkBudget()
        {
            return networkBudget;
        }

        int getNetworkPadding()
        {
            return networkPadding;
        }

        void setNetworkBudget(int networkBudget)
        {
            this.networkBudget = networkBudget;
        }

        void setNetworkPadding(int networkPadding)
        {
            this.networkPadding = networkPadding;
        }
    }

    public final class ClientHandshake
    {
        private final SSLEngine tlsEngine;
        private final String applicationProtocol;
        private final boolean defaultRoute;

        private final MessageConsumer networkInitial;
        private final long networkRouteId;
        private final long networkInitialId;
        private final long networkAuthorization;
        private final MessageConsumer networkReply;

        private final MessageConsumer applicationReply;
        private final long applicationInitialId;

        private final long applicationRouteId;
        private final long networkReplyId;

        private final Runnable networkReplyDoneHandler;
        private final List<Future<?>> pendingFutures;

        private int networkReplySlot = NO_SLOT;
        private int networkReplySlotOffset;

        private Consumer<WindowFW> windowHandler;
        private BiConsumer<HandshakeStatus, Consumer<SSLEngineResult>> statusHandler;
        private int pendingTasks;

        IntSupplier networkReplyBudgetSupplier;
        IntSupplier networkReplyPaddingSupplier;
        IntConsumer networkReplyBudgetConsumer;

        IntSupplier networkBudgetSupplier;
        IntSupplier networkPaddingSupplier;
        IntConsumer networkBudgetConsumer;
        IntConsumer networkPaddingConsumer;
        LongConsumer sendApplicationWindow;
        long networkReplyTraceId;

        private ClientHandshake(
            SSLEngine tlsEngine,
            String applicationProtocol,
            boolean defaultRoute,
            long networkRouteId,
            long networkInitialId,
            long authorization,
            long applicationRouteId,
            long networkReplyId,
            MessageConsumer networkThrottle,
            MessageConsumer applicationReply,
            long applicationInitialId,
            Runnable networkReplyDoneHandler,
            IntSupplier networkBudgetSupplier,
            IntSupplier networkPaddingSupplier,
            IntConsumer networkBudgetConsumer,
            IntConsumer networkPaddingConsumer,
            LongConsumer sendApplicationWindow)
        {
            this.tlsEngine = tlsEngine;
            this.applicationProtocol = applicationProtocol;
            this.defaultRoute = defaultRoute;
            this.networkInitial = router.supplyReceiver(networkInitialId);
            this.networkRouteId = networkRouteId;
            this.networkInitialId = networkInitialId;
            this.networkAuthorization = authorization;
            this.applicationRouteId = applicationRouteId;
            this.networkReplyId = networkReplyId;
            this.networkReply = networkThrottle;
            this.windowHandler = this::beforeNetworkReply;
            this.applicationReply = applicationReply;
            this.applicationInitialId = applicationInitialId;
            this.networkReplyDoneHandler = networkReplyDoneHandler;
            this.networkBudgetSupplier = networkBudgetSupplier;
            this.networkPaddingSupplier = networkPaddingSupplier;
            this.networkBudgetConsumer = networkBudgetConsumer;
            this.networkPaddingConsumer = networkPaddingConsumer;
            this.sendApplicationWindow = sendApplicationWindow;
            this.pendingFutures = new ArrayList<>(3);
        }

        @Override
        public String toString()
        {
            return String.format("%s [tlsEngine=%s]", getClass().getSimpleName(), tlsEngine);
        }

        private void onNetworkReply(
            BiConsumer<HandshakeStatus, Consumer<SSLEngineResult>> statusHandler,
            IntSupplier networkReplyBudgetSupplier,
            IntSupplier networkReplyPaddingSupplier,
            IntConsumer networkReplyBudgetConsumer)
        {
            this.statusHandler = statusHandler;
            this.windowHandler = this::afterNetworkReply;
            this.networkReplyBudgetSupplier = networkReplyBudgetSupplier;
            this.networkReplyPaddingSupplier = networkReplyPaddingSupplier;
            this.networkReplyBudgetConsumer = networkReplyBudgetConsumer;

            statusHandler.accept(tlsEngine.getHandshakeStatus(), this::updateNetworkWindow);
        }

        private MessageConsumer doBeginApplicationReply(
            MessageConsumer applicationThrottle,
            long applicationReplyId)
        {
            final String tlsPeerHost = tlsEngine.getPeerHost();

            String tlsApplicationProtocol0 = tlsEngine.getApplicationProtocol();
            if (tlsApplicationProtocol0 != null && tlsApplicationProtocol0.isEmpty())
            {
                tlsApplicationProtocol0 = null;
            }
            final String tlsApplicationProtocol = tlsApplicationProtocol0;

            doTlsBegin(applicationReply, applicationRouteId, applicationReplyId, tlsPeerHost,
                    tlsApplicationProtocol);
            router.setThrottle(applicationReplyId, applicationThrottle);

            router.setThrottle(networkInitialId, networkReply);

            sendApplicationWindow.accept(0);

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
            networkBudgetConsumer.accept(networkBudgetSupplier.getAsInt()+window.credit());
            networkPaddingConsumer.accept(window.padding());
        }

        private void afterNetworkReply(
            WindowFW window)
        {
            networkBudgetConsumer.accept(networkBudgetSupplier.getAsInt()+window.credit());
            networkPaddingConsumer.accept(window.padding());

            // tlsEngine.getHandshakeStatus() will block if delegated task is executing
            if (pendingTasks == 0)
            {
                statusHandler.accept(tlsEngine.getHandshakeStatus(), this::updateNetworkWindow);
            }
        }

        private void handleReset(
            ResetFW reset)
        {
            release();
            try
            {
                correlations.remove(networkReplyId);
                doReset(applicationReply, applicationRouteId, applicationInitialId, reset.trace());
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
            case SignalFW.TYPE_ID:
                final SignalFW signal = signalRO.wrap(buffer, index, index + length);
                handleSignal(signal);
                break;
            default:
                doNetworkReplyReset(supplyTrace.getAsLong());
                break;
            }
        }

        private void handleData(
            DataFW data)
        {
            int dataLength = data.length();
            networkReplyTraceId = data.trace();

            networkReplyBudgetConsumer.accept(
                    networkReplyBudgetSupplier.getAsInt() - dataLength - data.padding());

            if (networkReplySlot == NO_SLOT)
            {
                networkReplySlot = networkPool.acquire(networkReplyId);
            }

            try
            {
                if (networkReplySlot == NO_SLOT || networkReplyBudgetSupplier.getAsInt() < 0)
                {
                    doNetworkReplyReset(supplyTrace.getAsLong());
                    doCloseOutbound(tlsEngine, networkInitial, networkRouteId, networkInitialId, networkReplyTraceId,
                            networkPaddingSupplier.getAsInt(), networkAuthorization, networkReplyDoneHandler);
                    doReset(applicationReply, applicationRouteId, applicationInitialId);
                    networkReplySlotOffset = 0;
                }
                else
                {
                    final OctetsFW payload = data.payload();
                    final int payloadSize = payload.sizeof();

                    final MutableDirectBuffer inNetBuffer = networkPool.buffer(networkReplySlot);
                    inNetBuffer.putBytes(networkReplySlotOffset, payload.buffer(), payload.offset(), payloadSize);
                    final ByteBuffer inNetByteBuffer = networkPool.byteBuffer(networkReplySlot);
                    inNetByteBuffer.limit(inNetByteBuffer.position() + networkReplySlotOffset + payloadSize);

                    processNetwork(inNetBuffer, inNetByteBuffer);

                    int networkReplyBudgetCredit = dataLength + networkReplyPaddingSupplier.getAsInt();
                    networkReplyBudgetConsumer.accept(
                            networkReplyBudgetSupplier.getAsInt() + networkReplyBudgetCredit);
                    doWindow(networkInitial, networkRouteId, networkReplyId, networkReplyBudgetCredit,
                            networkReplyPaddingSupplier.getAsInt());
                }
            }
            catch (SSLException ex)
            {
                networkReplySlotOffset = 0;
                doReset(applicationReply, applicationRouteId, applicationInitialId);
                doAbort(networkInitial, networkRouteId, networkInitialId, networkAuthorization);
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
            pendingFutures.forEach(f -> f.cancel(true));
            correlations.remove(networkReplyId);
            tlsEngine.closeOutbound();
            doAbort(networkInitial, networkRouteId, networkInitialId, networkAuthorization);
            doReset(applicationReply, applicationRouteId, applicationInitialId, end.trace());
        }

        private void handleAbort(
            AbortFW abort)
        {
            pendingFutures.forEach(f -> f.cancel(true));
            correlations.remove(networkReplyId);
            tlsEngine.closeOutbound();
            doAbort(networkInitial, networkRouteId, networkInitialId, networkAuthorization);
            doReset(applicationReply, applicationRouteId, applicationInitialId, abort.trace());
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
                if (tlsEngine.isOutboundDone())
                {
                    // tlsEngine.unwrap() throws IllegalStateException after tlsEngine.closeOutbound()
                    throw new SSLException("SSLEngine closed");
                }

                HandshakeStatus handshakeStatus = NOT_HANDSHAKING;
                Status status = BUFFER_UNDERFLOW;

                if (pendingTasks == 0)
                {
                    outAppByteBuffer.rewind();
                    SSLEngineResult result = tlsEngine.unwrap(inNetByteBuffer, outAppByteBuffer);
                    status = result.getStatus();
                    handshakeStatus = result.getHandshakeStatus();
                }

                if (outAppByteBuffer.position() != 0)
                {
                    doNetworkReplyReset(supplyTrace.getAsLong());
                    break loop;
                }

                switch (status)
                {
                case BUFFER_UNDERFLOW:
                    final int totalBytesConsumed = inNetByteBuffer.position() - inNetByteBufferPosition;
                    final int totalBytesRemaining = inNetByteBuffer.remaining();
                    alignSlotBuffer(inNetBuffer, totalBytesConsumed, totalBytesRemaining);
                    networkReplySlotOffset = totalBytesRemaining;
                    break loop;
                default:
                    networkReplySlotOffset = 0;
                    statusHandler.accept(handshakeStatus, this::updateNetworkWindow);
                    break;
                }
            }
        }

        private void updateNetworkWindow(
            SSLEngineResult result)
        {
            final int bytesProduced = result.bytesProduced();
            if (bytesProduced != 0)
            {
                final int networkBudget = networkBudgetSupplier.getAsInt();
                final int networkPadding = networkPaddingSupplier.getAsInt();
                networkBudgetConsumer.accept(networkBudget - bytesProduced - networkPadding);
            }
        }

        private void flushHandshake()
        {
            pendingTasks--;

            if (pendingTasks == 0)
            {
                pendingFutures.clear();

                if (networkReplySlot != NO_SLOT)
                {
                    try
                    {
                        final MutableDirectBuffer inNetBuffer = networkPool.buffer(networkReplySlot);
                        final ByteBuffer inNetByteBuffer = networkPool.byteBuffer(networkReplySlot);
                        inNetByteBuffer.limit(inNetByteBuffer.position() + networkReplySlotOffset);
                        processNetwork(inNetBuffer, inNetByteBuffer);
                    }
                    catch (SSLException ex)
                    {
                        networkReplySlotOffset = 0;
                        doReset(applicationReply, applicationRouteId, applicationInitialId);
                        doAbort(networkInitial, networkRouteId, networkInitialId, networkAuthorization);
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
                else
                {
                    try
                    {
                        statusHandler.accept(tlsEngine.getHandshakeStatus(), this::updateNetworkWindow);
                    }
                    catch (Exception ex)
                    {
                        // catches SSLException re-thrown as unchecked
                        doReset(applicationReply, applicationRouteId, applicationInitialId);
                        doAbort(networkInitial, networkRouteId, networkInitialId, networkAuthorization);
                    }
                }
            }
        }

        private void doNetworkReplyReset(
            long traceId)
        {
            release();
            doReset(networkInitial, networkRouteId, networkReplyId, traceId);
        }

        private void release()
        {
            if (networkReplySlot != NO_SLOT)
            {
                networkPool.release(networkReplySlot);
                networkReplySlot = NO_SLOT;
                networkReplySlotOffset = 0;
            }
        }
    }

    private final class ClientConnectReplyStream
    {
        private final MessageConsumer networkReplyThrottle;
        private final long networkRouteId;
        private final long networkReplyId;

        private MessageConsumer networkInitial;
        private long networkInitialId;
        private long networkAuthorization;

        private int networkReplyBudget;
        private int networkReplyPadding;
        private int applicationReplyBudget;
        private int applicationReplyPadding;

        private int networkReplySlot = NO_SLOT;
        private int networkReplySlotOffset;

        private SSLEngine tlsEngine;

        private MessageConsumer applicationReply;
        private long applicationRouteId;
        private long applicationReplyId;
        private final long applicationReplyAuthorization;
        private ObjectLongBiFunction<MessageConsumer, MessageConsumer> doBeginApplicationReply;

        private MessageConsumer streamState;
        private int applicationReplySlot = NO_SLOT;
        private int applicationReplySlotOffset;

        private Runnable networkReplyDoneHandler;
        private String applicationProtocol;
        private boolean defaultRoute;
        private IntSupplier networkPaddingSupplier;

        private long networkReplyTraceId;
        private ClientHandshake handshake;

        private ClientConnectReplyStream(
            MessageConsumer networkReplyThrottle,
            long networkRouteId,
            long networkReplyId,
            long networkReplyAuthorization)
        {
            this.networkReplyThrottle = networkReplyThrottle;
            this.networkRouteId = networkRouteId;
            this.networkReplyId = networkReplyId;
            this.applicationReplyAuthorization = networkReplyAuthorization;
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
                doNetworkReplyReset(supplyTrace.getAsLong());
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
                doNetworkReplyReset(supplyTrace.getAsLong());
                break;
            }
        }

        private void handleBegin(
            BeginFW begin)
        {
            final long replyId = begin.streamId();

            final ClientHandshake handshake = correlations.remove(replyId);
            if (handshake != null)
            {
                this.tlsEngine = handshake.tlsEngine;
                this.handshake = handshake;
                this.applicationProtocol = handshake.applicationProtocol;
                this.applicationRouteId = handshake.applicationRouteId;
                this.defaultRoute = handshake.defaultRoute;
                this.networkInitial = handshake.networkInitial;
                this.networkInitialId = handshake.networkInitialId;
                this.networkPaddingSupplier = handshake.networkPaddingSupplier;
                this.networkAuthorization = handshake.networkAuthorization;
                this.networkReplySlot = handshake.networkReplySlot;
                this.networkReplySlotOffset = handshake.networkReplySlotOffset;
                this.doBeginApplicationReply = handshake::doBeginApplicationReply;
                this.streamState = handshake::afterBegin;
                this.networkReplyDoneHandler = handshake.networkReplyDoneHandler;

                networkReplyBudget += handshakeWindowBytes;
                doWindow(networkReplyThrottle, networkRouteId, networkReplyId, networkReplyBudget, networkReplyPadding);

                handshake.onNetworkReply(this::handleStatus, this::getNetworkReplyBudget, this::getNetworkReplyPadding,
                        this::setNetworkReplyBudget);
            }
            else
            {
                doNetworkReplyReset(supplyTrace.getAsLong());
            }
        }

        int getNetworkReplyBudget()
        {
            return networkReplyBudget;
        }

        int getNetworkReplyPadding()
        {
            return networkReplyPadding;
        }

        void setNetworkReplyBudget(int networkReplyBudget)
        {
            this.networkReplyBudget = networkReplyBudget;
        }

        private void handleData(
            DataFW data)
        {
            final int dataLength = data.length();
            networkReplyTraceId = data.trace();

            networkReplyBudget -= dataLength + data.padding();

            if (networkReplySlot == NO_SLOT)
            {
                networkReplySlot = networkPool.acquire(networkReplyId);
            }

            try
            {
                if (networkReplySlot == NO_SLOT || networkReplyBudget < 0)
                {
                    tlsEngine.closeInbound();
                    doNetworkReplyReset(supplyTrace.getAsLong());
                    doAbort(applicationReply, applicationRouteId, applicationReplyId, applicationReplyAuthorization);
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
                doNetworkReplyReset(supplyTrace.getAsLong());
                doAbort(applicationReply, applicationRouteId, applicationReplyId, applicationReplyAuthorization);
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
                    doNetworkReplyReset(supplyTrace.getAsLong());
                    doAbort(applicationReply, applicationRouteId, applicationReplyId, applicationReplyAuthorization);
                }
                else
                {
                    final MutableDirectBuffer inNetBuffer = networkPool.buffer(networkReplySlot);
                    final ByteBuffer inNetByteBuffer = networkPool.byteBuffer(networkReplySlot);
                    final int inNetByteBufferPosition = inNetByteBuffer.position();
                    inNetByteBuffer.limit(inNetByteBuffer.position() + networkReplySlotOffset);

                    loop:
                    while (inNetByteBuffer.hasRemaining() && !tlsEngine.isInboundDone())
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
                                doNetworkReplyReset(supplyTrace.getAsLong());
                                doAbort(applicationReply, applicationRouteId, applicationReplyId, applicationReplyAuthorization);
                            }
                            else if (totalBytesConsumed == 0)
                            {
                                final int networkWindowBytesUpdate =
                                    Math.max(networkPool.slotCapacity() - networkReplySlotOffset - networkReplyBudget, 0);

                                if (networkWindowBytesUpdate > 0)
                                {
                                    networkReplyBudget += networkWindowBytesUpdate;
                                    doWindow(networkReplyThrottle, networkRouteId, networkReplyId, networkWindowBytesUpdate,
                                            networkReplyPadding);
                                }
                            }
                            break loop;
                        default:
                            networkReplySlotOffset = 0;
                            applicationReplySlotOffset += result.bytesProduced();
                            handleStatus(result.getHandshakeStatus(), r -> {});
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
                doNetworkReplyReset(supplyTrace.getAsLong());
                doAbort(applicationReply, applicationRouteId, applicationReplyId, applicationReplyAuthorization);
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
            releaseSlots();

            final long traceId = end.trace();
            try
            {
                if (!tlsEngine.isInboundDone() && !tlsEngine.isOutboundDone())
                {
                    // tlsEngine.closeInbound() without CLOSE_NOTIFY is permitted by specification
                    // but invalidates TLS session, preventing future abbreviated TLS handshakes from same client
                    doCloseOutbound(tlsEngine, networkInitial, networkRouteId, networkInitialId, supplyTrace.getAsLong(),
                                    0, end.authorization(), NOP);
                }

                doEnd(applicationReply, applicationRouteId, applicationReplyId, traceId, applicationReplyAuthorization);
            }
            catch (SSLException ex)
            {
                doAbort(applicationReply, applicationRouteId, applicationReplyId, traceId, applicationReplyAuthorization);
            }
        }

        private void handleAbort(
            AbortFW abort)
        {
            releaseSlots();
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
                doAbort(applicationReply, applicationRouteId, applicationReplyId, abort.trace(), applicationReplyAuthorization);
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
                            Future<?> future = executor.execute(runnable, networkRouteId, networkReplyId, FLUSH_HANDSHAKE_SIGNAL);
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
                        outNetByteBuffer.rewind();
                        SSLEngineResult result = tlsEngine.wrap(EMPTY_BYTE_BUFFER, outNetByteBuffer);
                        resultHandler.accept(result);
                        flushNetwork(
                            tlsEngine,
                            result.bytesProduced(),
                            networkInitial,
                            networkRouteId,
                            networkInitialId,
                            networkReplyTraceId,
                            networkPaddingSupplier.getAsInt(),
                            networkAuthorization,
                            networkReplyDoneHandler);
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
        }

        private void handleFinished()
        {
            if (doBeginApplicationReply != null)
            {
                String tlsApplicationProtocol = tlsEngine.getApplicationProtocol();
                if ((tlsApplicationProtocol.equals("") && defaultRoute)
                        || Objects.equals(tlsApplicationProtocol, applicationProtocol))
                {
                    // no ALPN negotiation && default route OR
                    // negotiated protocol from ALPN matches with our route
                    final long newApplicationReplyId = supplyReplyId.applyAsLong(handshake.applicationInitialId);
                    this.applicationReply = this.doBeginApplicationReply.apply(this::handleThrottle, newApplicationReplyId);
                    this.applicationReplyId = newApplicationReplyId;

                    this.streamState = this::afterHandshake;
                    this.handshake = null;
                    this.doBeginApplicationReply = null;
                }
                else
                {
                    doNetworkReplyReset(supplyTrace.getAsLong());
                }
            }
        }

        private void handleFlushAppData()
        {
            if (applicationReplySlotOffset > 0)
            {
                final MutableDirectBuffer outAppBuffer = applicationPool.buffer(applicationReplySlot);
                final int applicationWindow = applicationReplyBudget - applicationReplyPadding;
                final int applicationBytesConsumed = Math.min(applicationReplySlotOffset, applicationWindow);

                if (applicationBytesConsumed > 0)
                {
                    final OctetsFW outAppOctets = outAppOctetsRO.wrap(outAppBuffer, 0, applicationBytesConsumed);

                    doData(applicationReply, applicationRouteId, applicationReplyId, networkReplyTraceId,
                            applicationReplyPadding, applicationReplyAuthorization, outAppOctets);

                    applicationReplyBudget -= applicationBytesConsumed + applicationReplyPadding;

                    applicationReplySlotOffset -= applicationBytesConsumed;

                    if (applicationReplySlotOffset != 0)
                    {
                        alignSlotBuffer(outAppBuffer, applicationBytesConsumed, applicationReplySlotOffset);
                    }
                }

            }

            if (applicationReplySlotOffset == 0 && tlsEngine.isInboundDone())
            {
                doEnd(applicationReply, applicationRouteId, applicationReplyId,
                        networkReplyTraceId, applicationReplyAuthorization);
                if (networkReplyBudget == -1)
                {
                    doNetworkReplyReset(supplyTrace.getAsLong());
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
            applicationReplyBudget += window.credit();
            applicationReplyPadding = networkReplyPadding = window.padding();

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
                    if (networkReplySlotOffset == 0 && networkReplySlot != NO_SLOT)
                    {
                        networkPool.release(networkReplySlot);
                        networkReplySlot = NO_SLOT;
                    }
                }
            }

            final int networkCredit = Math.min(applicationReplyBudget, networkPool.slotCapacity())
                    - networkReplyBudget - networkReplySlotOffset;

            if (networkCredit > 0)
            {
                networkReplyBudget += networkCredit;
                doWindow(networkReplyThrottle, networkRouteId, networkReplyId,
                        window.trace(), networkCredit, networkReplyPadding);
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
                doNetworkReplyReset(reset.trace());
            }
        }

        private void doNetworkReplyReset(
            long traceId)
        {
            releaseSlots();
            doReset(networkReplyThrottle, networkRouteId, networkReplyId, traceId);
        }

        private void releaseSlots()
        {
            if (networkReplySlot != NO_SLOT)
            {
                networkPool.release(networkReplySlot);
                networkReplySlot = NO_SLOT;
                networkReplySlotOffset = 0;
            }
            if (applicationReplySlot != NO_SLOT)
            {
                applicationPool.release(applicationReplySlot);
                applicationReplySlot = NO_SLOT;
                applicationReplySlotOffset = 0;
            }
        }

    }

    private void flushNetwork(
        SSLEngine tlsEngine,
        int bytesProduced,
        MessageConsumer networkTarget,
        long networkRouteId,
        long networkId,
        long traceId,
        int padding,
        long authorization,
        Runnable networkReplyDoneHandler)
    {
        if (bytesProduced > 0)
        {
            final OctetsFW outNetOctets = outNetOctetsRO.wrap(outNetBuffer, 0, bytesProduced);
            doData(networkTarget, networkRouteId, networkId, traceId, padding, authorization, outNetOctets);
        }

        if (tlsEngine.isOutboundDone())
        {
            doEnd(networkTarget, networkRouteId, networkId, traceId, authorization);
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
        MessageConsumer receiver,
        long routeId,
        long streamId,
        String hostname,
        String applicationProtocol)
    {
        final BeginFW begin = beginRW.wrap(writeBuffer, 0, writeBuffer.capacity())
                                     .routeId(routeId)
                                     .streamId(streamId)
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
        final long traceId,
        final long authorization,
        final OctetsFW extension)
    {
        final BeginFW begin = beginRW.wrap(writeBuffer, 0, writeBuffer.capacity())
                .routeId(routeId)
                .streamId(streamId)
                .trace(traceId)
                .authorization(authorization)
                .extension(extension)
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
                .payload(p -> p.set(payload.buffer(), payload.offset(), payload.sizeof()))
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

    private void doCloseOutbound(
        SSLEngine tlsEngine,
        MessageConsumer networkTarget,
        long networkRouteId,
        long networkId,
        long traceId,
        int networkPadding,
        long authorization,
        Runnable networkReplyDoneHandler) throws SSLException
    {
        tlsEngine.closeOutbound();
        outNetByteBuffer.rewind();
        SSLEngineResult result = tlsEngine.wrap(inAppByteBuffer, outNetByteBuffer);
        if (result.bytesProduced() > 0)
        {
            // networkWindowBudget -= result.bytesProduced() + networkWindowPadding;
        }
        flushNetwork(tlsEngine, result.bytesProduced(), networkTarget, networkRouteId, networkId,
                traceId, networkPadding, authorization,
                networkReplyDoneHandler);
    }

}
