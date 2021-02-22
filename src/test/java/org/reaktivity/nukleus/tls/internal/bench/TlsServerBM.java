/**
 * Copyright 2016-2021 The Reaktivity Project
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
package org.reaktivity.nukleus.tls.internal.bench;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.concurrent.TimeUnit.SECONDS;
import static org.reaktivity.reaktor.ReaktorConfiguration.REAKTOR_DIRECTORY;
import static org.reaktivity.reaktor.ReaktorConfiguration.REAKTOR_STREAMS_BUFFER_CAPACITY;

import java.util.Properties;
import java.util.Random;
import java.util.function.ToIntFunction;

import org.agrona.DirectBuffer;
import org.agrona.MutableDirectBuffer;
import org.agrona.concurrent.UnsafeBuffer;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Group;
import org.openjdk.jmh.annotations.GroupThreads;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.TearDown;
import org.openjdk.jmh.annotations.Warmup;
import org.openjdk.jmh.infra.Control;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;
import org.reaktivity.nukleus.tls.internal.types.Flyweight;
import org.reaktivity.nukleus.tls.internal.types.stream.BeginFW;
import org.reaktivity.nukleus.tls.internal.types.stream.DataFW;
import org.reaktivity.nukleus.tls.internal.types.stream.ProxyBeginExFW;
import org.reaktivity.nukleus.tls.internal.types.stream.WindowFW;
import org.reaktivity.reaktor.Reaktor;
import org.reaktivity.reaktor.nukleus.Configuration;
import org.reaktivity.reaktor.nukleus.function.MessageConsumer;
import org.reaktivity.reaktor.nukleus.function.MessagePredicate;

@State(Scope.Benchmark)
@BenchmarkMode(Mode.Throughput)
@Fork(3)
@Warmup(iterations = 5, time = 1, timeUnit = SECONDS)
@Measurement(iterations = 5, time = 1, timeUnit = SECONDS)
@OutputTimeUnit(SECONDS)
public class TlsServerBM
{
    private final Configuration configuration;
    private final Reaktor reaktor;

    {
        Properties properties = new Properties();
        properties.setProperty(REAKTOR_DIRECTORY.name(), "target/nukleus-benchmarks");
        properties.setProperty(REAKTOR_STREAMS_BUFFER_CAPACITY.name(), Long.toString(1024L * 1024L * 16L));

        configuration = new Configuration(properties);

        reaktor = Reaktor.builder()
                .config(configuration)
                .errorHandler(ex -> ex.printStackTrace(System.err))
                .build();

    }

    private final BeginFW beginRO = new BeginFW();
    private final DataFW dataRO = new DataFW();

    private final BeginFW.Builder beginRW = new BeginFW.Builder();
    private final DataFW.Builder dataRW = new DataFW.Builder();
    private final WindowFW.Builder windowRW = new WindowFW.Builder();

    private final ProxyBeginExFW.Builder tlsBeginExRW = new ProxyBeginExFW.Builder();

    private Source source;
    private Target target;

    private long routeId;
    private long targetRef;

    @Setup(Level.Trial)
    public void reinit() throws Exception
    {
        //final TlsController controller = reaktor.controller(TlsController.class);

        final Random random = new Random();
        this.targetRef = random.nextLong();
        //this.routeId = controller.route(SERVER, "tls#0", "target#0", null).get();

        final long sourceId = random.nextLong();

        source.reinit(routeId, sourceId);
        target.reinit();

        source.doBegin();
    }

    @TearDown(Level.Trial)
    public void reset() throws Exception
    {
        //final TlsController controller = reaktor.controller(TlsController.class);

        //controller.unroute(routeId).get();

        this.source = null;
        this.target = null;
    }

    @Benchmark
    @Group("throughput")
    @GroupThreads(1)
    public void writer(
        Control control) throws Exception
    {
        while (!control.stopMeasurement &&
               source.process() == 0)
        {
            Thread.yield();
        }
    }

    @Benchmark
    @Group("throughput")
    @GroupThreads(1)
    public void reader(
        Control control) throws Exception
    {
        while (!control.stopMeasurement &&
               target.read() == 0)
        {
            Thread.yield();
        }
    }

    private final class Source
    {
        private final MessagePredicate streams;
        private final ToIntFunction<MessageConsumer> throttle;

        private BeginFW begin;
        private DataFW data;

        private Source(
            MessagePredicate streams,
            ToIntFunction<MessageConsumer> throttle)
        {
            this.streams = streams;
            this.throttle = throttle;
        }

        private void reinit(
            long sourceRef,
            long sourceId)
        {
            final MutableDirectBuffer writeBuffer = new UnsafeBuffer(new byte[256]);

            // TODO: move to doBegin to avoid writeBuffer overwrite with DataFW
            this.begin = beginRW.wrap(writeBuffer, 0, writeBuffer.capacity())
                    .routeId(routeId)
                    .streamId(sourceId)
                    .sequence(0L)
                    .acknowledge(0L)
                    .extension(e -> e.set(visitTlsBeginEx("example.com")))
                    .build();

            byte[] charBytes = "Hello, world".getBytes(UTF_8);

            // TODO: use SslEngine to drive client behavior
        }

        private boolean doBegin()
        {
            return streams.test(begin.typeId(), begin.buffer(), begin.offset(), begin.sizeof());
        }

        private int process()
        {
            int work = 0;

            if (streams.test(data.typeId(), data.buffer(), data.offset(), data.sizeof()))
            {
                work++;
            }

            work += throttle.applyAsInt((t, b, i, l) -> {});

            return work;
        }

        private Flyweight.Builder.Visitor visitTlsBeginEx(
            String hostname)
        {
            return (buffer, offset, limit) ->
                tlsBeginExRW.wrap(buffer, offset, limit)
                            .address(a -> a.none(n -> {}))
                            .infosItem(i -> i.authority(hostname))
                            .build()
                            .sizeof();
        }
    }

    private final class Target
    {
        private final ToIntFunction<MessageConsumer> streams;
        private final MessagePredicate throttle;
        private final int windowMax;
        private final int windowPad;

        private MutableDirectBuffer writeBuffer;
        private MessageConsumer readHandler;
        private long sequence;
        private long acknowledge;

        private Target(
            ToIntFunction<MessageConsumer> streams,
            MessagePredicate throttle)
        {
            this.streams = streams;
            this.throttle = throttle;
            this.windowMax = 8192;
            this.windowPad = 0;
        }

        private void reinit()
        {
            this.writeBuffer = new UnsafeBuffer(new byte[256]);
            this.readHandler = this::beforeBegin;
        }

        private int read()
        {
            return streams.applyAsInt(readHandler);
        }

        private void beforeBegin(
            int msgTypeId,
            DirectBuffer buffer,
            int index,
            int length)
        {
            final BeginFW begin = beginRO.wrap(buffer, index, index + length);
            final long streamId = begin.streamId();
            final long sequence = begin.sequence();

            this.sequence = sequence;
            this.acknowledge = sequence;

            doWindow(streamId);

            this.readHandler = this::afterBegin;
        }

        private void afterBegin(
            int msgTypeId,
            DirectBuffer buffer,
            int index,
            int length)
        {
            final DataFW data = dataRO.wrap(buffer, index, index + length);
            final long streamId = data.streamId();
            final long sequence = data.sequence();
            final int reserved = data.reserved();

            this.sequence = sequence + reserved;
            this.acknowledge = sequence + reserved;

            doWindow(streamId);
        }

        private boolean doWindow(
            final long streamId)
        {
            final WindowFW window = windowRW.wrap(writeBuffer, 0, writeBuffer.capacity())
                    .routeId(routeId)
                    .streamId(streamId)
                    .sequence(sequence)
                    .acknowledge(acknowledge)
                    .padding(windowPad)
                    .maximum(windowMax)
                    .build();

            return throttle.test(window.typeId(), window.buffer(), window.offset(), window.sizeof());
        }
    }

    public static void main(String[] args) throws RunnerException
    {
        Options opt = new OptionsBuilder()
                .include(TlsServerBM.class.getSimpleName())
                .forks(0)
                .build();

        new Runner(opt).run();
    }
}
