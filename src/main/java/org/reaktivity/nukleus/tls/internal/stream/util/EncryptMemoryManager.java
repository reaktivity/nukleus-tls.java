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

package org.reaktivity.nukleus.tls.internal.stream.util;

import static org.reaktivity.nukleus.tls.internal.FrameFlags.EMPTY;

import java.nio.ByteBuffer;
import java.util.function.LongConsumer;
import java.util.function.LongSupplier;

import org.agrona.DirectBuffer;
import org.agrona.MutableDirectBuffer;
import org.agrona.collections.MutableInteger;
import org.agrona.concurrent.UnsafeBuffer;
import org.reaktivity.nukleus.buffer.DirectBufferBuilder;
import org.reaktivity.nukleus.buffer.MemoryManager;
import org.reaktivity.nukleus.tls.internal.types.ListFW;
import org.reaktivity.nukleus.tls.internal.types.ListFW.Builder;
import org.reaktivity.nukleus.tls.internal.types.stream.RegionFW;

public class EncryptMemoryManager
{
    private static final int MEM_NOT_SET = -1;
    public static final ListFW<RegionFW> EMPTY_REGION;
    static
    {
        ListFW.Builder<RegionFW.Builder, RegionFW> regionsRW = new Builder<RegionFW.Builder, RegionFW>(
                new RegionFW.Builder(),
                new RegionFW());
        EMPTY_REGION = regionsRW.wrap(new UnsafeBuffer(new byte[100]), 0, 100).build();
    }

    private static final byte EMPTY_REGION_TAG = 0x00;
    private static final byte FULL_REGION_TAG = 0x01;
    private static final byte WRAP_AROUND_REGION_TAG = 0x02;

    private static final int TAG_SIZE_PER_CHUNK = 1;
    private static final int TAG_SIZE_PER_WRITE = TAG_SIZE_PER_CHUNK * 2; // at most generates 2 regions
    private static final int MAX_REGION_SIZE = 1000;

    private final DirectBufferBuilder directBufferBuilderRO;
    private final MemoryManager memory;
    private final MutableDirectBuffer directBufferRW;
    private final ListFW<RegionFW> regionsRO;
    private final LongSupplier writeFramesAccumulator;
    private final LongConsumer writeBytesAccumulator;
    private final long streamId;
    private final int transferCapacity;
    private final long memoryAddress;
    private final long resolvedAddress;
    private final int indexMask;

    private long writeIndex;
    private long ackIndex;

    private final int backlogCapacity = 1024; // TODO: Configuration
    private long backlogAddress;
    private final MutableDirectBuffer backlogRW = new UnsafeBuffer(new byte[0]);
    private final ListFW.Builder<RegionFW.Builder, RegionFW> regionsRW =
            new ListFW.Builder<>(new RegionFW.Builder(), new RegionFW());

    private final DirectBuffer view = new UnsafeBuffer(new byte[0]);
    private final MutableInteger backlogOffset;
    private final MutableInteger iter;   // needed for lambda on ListFW
    private int queuedFlag = EMPTY;

    public EncryptMemoryManager(
        MemoryManager memoryManager,
        DirectBufferBuilder directBufferBuilderRO,
        MutableDirectBuffer directBufferRW,
        ListFW<RegionFW> regionsRO,
        int transferCapacity,
        long streamId,
        LongSupplier writeFramesAccumulator,
        LongConsumer writeBytesAccumulator)
    {
        this.directBufferBuilderRO = directBufferBuilderRO;
        this.memory = memoryManager;
        this.directBufferRW = directBufferRW;
        this.regionsRO = regionsRO;

        this.transferCapacity = transferCapacity;
        this.memoryAddress = memoryManager.acquire(transferCapacity);
        this.resolvedAddress = memoryManager.resolve(memoryAddress);
        if (this.memoryAddress == MEM_NOT_SET)
        {
            throw new IllegalStateException("Unable to allocate memory block: " + transferCapacity);
        }
        this.streamId = streamId;
        this.writeIndex = 0;
        this.ackIndex = 0;

        this.indexMask = transferCapacity - 1;

        this.writeBytesAccumulator = writeBytesAccumulator;
        this.writeFramesAccumulator = writeFramesAccumulator;
        this.backlogAddress = MEM_NOT_SET;

        this.backlogOffset = new MutableInteger();
        this.backlogOffset.value = 0;
        this.iter = new MutableInteger();
    }


    // know we have room for meta data cause must call maxPayloadSize
    public void packRegions(
        ByteBuffer src,
        int srcIndex,
        int length,
        ListFW<RegionFW> consumedRegions,
        ListFW.Builder<RegionFW.Builder, RegionFW> regionBuilders)
    {
        writeFramesAccumulator.getAsLong();
        writeBytesAccumulator.accept(length);
        final int sizeOfRegions = consumedRegions.isEmpty() ? TAG_SIZE_PER_CHUNK : consumedRegions.sizeof();
        int ackIndex = (int) (indexMask & writeIndex);
        final int rIndex = (int) (indexMask & ackIndex);

        final int lengthToWrap = ((ackIndex >= rIndex ? transferCapacity - ackIndex: rIndex - ackIndex));

        final int bytesToWrite = Math.min(lengthToWrap - TAG_SIZE_PER_CHUNK, length);
        directBufferRW.wrap(resolvedAddress + ackIndex, bytesToWrite);
        directBufferRW.putBytes(0, src, srcIndex, bytesToWrite);

        final long regionAddress = memoryAddress + ackIndex;
        regionBuilders.item(rb -> rb.address(regionAddress).length(bytesToWrite).streamId(streamId));
        ackIndex += bytesToWrite;
        writeIndex += bytesToWrite;


        if (length != bytesToWrite) // append tag and then write more
        {
            directBufferRW.wrap(resolvedAddress + ackIndex, TAG_SIZE_PER_CHUNK);
            directBufferRW.putByte(0, EMPTY_REGION_TAG);
            writeIndex += TAG_SIZE_PER_CHUNK;
            packRegions(src, srcIndex + bytesToWrite, length - bytesToWrite, consumedRegions, regionBuilders);
        }
        else if (consumedRegions.isEmpty()) // append empty tag and return
        {
            directBufferRW.wrap(resolvedAddress + ackIndex, TAG_SIZE_PER_CHUNK);
            directBufferRW.putByte(0, EMPTY_REGION_TAG);
            writeIndex += TAG_SIZE_PER_CHUNK;
        }
        else if(sizeOfRegions + TAG_SIZE_PER_CHUNK > transferCapacity - ackIndex) // append tags on wrap and return
        {
            directBufferRW.wrap(resolvedAddress + ackIndex, TAG_SIZE_PER_CHUNK);
            directBufferRW.putByte(0, WRAP_AROUND_REGION_TAG);

            int leftOverToWrite = transferCapacity - ackIndex - TAG_SIZE_PER_CHUNK;
            if (leftOverToWrite > 0)
            {
                directBufferRW.wrap(resolvedAddress + ackIndex + TAG_SIZE_PER_CHUNK, leftOverToWrite);
                directBufferRW.putBytes(
                    0,
                    consumedRegions.buffer(),
                    consumedRegions.offset(),
                    leftOverToWrite);
            }
            int rollOverToWrite = consumedRegions.sizeof() - leftOverToWrite;
            directBufferRW.wrap(resolvedAddress, rollOverToWrite);
            directBufferRW.putBytes(
                    0,
                    consumedRegions.buffer(),
                    consumedRegions.offset() + leftOverToWrite,
                    rollOverToWrite);

            writeIndex += TAG_SIZE_PER_CHUNK + sizeOfRegions;
        }
        else // append tags and return
        {
            directBufferRW.wrap(resolvedAddress + ackIndex, sizeOfRegions + TAG_SIZE_PER_CHUNK);
            directBufferRW.putByte(0, FULL_REGION_TAG);
            directBufferRW.putBytes(TAG_SIZE_PER_CHUNK, consumedRegions.buffer(), consumedRegions.offset(), sizeOfRegions);

            writeIndex += sizeOfRegions + TAG_SIZE_PER_CHUNK;
        }
    }

    public void buildAckedRegions(
        ListFW.Builder<RegionFW.Builder, RegionFW> builder,
        ListFW<RegionFW> regions)
    {
        regions.forEach(region ->
        {
            final long length = region.length();
            final long regionAddress = memory.resolve(region.address());
            directBufferRW.wrap(regionAddress + length, TAG_SIZE_PER_CHUNK);
            ackIndex += length + TAG_SIZE_PER_CHUNK;

            switch (directBufferRW.getByte(0))
            {
                case EMPTY_REGION_TAG:
                    break;
                case FULL_REGION_TAG:
                {
                    final int remainingCapacity = (int) (resolvedAddress - regionAddress + transferCapacity);
                    directBufferRW.wrap(regionAddress + length + TAG_SIZE_PER_CHUNK, remainingCapacity);
                    regionsRO.wrap(directBufferRW, 0, remainingCapacity)
                             .forEach(ackedRegion -> builder.item(rb -> rb.address(ackedRegion.address())
                                                                          .length(ackedRegion.length())
                                                                          .streamId(ackedRegion.streamId())));
                    ackIndex += regionsRO.sizeof();
                    break;
                }
                case WRAP_AROUND_REGION_TAG:
                {
                    final int remaining = MAX_REGION_SIZE;
                    final int ackOffset = (int) (ackIndex & indexMask);
                    final int toEndOfBuffer = Math.min(transferCapacity - ackOffset, remaining);

                    directBufferBuilderRO.wrap(resolvedAddress + ackOffset, toEndOfBuffer);
                    directBufferBuilderRO.wrap(resolvedAddress, remaining - toEndOfBuffer);

                    DirectBuffer directBufferRO = directBufferBuilderRO.build();

                    regionsRO.wrap(directBufferRO, 0, MAX_REGION_SIZE)
                        .forEach(ackedRegion -> builder.item(rb -> rb.address(ackedRegion.address())
                                                                 .length(ackedRegion.length())
                                                                 .streamId(ackedRegion.streamId())));
                    ackIndex += regionsRO.sizeof();
                    break;
                }
                default:
                    throw new IllegalArgumentException("Invalid state");
            }
        });
    }

    public void release()
    {
        memory.release(memoryAddress, transferCapacity);
    }

    public int maxWriteCapacity(
        ListFW<RegionFW> regions)
    {
        final int metaDataReserve =  regions.sizeof() + TAG_SIZE_PER_WRITE;
        final int unAcked = (int) (writeIndex - ackIndex);
        return transferCapacity - (unAcked + metaDataReserve);
    }

    public ListFW<RegionFW> stageRegions(
        ListFW<RegionFW> regions,
        ByteBuffer tlsInBuffer,
        int flags)
    {
        this.queuedFlag |= flags;
        regions = backlog(backlogAddress, regions);
        tlsInBuffer.clear();

        iter.value = 0;
        regions.forEach(r -> // TODO: remove multi line lambda
        {
            if (iter.value + r.length() > backlogOffset.value)
            {
                final int position = (iter.value < backlogOffset.value) ? backlogOffset.value - iter.value : 0;
                final int length = Math.min(tlsInBuffer.remaining(), r.length() - position);
                if (length > 0)
                {
                    view.wrap(memory.resolve(r.address()) + position, length);
                    view.getBytes(0, tlsInBuffer, tlsInBuffer.position(), length);
                    tlsInBuffer.position(tlsInBuffer.position() + length);
                }
            }
            iter.value += r.length();
        });
        tlsInBuffer.flip();
        return regions;
    }

    public boolean hasBacklog()
    {
        return backlogAddress != MEM_NOT_SET;
    }

    private ListFW<RegionFW> backlog(
            long address,
            ListFW<RegionFW> regions)
    {
        if (backlogAddress != MEM_NOT_SET)
        {
            final MutableDirectBuffer backlog = backlogRW;
            backlog.wrap(memory.resolve(backlogAddress), backlogCapacity);
            regionsRW.wrap(backlog, 0, backlog.capacity());
            regionsRO.wrap(backlog, 0, backlog.capacity())
                     .forEach(this::appendRegion);
            regions.forEach(this::appendRegion);
            regions = regionsRW.build();
        }
        return regions;
    }

    public int setBacklog(
        ListFW<RegionFW> regions,
        final int bytesConsumed)
    {
        if (backlogAddress != MEM_NOT_SET)
        {
            final MutableDirectBuffer backlog = backlogRW;
            backlog.wrap(memory.resolve(backlogAddress), backlogCapacity);
            regions = regionsRO.wrap(backlog, 0, backlogCapacity);
            regionsRW.wrap(backlog, 0, backlog.capacity());
        }

        backlogOffset.value += bytesConsumed;
        iter.value = 0;
        regions.forEach(r ->
        {
            if (iter.value + r.length() > backlogOffset.value)
            {
                if (iter.value < backlogOffset.value)
                {
                    // first region
                    backlogOffset.value -= iter.value;
                }
                if (backlogAddress == MEM_NOT_SET)
                {
                    final MutableDirectBuffer backlog = backlogRW;
                    backlog.wrap(memory.resolve(backlogAddress), backlogCapacity);
                    backlogAddress = acquireWriteMemory(backlogAddress);
                    backlog.wrap(memory.resolve(backlogAddress), backlogCapacity);
                    regionsRW.wrap(backlog, 0, backlog.capacity());
                }
                regionsRW.item(rb -> rb.address(r.address()).length(r.length()).streamId(r.streamId()));
            }
            iter.value += r.length();
        });
        if (backlogAddress != MEM_NOT_SET && regionsRW.build().isEmpty())
        {
            backlogAddress = releaseWriteMemory(backlogAddress);
        }
        if (backlogAddress == MEM_NOT_SET)
        {
            backlogOffset.value = 0;
        }
        return queuedFlag;
    }

    private void appendRegion(
        RegionFW region)
    {
        regionsRW.item(r -> r.address(region.address())
                             .length(region.length())
                             .streamId(region.streamId()));
    }

    public long acquireWriteMemory(
        long address)
    {
        return address == -1L ? memory.acquire(backlogCapacity) : address;
    }

    public long releaseWriteMemory(
        long address)
    {
        if (address != -1L)
        {
            memory.release(address, backlogCapacity);
        }
        return -1L;
    }

}
