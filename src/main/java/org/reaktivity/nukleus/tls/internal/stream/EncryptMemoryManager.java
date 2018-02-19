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

import java.nio.ByteBuffer;
import java.util.function.LongConsumer;
import java.util.function.LongSupplier;

import org.agrona.DirectBuffer;
import org.agrona.MutableDirectBuffer;
import org.agrona.concurrent.UnsafeBuffer;
import org.reaktivity.nukleus.buffer.DirectBufferBuilder;
import org.reaktivity.nukleus.buffer.MemoryManager;
import org.reaktivity.nukleus.tls.internal.types.ListFW;
import org.reaktivity.nukleus.tls.internal.types.ListFW.Builder;
import org.reaktivity.nukleus.tls.internal.types.stream.RegionFW;

public class EncryptMemoryManager
{
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

    private final DirectBufferBuilder directBufferBuilderRO;
    private final MemoryManager memoryManager;
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


    EncryptMemoryManager(
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
        this.memoryManager = memoryManager;
        this.directBufferRW = directBufferRW;
        this.regionsRO = regionsRO;

        this.transferCapacity = transferCapacity;
        this.memoryAddress = memoryManager.acquire(transferCapacity);
        this.resolvedAddress = memoryManager.resolve(memoryAddress);
        if (this.memoryAddress == -1)
        {
            throw new IllegalStateException("Unable to allocate memory block: " + transferCapacity);
        }
        this.streamId = streamId;
        this.writeIndex = 0;
        this.ackIndex = 0;

        this.indexMask = transferCapacity - 1;

        this.writeBytesAccumulator = writeBytesAccumulator;
        this.writeFramesAccumulator = writeFramesAccumulator;
    }

    // Returns the payload size you can accept
    public int maxPayloadSize(
        ListFW<RegionFW> regions)
    {
        final int metaDataReserve =  regions.sizeof() + TAG_SIZE_PER_WRITE;
        final int unAcked = (int) (writeIndex - ackIndex);
        return transferCapacity - (unAcked + metaDataReserve);
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
        int wIndex = (int) (indexMask & writeIndex);
        final int rIndex = (int) (indexMask & ackIndex);

        final int blockSizeAvailable = ((wIndex >= rIndex ? transferCapacity - wIndex: rIndex - wIndex))
                                       - TAG_SIZE_PER_CHUNK;

        final int writeInLength = Math.min(blockSizeAvailable, length);
        directBufferRW.wrap(resolvedAddress + wIndex, writeInLength);
        directBufferRW.putBytes(0, src, srcIndex, writeInLength);

        final long regionAddress = memoryAddress + wIndex;
        regionBuilders.item(rb -> rb.address(regionAddress).length(writeInLength).streamId(streamId));
        wIndex += writeInLength;
        writeIndex += writeInLength;


        if (length != writeInLength) // append tag and then write more
        {
            final int metaDataSize = TAG_SIZE_PER_CHUNK;
            directBufferRW.wrap(resolvedAddress + wIndex, metaDataSize);
            directBufferRW.putByte(0, EMPTY_REGION_TAG);
            writeIndex += metaDataSize;
            packRegions(src, srcIndex + writeInLength, length - writeInLength, consumedRegions, regionBuilders);
        }
        else if (consumedRegions.isEmpty()) // append empty tag and return
        {
            final int metaDataSize = TAG_SIZE_PER_CHUNK;
            directBufferRW.wrap(resolvedAddress + wIndex, metaDataSize);
            directBufferRW.putByte(0, EMPTY_REGION_TAG);
            writeIndex += metaDataSize;
        }
        else if(sizeOfRegions + TAG_SIZE_PER_CHUNK > transferCapacity - wIndex) // append tags on wrap and return
        {
            final int metaDataSize = sizeOfRegions + TAG_SIZE_PER_CHUNK;

            System.out.println("Adding split at " + (resolvedAddress + wIndex) + " of length " + sizeOfRegions);

            directBufferRW.wrap(resolvedAddress + wIndex, TAG_SIZE_PER_CHUNK);
            directBufferRW.putByte(0, WRAP_AROUND_REGION_TAG);

            for (int i = 0; i < consumedRegions.sizeof(); i++)
            {
                System.out.printf("%02x ", consumedRegions.buffer().getByte(consumedRegions.offset() + i));
            }
            System.out.println("");

            int leftOverToWrite = transferCapacity - wIndex - TAG_SIZE_PER_CHUNK;
            if (leftOverToWrite > 0)
            {
                directBufferRW.wrap(resolvedAddress + wIndex + TAG_SIZE_PER_CHUNK, leftOverToWrite);
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

            writeIndex += metaDataSize + consumedRegions.sizeof();
        }
        else // append tags and return
        {
            final int metaDataSize = sizeOfRegions + TAG_SIZE_PER_CHUNK;
            directBufferRW.wrap(resolvedAddress + wIndex, metaDataSize);
            directBufferRW.putByte(0, FULL_REGION_TAG);
            directBufferRW.putBytes(TAG_SIZE_PER_CHUNK, consumedRegions.buffer(), consumedRegions.offset(), sizeOfRegions);

            writeIndex += metaDataSize;
        }
    }

    public void buildAckedRegions(
        ListFW.Builder<RegionFW.Builder, RegionFW> builder,
        ListFW<RegionFW> regions)
    {
        regions.forEach(region ->
        {
            final long length = region.length();
            final long regionAddress = memoryManager.resolve(region.address());
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
                    final int remainingCapacity = transferCapacity - (int) (ackIndex & indexMask);

                    System.out.println("remaining capacity: " + remainingCapacity);
                    directBufferBuilderRO.wrap(resolvedAddress + (ackIndex & indexMask), remainingCapacity);
                    directBufferBuilderRO.wrap(resolvedAddress, 1000);
                    DirectBuffer directBufferRO = directBufferBuilderRO.build();

                    System.out.println("DPW ---- reading region at " + (regionAddress + length + TAG_SIZE_PER_CHUNK));
                    for (int i = 0; i < remainingCapacity + 1000; i++)
                    {
                        System.out.printf("%02x ", directBufferRO.getByte(i));
                    }
                    System.out.println("");

                    regionsRO.wrap(directBufferRO, 0, remainingCapacity + 1000)
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
        memoryManager.release(memoryAddress, transferCapacity);
    }
}