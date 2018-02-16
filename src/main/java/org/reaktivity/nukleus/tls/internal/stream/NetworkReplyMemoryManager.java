package org.reaktivity.nukleus.tls.internal.stream;

import java.nio.ByteBuffer;
import java.util.function.Consumer;

import org.agrona.MutableDirectBuffer;
import org.agrona.collections.IntArrayList;
import org.agrona.concurrent.UnsafeBuffer;
import org.reaktivity.nukleus.buffer.DirectBufferBuilder;
import org.reaktivity.nukleus.buffer.MemoryManager;
import org.reaktivity.nukleus.tls.internal.types.ListFW;
import org.reaktivity.nukleus.tls.internal.types.ListFW.Builder;
import org.reaktivity.nukleus.tls.internal.types.stream.RegionFW;
import org.reaktivity.reaktor.internal.buffer.DefaultDirectBufferBuilder;

class NetworkReplyMemoryManager2
{
    public static final ListFW<RegionFW> EMPTY_REGION_RO;

    private static final byte EMPTY_REGION_TAG = 0x00;
    private static final byte FULL_REGION_TAG = 0x01;
    private static final byte WRAP_AROUND_REGION_TAG = 0x02;

    private static final int TAG_SIZE_PER_CHUNK = 1;
    private static final int TAG_SIZE_PER_WRITE = TAG_SIZE_PER_CHUNK * 2; // at most generates 2 regions

    static
    {
        ListFW.Builder<RegionFW.Builder, RegionFW> regionsRW = new Builder<RegionFW.Builder, RegionFW>(
                new RegionFW.Builder(),
                new RegionFW());
        EMPTY_REGION_RO = regionsRW.wrap(new UnsafeBuffer(new byte[100]), 0, 100).build();
    }

    private final MutableDirectBuffer directBufferRW = new UnsafeBuffer(new byte[0]);
    private final ListFW<RegionFW> regionsRO = new ListFW<RegionFW>(new RegionFW());
    private final DirectBufferBuilder directBufferBuilderRO = new DefaultDirectBufferBuilder();

    private final MemoryManager memoryManager;

    private final int transferCapacity;
    private final long memoryAddress;
    private final long resolvedAddress;
    private final int indexMask;

    private long writeIndex;
    private long ackIndex;

    private IntArrayList marks = new IntArrayList(2, -2);

    NetworkReplyMemoryManager2(
        MemoryManager memoryManager,
        int transferCapacity)
    {
        this.memoryManager = memoryManager;
        this.transferCapacity = transferCapacity;
        this.memoryAddress = memoryManager.acquire(transferCapacity);
        this.resolvedAddress = memoryManager.resolve(memoryAddress);
        if (this.memoryAddress == -1)
        {
            throw new IllegalStateException("Unable to allocate memory block: " + transferCapacity);
        }
        this.writeIndex = 0;
        this.ackIndex = 0;

        this.indexMask = ~(transferCapacity - 1);
    }

    // Returns the payload size you can accept
    public int maxPayloadSize(
        ListFW<RegionFW> regions)
    {
        final int metaDataReserve =  regions.sizeof() + TAG_SIZE_PER_WRITE;
        final int unAcked = (int) (writeIndex - ackIndex);
        return transferCapacity - (unAcked + metaDataReserve);
    }

    // know you have room for meta data
    public Consumer<ListFW.Builder<RegionFW.Builder, RegionFW>> packRegions(
        ByteBuffer src,
        int srcIndex,
        int length,
        ListFW<RegionFW> consumedRegions)
    {
        int wIndex = (int) (indexMask & writeIndex);
        final int rIndex = (int) (indexMask & writeIndex);
        final int blockSizeAvailable = ((wIndex > rIndex) ? (wIndex - rIndex)  : rIndex - wIndex) - TAG_SIZE_PER_CHUNK;
        final int writeInLength = Math.min(blockSizeAvailable, length);
        directBufferRW.wrap(resolvedAddress + wIndex, writeInLength);
        directBufferRW.putBytes(0, src, srcIndex, writeInLength);

        wIndex += writeInLength;
        writeIndex += writeInLength;

        final int sizeOfRegions = consumedRegions.sizeof();

        if (length != writeInLength) // append tag and then write more
        {
            final int metaDataSize = TAG_SIZE_PER_CHUNK;
            directBufferRW.wrap(wIndex, metaDataSize);
            directBufferRW.putByte(0, EMPTY_REGION_TAG);
            writeIndex += metaDataSize;
            packRegions(src, srcIndex + writeInLength, length - writeInLength, consumedRegions);
        }
        else if (consumedRegions.isEmpty()) // append empty tag and return
        {
            final int metaDataSize = TAG_SIZE_PER_CHUNK;
            directBufferRW.wrap(wIndex, metaDataSize);
            directBufferRW.putByte(0, EMPTY_REGION_TAG);
            writeIndex += metaDataSize;
        }
        else if(sizeOfRegions + TAG_SIZE_PER_CHUNK > transferCapacity - wIndex) // append tags on wrap and return
        {
            throw new RuntimeException("NOT IMPLEMENTED");
        }
        else // append tags and return
        {
            final int metaDataSize = sizeOfRegions + TAG_SIZE_PER_CHUNK;
            directBufferRW.wrap(wIndex, metaDataSize);
            directBufferRW.putByte(0, FULL_REGION_TAG);
            directBufferRW.putBytes(TAG_SIZE_PER_CHUNK, consumedRegions.buffer(), consumedRegions.offset(), sizeOfRegions);

            writeIndex += metaDataSize;
        }
        return null;
    }

    public void buildAckedRegions(
        ListFW.Builder<RegionFW.Builder, RegionFW> builder,
        ListFW<RegionFW> regions)
    {
        regions.forEach(region ->
        {
            final long length = region.length();
            final long regionAddress = memoryManager.resolve(region.address());
            directBufferRW.wrap(regionAddress, TAG_SIZE_PER_CHUNK);
            ackIndex += length + TAG_SIZE_PER_CHUNK;

            switch (directBufferRW.getByte(0))
            {
                case EMPTY_REGION_TAG:
                    break;
                case FULL_REGION_TAG:
                    final int remainingCapacity = (int) (resolvedAddress - regionAddress + transferCapacity);
                    directBufferRW.wrap(regionAddress + TAG_SIZE_PER_CHUNK, remainingCapacity);
                    regionsRO.wrap(directBufferRW, 0, remainingCapacity)
                             .forEach(ackedRegion -> builder.item(rb -> rb.address(ackedRegion.address())
                                                                          .length(ackedRegion.length())
                                                                          .streamId(ackedRegion.streamId())));
                    ackIndex += regionsRO.sizeof();
                    break;
                case WRAP_AROUND_REGION_TAG:
                    throw new RuntimeException("NOT IMPLEMENTED");
                default:
                    throw new RuntimeException("Invalid state");
            }
        });
    }

    public void releaseHard()
    {
        memoryManager.release(memoryAddress, transferCapacity);
    }

    public void release()
    {
        assert writeIndex == ackIndex;
        memoryManager.release(memoryAddress, transferCapacity);
    }
}
