package org.reaktivity.nukleus.tls.internal.stream.util;

import java.util.function.Consumer;

import org.reaktivity.nukleus.tls.internal.types.ListFW.Builder;
import org.reaktivity.nukleus.tls.internal.types.stream.RegionFW;

@FunctionalInterface
public interface AckedRegionBuilder
{

    Consumer<Builder<RegionFW.Builder, RegionFW>> ackRegions(
            int totalBytesConsumed);
}
