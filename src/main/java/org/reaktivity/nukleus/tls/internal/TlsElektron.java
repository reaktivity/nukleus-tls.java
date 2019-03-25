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
package org.reaktivity.nukleus.tls.internal;

import static org.reaktivity.nukleus.route.RouteKind.CLIENT;
import static org.reaktivity.nukleus.route.RouteKind.SERVER;

import java.util.EnumMap;
import java.util.Map;
import java.util.function.Function;

import javax.net.ssl.SSLContext;

import org.reaktivity.nukleus.Elektron;
import org.reaktivity.nukleus.route.RouteKind;
import org.reaktivity.nukleus.stream.StreamFactoryBuilder;
import org.reaktivity.nukleus.tls.internal.stream.ClientStreamFactoryBuilder;
import org.reaktivity.nukleus.tls.internal.stream.ServerStreamFactoryBuilder;

final class TlsElektron implements Elektron
{
    private final Map<RouteKind, StreamFactoryBuilder> streamFactoryBuilders;

    TlsElektron(
        TlsConfiguration config,
        Function<String, SSLContext> lookupContext)
    {
        Map<RouteKind, StreamFactoryBuilder> streamFactoryBuilders = new EnumMap<>(RouteKind.class);
        streamFactoryBuilders.put(SERVER, new ServerStreamFactoryBuilder(config, lookupContext));
        streamFactoryBuilders.put(CLIENT, new ClientStreamFactoryBuilder(config, lookupContext));
        this.streamFactoryBuilders = streamFactoryBuilders;
    }

    @Override
    public StreamFactoryBuilder streamFactoryBuilder(
        RouteKind kind)
    {
        return streamFactoryBuilders.get(kind);
    }

    @Override
    public String toString()
    {
        return String.format("%s %s", getClass().getSimpleName(), streamFactoryBuilders);
    }
}
