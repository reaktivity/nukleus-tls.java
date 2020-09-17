/**
 * Copyright 2016-2020 The Reaktivity Project
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

import static java.lang.System.getProperty;
import static org.reaktivity.nukleus.route.RouteKind.CLIENT;
import static org.reaktivity.nukleus.route.RouteKind.SERVER;

import java.io.File;
import java.io.FileInputStream;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

import org.agrona.DirectBuffer;
import org.agrona.LangUtil;
import org.agrona.MutableDirectBuffer;
import org.agrona.collections.Int2ObjectHashMap;
import org.reaktivity.nukleus.Nukleus;
import org.reaktivity.nukleus.function.CommandHandler;
import org.reaktivity.nukleus.function.MessageConsumer;
import org.reaktivity.nukleus.function.MessagePredicate;
import org.reaktivity.nukleus.route.RouteKind;
import org.reaktivity.nukleus.tls.internal.types.control.ErrorFW;
import org.reaktivity.nukleus.tls.internal.types.control.ResolveFW;
import org.reaktivity.nukleus.tls.internal.types.control.ResolvedFW;
import org.reaktivity.nukleus.tls.internal.types.control.RouteFW;
import org.reaktivity.nukleus.tls.internal.types.control.TlsRouteExFW;
import org.reaktivity.nukleus.tls.internal.types.control.UnresolveFW;
import org.reaktivity.nukleus.tls.internal.types.control.UnresolvedFW;
import org.reaktivity.nukleus.tls.internal.types.control.UnrouteFW;
import org.reaktivity.reaktor.internal.router.RouteId;

public final class TlsNukleus implements Nukleus
{
    public static final String NAME = "tls";

    public static final boolean DEBUG_HANDSHAKE_FINISHED = Boolean.getBoolean("tls.debug.handshake.finished");

    private static final String PROPERTY_TLS_KEYSTORE = "tls.keystore";
    private static final String PROPERTY_TLS_KEYSTORE_TYPE = "tls.keystore.type";
    private static final String PROPERTY_TLS_KEYSTORE_PASSWORD = "tls.keystore.password";
    private static final String PROPERTY_TLS_TRUSTSTORE = "tls.truststore";
    private static final String PROPERTY_TLS_TRUSTSTORE_TYPE = "tls.truststore.type";
    private static final String PROPERTY_TLS_TRUSTSTORE_PASSWORD = "tls.truststore.password";

    private static final String DEFAULT_TLS_KEYSTORE = "keys";
    private static final String DEFAULT_TLS_KEYSTORE_TYPE = "JKS";
    private static final String DEFAULT_TLS_KEYSTORE_PASSWORD = "generated";
    private static final String DEFAULT_TLS_TRUSTSTORE = "trust";
    private static final String DEFAULT_TLS_TRUSTSTORE_TYPE = "JKS";
    private static final String DEFAULT_TLS_TRUSTSTORE_PASSWORD = "generated";

    private final UnrouteFW unrouteRO = new UnrouteFW();
    private final RouteFW routeRO = new RouteFW();
    private final TlsRouteExFW tlsRouteExRO = new TlsRouteExFW();

    private final ResolveFW resolveRO = new ResolveFW();
    private final ResolvedFW.Builder resolvedRW = new ResolvedFW.Builder();
    private final UnresolveFW unresolveRO = new UnresolveFW();
    private final UnresolvedFW.Builder unresolvedRW = new UnresolvedFW.Builder();
    private final ErrorFW.Builder errorRW = new ErrorFW.Builder();

    private final TlsConfiguration config;
    private final Map<RouteKind, MessagePredicate> routeHandlers;
    private final Int2ObjectHashMap<CommandHandler> commandHandlers;

    private final Map<Integer, String> storesByRouteId;

    private final TlsStoreInfo[] storeInfos;

    TlsNukleus(
        TlsConfiguration config)
    {
        this.config = config;

        this.storesByRouteId = new HashMap<>();
        this.storeInfos = new TlsStoreInfo[256];

        Map<RouteKind, MessagePredicate> routeHandlers = new EnumMap<>(RouteKind.class);
        routeHandlers.put(SERVER, this::handleRoute);
        routeHandlers.put(CLIENT, this::handleRoute);
        this.routeHandlers = routeHandlers;
        final Int2ObjectHashMap<CommandHandler> commandHandlers = new Int2ObjectHashMap<>();
        commandHandlers.put(ResolveFW.TYPE_ID, this::resolve);
        commandHandlers.put(UnresolveFW.TYPE_ID, this::unresolve);
        this.commandHandlers = commandHandlers;
    }

    @Override
    public String name()
    {
        return TlsNukleus.NAME;
    }

    @Override
    public TlsConfiguration config()
    {
        return config;
    }

    @Override
    public MessagePredicate routeHandler(
        RouteKind kind)
    {
        return routeHandlers.get(kind);
    }

    @Override
    public CommandHandler commandHandler(
        int msgTypeId)
    {
        return commandHandlers.get(msgTypeId);
    }

    @Override
    public TlsElektron supplyElektron()
    {
        return new TlsElektron(config, localAddr -> findStore(storesByRouteId.get(localAddr)));
    }

    private boolean handleRoute(
        int msgTypeId,
        DirectBuffer buffer,
        int index,
        int length)
    {
        boolean handled = false;
        switch (msgTypeId)
        {
        case RouteFW.TYPE_ID:
            final RouteFW route = routeRO.wrap(buffer, index, index + length);
            handled = handleRoute(route);
            break;
        case UnrouteFW.TYPE_ID:
            final UnrouteFW unroute = unrouteRO.wrap(buffer, index, index + length);
            handled = handleUnroute(unroute);
            break;
        }
        return handled;
    }

    private boolean handleRoute(
        final RouteFW route)
    {
        final TlsRouteExFW routeEx = route.extension().get(tlsRouteExRO::wrap);
        final String store = routeEx.store().asString();
        final long routeId = route.correlationId();

        storesByRouteId.put(RouteId.localId(routeId), store);
        TlsStoreInfo storeInfo = newStoreInfoIfNecessary(store);
        if (storeInfo != null)
        {
            storeInfo.routeCount++;
        }

        return storeInfo != null;
    }

    private boolean handleUnroute(
        final UnrouteFW unroute)
    {
        final long routeId = unroute.routeId();

        final String store = storesByRouteId.remove(RouteId.localId(routeId));
        TlsStoreInfo storeInfo = findStore(store);
        if (storeInfo != null)
        {
            storeInfo.routeCount--;
            if (storeInfo.routeCount == 0)
            {
                storeInfos[storeInfo.storeIndex] = null;
            }
        }
        return true;
    }

    private void resolve(
        DirectBuffer buffer,
        int index,
        int length,
        MessageConsumer reply,
        MutableDirectBuffer replyBuffer)
    {
        ResolveFW resolve = resolveRO.wrap(buffer, index, index + length);
        String realm = resolve.realm().asString();
        long authorization = 0L;
        if (realm != null)
        {
            int position = realm.indexOf(':');
            String store = position == -1 ? null : realm.substring(0, position);
            TlsStoreInfo storeInfo = newStoreInfoIfNecessary(store);
            if (storeInfo != null)
            {
                storeInfo.routeCount++;
                String dname = realm.substring(position + 1);
                authorization = storeInfo.authorization(dname);
            }
        }

        if (authorization != 0L)
        {
            ResolvedFW resolved = resolvedRW.wrap(replyBuffer, 0,  replyBuffer.capacity())
                    .correlationId(resolve.correlationId())
                    .authorization(authorization)
                    .build();
            reply.accept(ResolvedFW.TYPE_ID, resolved.buffer(), resolved.offset(), resolved.sizeof());
        }
        else
        {
            ErrorFW error = errorRW.wrap(replyBuffer, 0,  replyBuffer.capacity())
                    .correlationId(resolve.correlationId())
                    .build();
            reply.accept(ErrorFW.TYPE_ID, error.buffer(), error.offset(), error.sizeof());
        }
    }

    private void unresolve(
        DirectBuffer buffer,
        int index,
        int length,
        MessageConsumer reply,
        MutableDirectBuffer replyBuffer)
    {
        UnresolveFW unresolve = unresolveRO.wrap(buffer, index, index + length);
        long authorization = unresolve.authorization();
        boolean unresolved = false;
        if (authorization != 0L)
        {
            int storeIndex = (int) (authorization >>> 56);
            TlsStoreInfo storeInfo = storeInfos[storeIndex];
            storeInfo.routeCount--;
            if (storeInfo.routeCount == 0)
            {
                storeInfos[storeInfo.storeIndex] = null;
            }
            unresolved = storeInfo.unresolve(authorization);
        }
        if (unresolved)
        {
            UnresolvedFW result = unresolvedRW.wrap(replyBuffer, 0,  replyBuffer.capacity())
                    .correlationId(unresolve.correlationId())
                    .build();
            reply.accept(UnresolvedFW.TYPE_ID, result.buffer(), result.offset(), result.sizeof());
        }
        else
        {
            ErrorFW error = errorRW.wrap(replyBuffer, 0,  replyBuffer.capacity())
                    .correlationId(unresolve.correlationId())
                    .build();
            reply.accept(ErrorFW.TYPE_ID, error.buffer(), error.offset(), error.sizeof());
        }
    }

    private TlsStoreInfo newStoreInfoIfNecessary(
        String store)
    {
        TlsStoreInfo storeInfo = findStore(store);
        if (storeInfo != null)
        {
            return storeInfo;
        }

        Path directory = config.directory();
        SSLContext context = null;
        Set<String> caDnames = new LinkedHashSet<>();
        boolean trustStoreExists = false;
        int storeIndex = nextIndex(store);

        try
        {
            String keyStorePassword = getProperty(PROPERTY_TLS_KEYSTORE_PASSWORD, DEFAULT_TLS_KEYSTORE_PASSWORD);
            String keyStoreFilename = getProperty(PROPERTY_TLS_KEYSTORE, DEFAULT_TLS_KEYSTORE);
            String keyStoreType = getProperty(PROPERTY_TLS_KEYSTORE_TYPE, DEFAULT_TLS_KEYSTORE_TYPE);
            File keyStoreFile = resolve(directory, store, keyStoreFilename);

            KeyManager[] keyManagers = null;
            if (keyStoreFile.exists())
            {
                KeyStore keyStore = KeyStore.getInstance(keyStoreType);
                keyStore.load(new FileInputStream(keyStoreFile), keyStorePassword.toCharArray());
                KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(
                        config.keyManagerAlgorithm());
                keyManagerFactory.init(keyStore, keyStorePassword.toCharArray());
                keyManagers = keyManagerFactory.getKeyManagers();
            }

            String trustStorePassword = getProperty(PROPERTY_TLS_TRUSTSTORE_PASSWORD, DEFAULT_TLS_TRUSTSTORE_PASSWORD);
            String trustStoreFilename = System.getProperty(PROPERTY_TLS_TRUSTSTORE, DEFAULT_TLS_TRUSTSTORE);
            String trustStoreType = System.getProperty(PROPERTY_TLS_TRUSTSTORE_TYPE, DEFAULT_TLS_TRUSTSTORE_TYPE);
            File trustStoreFile = resolve(directory, store, trustStoreFilename);

            TrustManager[] trustManagers = null;
            if (trustStoreFile.exists())
            {
                trustStoreExists = true;
                KeyStore trustStore = KeyStore.getInstance(trustStoreType);
                trustStore.load(new FileInputStream(trustStoreFile), trustStorePassword.toCharArray());
                // TODO: TLS Alert Record, code 112 / scope trustStore to match routes?
                TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(
                        TrustManagerFactory.getDefaultAlgorithm());
                trustManagerFactory.init(trustStore);
                trustManagers = trustManagerFactory.getTrustManagers();

                if (storeIndex == -1)
                {
                    // cannot fit in 1 byte
                    return null;
                }

                for (String alias : Collections.list(trustStore.aliases()))
                {
                    if (trustStore.isCertificateEntry(alias))
                    {
                        Certificate certificate = trustStore.getCertificate(alias);
                        String dn = ((X509Certificate) certificate).getSubjectX500Principal().getName();
                        caDnames.add(dn);
                    }
                }
            }

            context = SSLContext.getInstance("TLS");
            context.init(keyManagers, trustManagers, new SecureRandom());
        }
        catch (Exception ex)
        {
            LangUtil.rethrowUnchecked(ex);
        }

        storeInfo = new TlsStoreInfo(store, storeIndex, context, trustStoreExists, caDnames);
        storeInfos[storeIndex] = storeInfo;
        return storeInfo;
    }

    private static File resolve(
        Path directory,
        String store,
        String storeFilename)
    {
        return store == null
                ? directory.resolve("tls").resolve(storeFilename).toFile()
                : directory.resolve("tls").resolve("stores").resolve(store).resolve(storeFilename).toFile();
    }

    private TlsStoreInfo findStore(String store)
    {
        int storeIndex = Math.abs(store == null ? 1 : store.hashCode());
        for (int i = 0; i < storeInfos.length; i++)
        {
            storeIndex = (storeIndex + i) % storeInfos.length;
            TlsStoreInfo storeInfo = storeInfos[storeIndex];
            if (storeInfo != null && Objects.equals(storeInfo.store, store))
            {
                return storeInfo;
            }
        }

        return null;
    }

    // @return -1 if there is no slot for the given store
    private int nextIndex(String store)
    {
        int storeIndex = Math.abs(store == null ? 1 : store.hashCode());
        for (int i = 0; i < storeInfos.length; i++)
        {
            storeIndex = (storeIndex + i) % storeInfos.length;
            if (storeIndex != 0 && storeInfos[storeIndex] == null)
            {
                return storeIndex;
            }
        }

        return -1;
    }

}
