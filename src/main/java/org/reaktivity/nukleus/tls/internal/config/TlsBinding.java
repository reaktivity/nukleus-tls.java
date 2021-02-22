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
package org.reaktivity.nukleus.tls.internal.config;

import static java.util.Collections.singletonList;
import static java.util.stream.Collectors.toList;
import static javax.net.ssl.StandardConstants.SNI_HOST_NAME;
import static org.reaktivity.nukleus.tls.internal.types.ProxyInfoType.ALPN;
import static org.reaktivity.nukleus.tls.internal.types.ProxyInfoType.AUTHORITY;

import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.List;

import javax.net.ssl.ExtendedSSLSession;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

import org.agrona.LangUtil;
import org.reaktivity.nukleus.tls.internal.types.Array32FW;
import org.reaktivity.nukleus.tls.internal.types.ProxyInfoFW;
import org.reaktivity.nukleus.tls.internal.types.stream.ProxyBeginExFW;
import org.reaktivity.reaktor.config.Binding;
import org.reaktivity.reaktor.config.Role;
import org.reaktivity.reaktor.nukleus.vault.BindingVault;

public final class TlsBinding
{
    public final long id;
    public final long vaultId;
    public final String entry;
    public final TlsOptions options;
    public final Role kind;
    public final List<TlsRoute> routes;
    public final TlsRoute exit;

    private SSLContext context;

    public TlsBinding(
        Binding binding)
    {
        this.id = binding.id;
        this.vaultId = binding.vault != null ? binding.vault.id : 0L;
        this.entry = binding.entry;
        this.kind = binding.kind;
        this.options = TlsOptions.class.cast(binding.options);
        this.routes = binding.routes.stream().map(TlsRoute::new).collect(toList());
        this.exit = binding.exit != null ? new TlsRoute(binding.exit) : null;
    }

    public void init(
        BindingVault vault,
        String keyManagerAlgorithm,
        SecureRandom random)
    {
        char[] keysPass = "generated".toCharArray();
        KeyStore keys = vault.newKeys(keysPass, options.keys);
        KeyStore trust = vault.newTrust(options.trust);

        try
        {

            KeyManager[] keyManagers = null;
            if (keys != null)
            {
                KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(keyManagerAlgorithm);
                keyManagerFactory.init(keys, keysPass);
                keyManagers = keyManagerFactory.getKeyManagers();
            }

            TrustManager[] trustManagers = null;
            if (trust != null)
            {
                TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(
                        TrustManagerFactory.getDefaultAlgorithm());
                trustManagerFactory.init(trust);
                trustManagers = trustManagerFactory.getTrustManagers();
            }

            String version = options.version != null ? options.version : "TLS";
            SSLContext context = SSLContext.getInstance(version);
            context.init(keyManagers, trustManagers, random);

            this.context = context;
        }
        catch (Exception ex)
        {
            LangUtil.rethrowUnchecked(ex);
        }
    }

    public TlsRoute resolve(
        long authorization,
        ProxyBeginExFW beginEx)
    {
        Array32FW<ProxyInfoFW> infos = beginEx != null ? beginEx.infos() : null;
        ProxyInfoFW authorityInfo = infos != null ? infos.matchFirst(a -> a.kind() == AUTHORITY) : null;
        ProxyInfoFW alpnInfo = infos != null ? infos.matchFirst(a -> a.kind() == ALPN) : null;
        String authority = authorityInfo != null ? authorityInfo.authority().asString() : null;
        String alpn = alpnInfo != null ? alpnInfo.alpn().asString() : null;

        return resolve(authorization, authority, alpn);
    }

    public TlsRoute resolve(
        long authorization,
        String hostname,
        String alpn)
    {
        TlsRoute resolved = null;

        for (TlsRoute route : routes)
        {
            if (route.when.stream().anyMatch(m -> m.matches(hostname, alpn)))
            {
                resolved = route;
                break;
            }
        }

        if (resolved == null)
        {
            resolved = exit;
        }

        return resolved;
    }

    public SSLEngine newClientEngine(
        ProxyBeginExFW beginEx)
    {
        SSLEngine engine = null;

        if (context != null)
        {
            engine = context.createSSLEngine();
            engine.setUseClientMode(true);

            List<String> sni = options.sni;
            if (sni == null && beginEx != null)
            {
                ProxyInfoFW info = beginEx.infos().matchFirst(a -> a.kind() == AUTHORITY);

                // TODO: support multiple authority info
                if (info != null)
                {
                    sni = singletonList(info.authority().asString());
                }
            }

            List<String> alpn = options.alpn;
            if (alpn == null && beginEx != null)
            {
                ProxyInfoFW info = beginEx.infos().matchFirst(a -> a.kind() == ALPN);

                // TODO: support multiple alpn info
                if (info != null)
                {
                    alpn = singletonList(info.alpn().asString());
                }
            }

            final SSLParameters parameters = engine.getSSLParameters();
            parameters.setEndpointIdentificationAlgorithm("HTTPS");

            if (sni != null)
            {
                List<SNIServerName> serverNames = sni.stream()
                        .map(SNIHostName::new)
                        .collect(toList());
                parameters.setServerNames(serverNames);
            }

            if (alpn != null)
            {
                List<String> alpnNonNull = alpn.stream()
                    .filter(s -> s != null)
                    .collect(toList());
                parameters.setApplicationProtocols(alpnNonNull.toArray(new String[alpnNonNull.size()]));
            }

            engine.setSSLParameters(parameters);
        }

        return engine;
    }

    public SSLEngine newServerEngine()
    {
        SSLEngine engine = null;

        if (context != null)
        {
            engine = context.createSSLEngine();
            engine.setUseClientMode(false);

            TlsMutual mutual = options != null ? options.mutual : null;
            if (mutual != null)
            {
                switch (mutual)
                {
                case WANTED:
                    engine.setWantClientAuth(true);
                    break;
                case NEEDED:
                    engine.setNeedClientAuth(true);
                    break;
                }
            }
            else
            {
                engine.setWantClientAuth(false);
            }

            engine.setHandshakeApplicationProtocolSelector(this::selectAlpn);
        }

        return engine;
    }

    private String selectAlpn(
        SSLEngine engine,
        List<String> protocols)
    {
        List<SNIServerName> serverNames = null;

        SSLSession session = engine.getHandshakeSession();
        if (session instanceof ExtendedSSLSession)
        {
            ExtendedSSLSession sessionEx = (ExtendedSSLSession) session;
            serverNames = sessionEx.getRequestedServerNames();
        }

        List<String> sni = options != null ? options.sni : null;
        List<String> alpn = options != null ? options.alpn : null;

        String selected = null;

        if (serverNames != null)
        {
            for (SNIServerName serverName : serverNames)
            {
                if (serverName.getType() == SNI_HOST_NAME)
                {
                    SNIHostName hostName = (SNIHostName) serverName;
                    String authority = hostName.getAsciiName();

                    if (sni != null && !sni.contains(authority))
                    {
                        continue;
                    }

                    for (TlsRoute route : routes)
                    {
                        for (String protocol : protocols)
                        {
                            if (alpn != null && !alpn.contains(protocol))
                            {
                                continue;
                            }

                            if (route.when.stream().anyMatch(m -> m.matches(authority, protocol)))
                            {
                                selected = protocol;
                                break;
                            }
                        }
                    }
                }
            }
        }

        if (selected == null && exit != null)
        {
            selected = "";
        }

        return selected;
    }
}
