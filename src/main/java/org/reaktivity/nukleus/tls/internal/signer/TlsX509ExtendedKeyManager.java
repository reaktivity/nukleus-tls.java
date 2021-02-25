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
package org.reaktivity.nukleus.tls.internal.signer;

import static java.util.Collections.singletonList;
import static java.util.Collections.unmodifiableMap;
import static javax.net.ssl.StandardConstants.SNI_HOST_NAME;

import java.net.Socket;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import javax.net.ssl.ExtendedSSLSession;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSession;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509KeyManager;

import org.agrona.LangUtil;
import org.reaktivity.nukleus.tls.internal.config.TlsCertificate;
import org.reaktivity.reaktor.nukleus.vault.BindingVault;

public final class TlsX509ExtendedKeyManager extends X509ExtendedKeyManager implements X509KeyManager
{
    public static final String DISTINGUISHED_NAME_KEY = "distinguished.name";

    private static final Map<String, String> SIG_TYPES_BY_KEY_TYPES;

    static
    {
        Map<String, String> sigAlgsByKeyAlgs = new TreeMap<>(String::compareToIgnoreCase);
        sigAlgsByKeyAlgs.put("EC", "SHA256withECDSA");
        sigAlgsByKeyAlgs.put("RSA", "SHA256WithRSA");
        sigAlgsByKeyAlgs.put("DSA", "SHA1WithDSA");
        SIG_TYPES_BY_KEY_TYPES = unmodifiableMap(sigAlgsByKeyAlgs);
    }

    private final BindingVault vault;
    private final TlsCertificate certificate;
    private final Map<String, TlsCacheEntry> cache;

    public TlsX509ExtendedKeyManager(
        BindingVault vault,
        TlsCertificate certificate)
    {
        this.vault = vault;
        this.certificate = certificate;
        this.cache = new HashMap<>();
    }

    @Override
    public String[] getClientAliases(
        String keyType,
        Principal[] issuers)
    {
        return null;
    }

    @Override
    public String chooseClientAlias(
        String[] keyType,
        Principal[] issuers,
        Socket socket)
    {
        return null;
    }

    @Override
    public String[] getServerAliases(
        String keyType,
        Principal[] issuers)
    {
        return cache.keySet().toArray(String[]::new);
    }

    @Override
    public String chooseServerAlias(
        String keyType,
        Principal[] issuers,
        Socket socket)
    {
        return null;
    }

    @Override
    public String chooseEngineClientAlias(
        String[] keyTypes,
        Principal[] issuers,
        SSLEngine engine)
    {
        String alias = null;

        SSLSession session = engine.getSession();
        String dname = (String) session.getValue(DISTINGUISHED_NAME_KEY);

        if (dname != null)
        {
            loop:
            for (String keyType : keyTypes)
            {
                String candidate = String.format("%s/%s", dname, keyType);

                if (!cache.containsKey(candidate))
                {
                    TlsCacheEntry entry = cacheEntry(keyType, dname, null);

                    if (entry != null)
                    {
                        cache.put(candidate, entry);
                    }
                }

                if (cache.containsKey(candidate))
                {
                    alias = candidate;
                    break loop;
                }

            }
        }

        return alias;
    }

    @Override
    public String chooseEngineServerAlias(
        String keyType,
        Principal[] issuers,
        SSLEngine engine)
    {
        String alias = null;

        ExtendedSSLSession session = (ExtendedSSLSession) engine.getHandshakeSession();

        loop:
        for (SNIServerName serverName : session.getRequestedServerNames())
        {
            if (serverName.getType() == SNI_HOST_NAME)
            {
                SNIHostName hostName = (SNIHostName) serverName;
                String asciiName = hostName.getAsciiName();
                String candidate = String.format("%s/%s", asciiName, keyType);

                if (!cache.containsKey(candidate))
                {
                    String dname = String.format("CN=%s", asciiName);
                    TlsCacheEntry entry = cacheEntry(keyType, dname, asciiName);

                    if (entry != null)
                    {
                        cache.put(candidate, entry);
                    }
                }

                if (cache.containsKey(candidate))
                {
                    alias = candidate;
                    break loop;
                }
            }
        }

        return alias;
    }

    @Override
    public X509Certificate[] getCertificateChain(
        String alias)
    {
        TlsCacheEntry entry = cache.get(alias);
        return entry != null ? entry.chain : null;
    }

    @Override
    public PrivateKey getPrivateKey(
        String alias)
    {
        TlsCacheEntry entry = cache.get(alias);
        return entry != null ? entry.key : null;
    }

    private TlsCacheEntry cacheEntry(
        String keyType,
        String dname,
        String serverName)
    {
        String sigType = SIG_TYPES_BY_KEY_TYPES.get(keyType);
        KeyPairGenerator generator = supplyGenerator(keyType);
        KeyPair pair = generator.generateKeyPair();

        X509Certificate[] chain = null;
        if (sigType != null)
        {
            Instant notBefore = Instant.now().minus(Duration.ofSeconds(5));
            Instant notAfter = notBefore.plus(certificate.validity);
            String signer = certificate.signers != null && !certificate.signers.isEmpty() ? certificate.signers.get(0) : null;
            List<String> subjects = certificate.alternatives != null
                    ? certificate.alternatives
                    : serverName != null ? singletonList(serverName) : null;

            chain = vault.sign(signer, pair.getPublic(), dname, notBefore, notAfter, subjects, sigType);
        }

        TlsCacheEntry entry = null;
        if (chain != null)
        {
            entry = new TlsCacheEntry(chain, pair.getPrivate());
        }

        return entry;
    }

    private KeyPairGenerator supplyGenerator(
        String keyType)
    {
        KeyPairGenerator generator = null;
        try
        {
            generator = KeyPairGenerator.getInstance(keyType);
        }
        catch (NoSuchAlgorithmException ex)
        {
            LangUtil.rethrowUnchecked(ex);
        }
        return generator;
    }

    private static final class TlsCacheEntry
    {
        final X509Certificate[] chain;
        final PrivateKey key;

        private TlsCacheEntry(
            X509Certificate[] chain,
            PrivateKey key)
        {
            this.chain = chain;
            this.key = key;
        }
    }
}
