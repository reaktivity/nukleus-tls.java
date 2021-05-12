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
import static javax.net.ssl.StandardConstants.SNI_HOST_NAME;

import java.net.Socket;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

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
import org.reaktivity.reaktor.nukleus.vault.CertificateRequest;

public final class TlsX509ExtendedKeyManager extends X509ExtendedKeyManager implements X509KeyManager
{
    public static final String COMMON_NAME_KEY = "common.name";

    private final BindingVault vault;
    private final TlsCertificate certificate;
    private final Map<String, KeyStore.PrivateKeyEntry> cache;

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
        return cache.keySet().toArray(String[]::new);
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
        String name = (String) session.getValue(COMMON_NAME_KEY);

        if (name != null)
        {
            loop:
            for (String signer : certificate.signers)
            {
                for (String keyType : keyTypes)
                {
                    String candidate = String.format("%s/%s", name, keyType);

                    if (!cache.containsKey(candidate))
                    {
                        String dname = String.format("CN=%s", name);
                        char[] passphrase = "generated".toCharArray();
                        PrivateKeyEntry entry = supplyKeyEntry(signer, passphrase, keyType, dname, null);

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
                    for (String signer : certificate.signers)
                    {
                        String dname = String.format("CN=%s", asciiName);
                        char[] passphrase = "generated".toCharArray();
                        KeyStore.PrivateKeyEntry entry = supplyKeyEntry(signer, passphrase, keyType, dname, asciiName);

                        if (entry != null)
                        {
                            cache.put(candidate, entry);
                            break;
                        }
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
        KeyStore.PrivateKeyEntry entry = cache.get(alias);

        X509Certificate[] x509s = null;

        if (entry != null)
        {
            x509s = Arrays.asList(entry.getCertificateChain())
                .stream()
                .filter(X509Certificate.class::isInstance)
                .collect(Collectors.toList())
                .toArray(X509Certificate[]::new);
        }

        return x509s;
    }

    @Override
    public PrivateKey getPrivateKey(
        String alias)
    {
        KeyStore.PrivateKeyEntry entry = cache.get(alias);
        return entry != null ? entry.getPrivateKey() : null;
    }

    private KeyStore.PrivateKeyEntry supplyKeyEntry(
        String signerAlias,
        char[] passphrase,
        String keyType,
        String dname,
        String serverName)
    {
        KeyStore.PrivateKeyEntry entry = null;

        String signedRef = vault.signedRef(signerAlias, dname, keyType);

        if (signedRef != null)
        {
            entry = vault.key(signedRef);
        }
        else
        {
            KeyPair pair = supplyGenerator(keyType).generateKeyPair();
            CertificateRequest request = new CertificateRequest();
            request.publicKey = pair.getPublic();
            request.dname = dname;
            request.notBefore = Instant.now();
            request.notAfter = request.notBefore.plus(certificate.validity);
            request.subjectNames = serverName != null ? singletonList(serverName) : null;

            X509Certificate[] chain = vault.sign(signerAlias, request);

            if (chain != null)
            {
                entry = new PrivateKeyEntry(pair.getPrivate(), chain);
            }
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
}
