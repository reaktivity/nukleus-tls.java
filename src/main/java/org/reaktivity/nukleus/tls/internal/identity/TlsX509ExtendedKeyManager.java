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
package org.reaktivity.nukleus.tls.internal.identity;

import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSession;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509KeyManager;
import javax.security.auth.x500.X500Principal;

public final class TlsX509ExtendedKeyManager extends X509ExtendedKeyManager implements X509KeyManager
{
    public static final String DISTINGUISHED_NAME_KEY = "distinguished.name";

    private final X509ExtendedKeyManager delegate;

    public TlsX509ExtendedKeyManager(
        X509ExtendedKeyManager delegate)
    {
        this.delegate = delegate;
    }

    @Override
    public String[] getClientAliases(
        String keyType,
        Principal[] issuers)
    {
        return delegate.getClientAliases(keyType, issuers);
    }

    @Override
    public String chooseClientAlias(
        String[] keyType,
        Principal[] issuers,
        Socket socket)
    {
        return delegate.chooseClientAlias(keyType, issuers, socket);
    }

    @Override
    public String[] getServerAliases(
        String keyType,
        Principal[] issuers)
    {
        return delegate.getServerAliases(keyType, issuers);
    }

    @Override
    public String chooseServerAlias(
        String keyType,
        Principal[] issuers,
        Socket socket)
    {
        return delegate.chooseServerAlias(keyType, issuers, socket);
    }

    @Override
    public String chooseEngineClientAlias(
        String[] keyTypes,
        Principal[] issuers,
        SSLEngine engine)
    {
        String alias = null;

        SSLSession session = engine.getSession();
        String subjectDN = (String) session.getValue(DISTINGUISHED_NAME_KEY);

        if (subjectDN == null)
        {
            alias = delegate.chooseEngineClientAlias(keyTypes, issuers, engine);
        }
        else if (keyTypes != null)
        {
            outer:
            for (String keyType : keyTypes)
            {
                String[] candidates = delegate.getClientAliases(keyType, issuers);
                if (candidates != null)
                {
                    for (String candidate : candidates)
                    {
                        X509Certificate[] chain = delegate.getCertificateChain(candidate);
                        if (chain != null)
                        {
                            X500Principal subject = chain[0].getSubjectX500Principal();

                            if (subject != null && subjectDN.equals(subject.getName()))
                            {
                                alias = candidate;
                                break outer;
                            }
                        }
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
        return delegate.chooseEngineServerAlias(keyType, issuers, engine);
    }

    @Override
    public X509Certificate[] getCertificateChain(
        String alias)
    {
        return delegate.getCertificateChain(alias);
    }

    @Override
    public PrivateKey getPrivateKey(
        String alias)
    {
        return delegate.getPrivateKey(alias);
    }
}
