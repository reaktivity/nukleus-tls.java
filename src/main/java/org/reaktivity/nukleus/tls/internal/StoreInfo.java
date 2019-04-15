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

import javax.net.ssl.SSLContext;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

public class StoreInfo
{
    private static final long MAX_AUTHORIZATION = 1L << 56;
    private final String store;
    public final SSLContext context;
    private final Map<String, Long> authorizationMap;   // dn -> authorization (1st byte store index + 7 bytes for dn index)
    private final Set<String> caDnames;
    public final boolean supportsClientAuth;
    private final int storeIndex;

    int routeCount;
    private long authorization = 1L;

    StoreInfo(
        String store,
        int storeIndex,
        SSLContext context,
        boolean supportsClientAuth,
        Set<String> caDnames)
    {
        this.store = store;
        this.storeIndex = storeIndex;
        this.context = context;
        this.caDnames = caDnames;
        this.authorizationMap = new LinkedHashMap<>();
        this.supportsClientAuth = supportsClientAuth;
    }

    public long authorization(String dname)
    {
        Long auth = null;

        if (caDnames.contains(dname))
        {
            auth = authorizationMap.computeIfAbsent(dname, dn ->
            {
                //  0           7                                63
                // +-------------+---------------------------------+
                // | store index |          ca bit                 |
                // +-------------+---------------------------------+

                if (authorization < MAX_AUTHORIZATION)
                {
                    long routeAuthorization = ((long) storeIndex << 56) | authorization;
                    authorization *= 2;
                    return routeAuthorization;
                }
                else
                {
                    // more than 56 ca certs, cannot fit in 7 bytes
                    return null;
                }
            });
        }
        return auth == null ? 0L : auth;
    }

    public boolean unresolve(long authorization)
    {
        return authorizationMap.entrySet().removeIf(e -> (e.getValue() == authorization));
    }

    @Override
    public String toString()
    {
        return String.format("store=%s authorization=%s", store, authorization);
    }
}
