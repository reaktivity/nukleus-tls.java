/**
 * Copyright 2016-2018 The Reaktivity Project
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
import java.util.Map;

public class StoreInfo
{
    private final String store;
    public final SSLContext context;
    public final Map<String, Long> authorization;       // dn -> authorization (1st byte store index + 5 bytes for dn index)
    int routeCount;

    StoreInfo(String store, SSLContext context, Map<String, Long> authorization)
    {
        this.store = store;
        this.context = context;
        this.authorization = authorization;
    }
}
