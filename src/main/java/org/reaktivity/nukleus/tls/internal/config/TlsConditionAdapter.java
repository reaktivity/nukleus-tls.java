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

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import javax.json.bind.adapter.JsonbAdapter;

import org.reaktivity.nukleus.tls.internal.TlsNukleus;
import org.reaktivity.reaktor.config.Condition;
import org.reaktivity.reaktor.config.ConditionAdapterSpi;

public final class TlsConditionAdapter implements ConditionAdapterSpi, JsonbAdapter<Condition, JsonObject>
{
    private static final String AUTHORITY_NAME = "authority";
    private static final String ALPN_NAME = "alpn";

    @Override
    public String type()
    {
        return TlsNukleus.NAME;
    }

    @Override
    public JsonObject adaptToJson(
        Condition condition)
    {
        TlsCondition tlsCondition = (TlsCondition) condition;

        JsonObjectBuilder object = Json.createObjectBuilder();

        if (tlsCondition.authority != null)
        {
            object.add(AUTHORITY_NAME, tlsCondition.authority);
        }

        if (tlsCondition.alpn != null)
        {
            object.add(ALPN_NAME, tlsCondition.alpn);
        }

        return object.build();
    }

    @Override
    public Condition adaptFromJson(
        JsonObject object)
    {
        String authority = object.containsKey(AUTHORITY_NAME)
                ? object.getString(AUTHORITY_NAME)
                : null;
        String alpn = object.containsKey(ALPN_NAME)
                ? object.getString(ALPN_NAME)
                : null;

        return new TlsCondition(authority, alpn);
    }
}
