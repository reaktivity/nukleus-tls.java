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

import static java.util.stream.Collectors.toList;

import java.time.Duration;
import java.util.List;

import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonArrayBuilder;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import javax.json.JsonString;
import javax.json.JsonValue;
import javax.json.bind.adapter.JsonbAdapter;

public final class TlsCertificateAdapter implements JsonbAdapter<TlsCertificate, JsonObject>
{
    private static final String VALIDITY_NAME = "validity";
    private static final String SIGNERS_NAME = "signers";

    @Override
    public JsonObject adaptToJson(
        TlsCertificate certificate)
    {
        JsonObjectBuilder object = Json.createObjectBuilder();

        if (certificate.validity != null)
        {
            object.add(VALIDITY_NAME, certificate.validity.toDays());
        }

        if (certificate.signers != null)
        {
            JsonArrayBuilder signers = Json.createArrayBuilder();
            certificate.signers.forEach(signers::add);
            object.add(SIGNERS_NAME, signers);
        }

        return object.build();
    }

    @Override
    public TlsCertificate adaptFromJson(
        JsonObject object)
    {
        Duration validity = object.containsKey(VALIDITY_NAME)
                ? Duration.ofDays(object.getInt(VALIDITY_NAME))
                : null;
        List<String> signers = object.containsKey(SIGNERS_NAME)
                ? asListString(object.getJsonArray(SIGNERS_NAME))
                : null;

        return new TlsCertificate(validity, signers);
    }

    private static List<String> asListString(
        JsonArray array)
    {
        return array.stream()
            .map(TlsCertificateAdapter::asString)
            .collect(toList());
    }

    private static String asString(
        JsonValue value)
    {
        switch (value.getValueType())
        {
        case STRING:
            return ((JsonString) value).getString();
        case NULL:
            return null;
        default:
            throw new IllegalArgumentException("Unexpected type: " + value.getValueType());
        }
    }
}
