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
import static org.reaktivity.nukleus.tls.internal.config.TlsMutual.NEEDED;

import java.util.List;

import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonArrayBuilder;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import javax.json.JsonString;
import javax.json.JsonValue;
import javax.json.bind.adapter.JsonbAdapter;

import org.reaktivity.nukleus.tls.internal.TlsNukleus;
import org.reaktivity.reaktor.config.Options;
import org.reaktivity.reaktor.config.OptionsAdapterSpi;

public final class TlsOptionsAdapter implements OptionsAdapterSpi, JsonbAdapter<Options, JsonObject>
{
    private static final String VERSION_NAME = "version";
    private static final String KEYS_NAME = "keys";
    private static final String TRUST_NAME = "trust";
    private static final String SNI_NAME = "sni";
    private static final String ALPN_NAME = "alpn";
    private static final String MUTUAL_NAME = "mutual";
    private static final String CERTIFICATE_NAME = "certificate";

    private final TlsCertificateAdapter certificate = new TlsCertificateAdapter();

    @Override
    public String type()
    {
        return TlsNukleus.NAME;
    }

    @Override
    public JsonObject adaptToJson(
        Options options)
    {
        TlsOptions tlsOptions = (TlsOptions) options;

        JsonObjectBuilder object = Json.createObjectBuilder();

        if (tlsOptions.version != null)
        {
            object.add(VERSION_NAME, tlsOptions.version);
        }

        if (tlsOptions.keys != null)
        {
            JsonArrayBuilder keys = Json.createArrayBuilder();
            tlsOptions.keys.forEach(keys::add);
            object.add(KEYS_NAME, keys);
        }

        if (tlsOptions.trust != null)
        {
            JsonArrayBuilder trust = Json.createArrayBuilder();
            tlsOptions.trust.forEach(trust::add);
            object.add(TRUST_NAME, trust);
        }

        if (tlsOptions.sni != null)
        {
            JsonArrayBuilder sni = Json.createArrayBuilder();
            tlsOptions.sni.forEach(sni::add);
            object.add(SNI_NAME, sni);
        }

        if (tlsOptions.alpn != null)
        {
            JsonArrayBuilder alpn = Json.createArrayBuilder();
            tlsOptions.alpn.forEach(alpn::add);
            object.add(ALPN_NAME, alpn);
        }

        if (tlsOptions.mutual != null &&
            (tlsOptions.mutual != NEEDED || tlsOptions.trust != null))
        {
            String mutual = tlsOptions.mutual.name().toLowerCase();
            object.add(MUTUAL_NAME, mutual);
        }

        if (tlsOptions.certificate != null)
        {
            object.add(CERTIFICATE_NAME, certificate.adaptToJson(tlsOptions.certificate));
        }

        return object.build();
    }

    @Override
    public Options adaptFromJson(
        JsonObject object)
    {
        String version = object.containsKey(VERSION_NAME)
                ? object.getString(VERSION_NAME)
                : null;
        List<String> keys = object.containsKey(KEYS_NAME)
                ? asListString(object.getJsonArray(KEYS_NAME))
                : null;
        List<String> trust = object.containsKey(TRUST_NAME)
                ? asListString(object.getJsonArray(TRUST_NAME))
                : null;
        List<String> sni = object.containsKey(SNI_NAME)
                ? asListString(object.getJsonArray(SNI_NAME))
                : null;
        List<String> alpn = object.containsKey(ALPN_NAME)
                ? asListString(object.getJsonArray(ALPN_NAME))
                : null;
        TlsMutual mutual = object.containsKey(MUTUAL_NAME)
                ? TlsMutual.valueOf(object.getString(MUTUAL_NAME).toUpperCase())
                : trust != null ? NEEDED : null;
        TlsCertificate cert = object.containsKey(CERTIFICATE_NAME)
                ? certificate.adaptFromJson(object.getJsonObject(CERTIFICATE_NAME))
                : null;

        return new TlsOptions(version, keys, trust, sni, alpn, mutual, cert);
    }

    private static List<String> asListString(
        JsonArray array)
    {
        return array.stream()
            .map(TlsOptionsAdapter::asString)
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
