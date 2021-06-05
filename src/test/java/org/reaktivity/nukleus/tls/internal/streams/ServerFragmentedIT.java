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
package org.reaktivity.nukleus.tls.internal.streams;

import static java.util.concurrent.TimeUnit.SECONDS;
import static org.junit.rules.RuleChain.outerRule;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.DisableOnDebug;
import org.junit.rules.TestRule;
import org.junit.rules.Timeout;
import org.kaazing.k3po.junit.annotation.ScriptProperty;
import org.kaazing.k3po.junit.annotation.Specification;
import org.kaazing.k3po.junit.rules.K3poRule;
import org.reaktivity.nukleus.tls.internal.TlsConfigurationTest;
import org.reaktivity.reaktor.test.ReaktorRule;
import org.reaktivity.reaktor.test.annotation.Configuration;
import org.reaktivity.reaktor.test.annotation.Configure;

public class ServerFragmentedIT
{
    private final K3poRule k3po = new K3poRule()
            .addScriptRoot("net", "org/reaktivity/specification/nukleus/tls/streams/network")
            .addScriptRoot("app", "org/reaktivity/specification/nukleus/tls/streams/application");

    private final TestRule timeout = new DisableOnDebug(new Timeout(10, SECONDS));

    private final ReaktorRule reaktor = new ReaktorRule()
            .directory("target/nukleus-itests")
            .commandBufferCapacity(1024)
            .responseBufferCapacity(1024)
            .counterValuesBufferCapacity(8192)
            .configurationRoot("org/reaktivity/specification/nukleus/tls/config")
            .external("app#0")
            .clean();

    @Rule
    public final TestRule chain = outerRule(reaktor).around(k3po).around(timeout);

    @Test
    @Configuration("server.json")
    @Specification({
        "${net}/connection.established/client",
        "${app}/connection.established/server" })
    @Configure(name = TlsConfigurationTest.TLS_HANDSHAKE_WINDOW_BYTES_NAME, value = "8")
    public void shouldEstablishConnectionWithLimitedHandshakeWindow() throws Exception
    {
        k3po.finish();
    }

    @Test
    @Configuration("server.json")
    @Specification({
        "${net}/echo.payload.length.100k/client",
        "${app}/echo.payload.length.100k/server"})
    @ScriptProperty({
        "serverWindow 8192"})
    public void shouldEchoPayloadLength100kWithLimitedPayloadWindow() throws Exception
    {
        k3po.finish();
    }
}
