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
import static org.reaktivity.nukleus.tls.internal.TlsConfigurationTest.REAKTOR_TASK_PARALLELISM_NAME;

import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.DisableOnDebug;
import org.junit.rules.TestRule;
import org.junit.rules.Timeout;
import org.kaazing.k3po.junit.annotation.Specification;
import org.kaazing.k3po.junit.rules.K3poRule;
import org.reaktivity.nukleus.tls.internal.TlsConfigurationTest;
import org.reaktivity.reaktor.ReaktorConfiguration;
import org.reaktivity.reaktor.test.ReaktorRule;
import org.reaktivity.reaktor.test.annotation.Configuration;
import org.reaktivity.reaktor.test.annotation.Configure;

public class ServerIT
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
            .configure(ReaktorConfiguration.REAKTOR_DRAIN_ON_CLOSE, false)
            .clean();

    @Rule
    public final TestRule chain = outerRule(reaktor).around(k3po).around(timeout);

    @Test
    @Configuration("server.json")
    @Specification({
        "${net}/connection.established/client",
        "${app}/connection.established/server" })
    public void shouldEstablishConnection() throws Exception
    {
        k3po.finish();
    }

    @Test
    @Configuration("server.alpn.json")
    @Specification({
        "${net}/connection.established.with.alpn/client",
        "${app}/connection.established.with.alpn/server" })
    public void shouldNegotiateWithAlpn() throws Exception
    {
        k3po.finish();
    }

    @Test
    @Configuration("server.json")
    @Specification({
        "${net}/connection.established.with.alpn/client",
        "${app}/connection.established/server" })
    public void shouldNotNegotiateAlpnWithDefaultRoute() throws Exception
    {
        k3po.finish();
    }

    @Ignore("https://github.com/k3po/k3po/issues/454 - Support connect aborted")
    @Test
    @Configuration("server.alpn.json")
    @Specification({
        "${net}/connection.not.established.with.wrong.alpn/client",
        "${app}/connection.established/server" })
    public void shouldNotNegotiateWithAlpnAsProtocolMismatch() throws Exception
    {
        k3po.finish();
    }

    @Ignore("https://github.com/k3po/k3po/issues/454 - Support connect aborted")
    @Test
    @Configuration("server.json")
    @Specification({
        "${net}/connection.established/client" })
    public void shouldNegotiateWithNoAlpnButRouteMismatch() throws Exception
    {
        k3po.finish();
    }

    @Test
    @Configuration("server.alpn.default.json")
    @Specification({
        "${net}/connection.established.with.alpn/client",
        "${app}/connection.established.with.alpn/server" })
    public void shouldNegotiateAlpnWithAlpnAndDefaultRoutes() throws Exception
    {
        k3po.finish();
    }

    @Test
    @Configuration("server.alpn.json")
    @Specification({
        "${net}/connection.established.with.alpn/client",
        "${app}/connection.established.with.alpn/server" })
    public void shouldNegotiateAlpnWithAlpnAndNoHostname() throws Exception
    {
        k3po.finish();
    }

    @Test
    @Configuration("server.alpn.default.json")
    @Specification({
        "${net}/connection.established/client",
        "${app}/connection.established/server" })
    public void shouldNotNegotiateAlpnWithAlpnAndDefaultRoutes() throws Exception
    {
        k3po.finish();
    }

    @Test
    @Configuration("server.json")
    @Specification({
        "${net}/echo.payload.length.10k/client",
        "${app}/echo.payload.length.10k/server"})
    public void shouldEchoPayloadLength10k() throws Exception
    {
        k3po.finish();
    }

    @Test
    @Configuration("server.json")
    @Specification({
        "${net}/echo.payload.length.100k/client",
        "${app}/echo.payload.length.100k/server"})
    public void shouldEchoPayloadLength100k() throws Exception
    {
        k3po.finish();
    }

    @Test
    @Configuration("server.json")
    @Specification({
        "${net}/echo.payload.length.1000k/client",
        "${app}/echo.payload.length.1000k/server"})
    public void shouldEchoPayloadLength1000k() throws Exception
    {
        k3po.finish();
    }

    @Test
    @Configuration("server.json")
    @Specification({
        "${net}/server.sent.write.close/client",
        "${app}/server.sent.write.close/server"})
    public void shouldReceiveServerSentWriteClose() throws Exception
    {
        k3po.finish();
    }

    @Test
    @Configuration("server.json")
    @Specification({
        "${net}/client.sent.write.close.before.handshake/client"})
    public void shouldReceiveClientSentWriteCloseBeforeHandshake() throws Exception
    {
        k3po.finish();
    }

    @Test
    @Configuration("server.json")
    @Specification({
        "${net}/client.sent.write.close/client",
        "${app}/client.sent.write.close/server"})
    public void shouldReceiveClientSentWriteClose() throws Exception
    {
        k3po.finish();
    }

    @Test
    @Configuration("server.json")
    @Specification({
        "${net}/server.sent.write.abort/client",
        "${app}/server.sent.write.abort/server"})
    public void shouldReceiveServerSentWriteAbort() throws Exception
    {
        k3po.finish();
    }

    @Test
    @Configuration("server.json")
    @Specification({
        "${net}/client.sent.write.abort.before.handshake/client"})
    public void shouldReceiveClientSentWriteAbortBeforeHandshake() throws Exception
    {
        k3po.finish();
    }

    @Test
    @Configuration("server.json")
    @Specification({
        "${net}/client.sent.write.abort/client",
        "${app}/client.sent.write.abort/server"})
    @Configure(name = REAKTOR_TASK_PARALLELISM_NAME, value = "0")
    public void shouldReceiveClientSentWriteAbort() throws Exception
    {
        k3po.finish();
    }

    @Test
    @Configuration("server.json")
    @Specification({
        "${net}/server.sent.read.abort/client",
        "${app}/server.sent.read.abort/server"})
    public void shouldReceiveServerSentReadAbort() throws Exception
    {
        k3po.finish();
    }

    @Test
    @Configuration("server.json")
    @Specification({
        "${net}/client.sent.read.abort.before.handshake/client"})
    public void shouldReceiveClientSentReadAbortBeforeHandshake() throws Exception
    {
        k3po.finish();
    }

    @Test
    @Configuration("server.json")
    @Specification({
        "${net}/client.sent.read.abort/client",
        "${app}/client.sent.read.abort/server"})
    @Configure(name = REAKTOR_TASK_PARALLELISM_NAME, value = "0")
    public void shouldReceiveClientSentReadAbort() throws Exception
    {
        k3po.finish();
    }

    @Test
    @Configuration("server.json")
    @Specification({
        "${net}/client.hello.malformed/client"})
    public void shouldResetMalformedClientHello() throws Exception
    {
        k3po.finish();
    }

    @Test
    @Configuration("server.mutual.json")
    @Specification({
        "${net}/server.want.auth/client",
        "${app}/server.want.auth/server"})
    public void serverNeedClientAuth() throws Exception
    {
        k3po.finish();
    }

    @Test
    @Configuration("server.mutual.wanted.json")
    @Specification({
        "${net}/server.want.auth/client",
        "${app}/server.want.auth/server"})
    public void serverWantClientAuth() throws Exception
    {
        k3po.finish();
    }

    @Test
    @Configuration("server.json")
    @Specification({
        "${net}/server.handshake.timeout/client"})
    @Configure(name = TlsConfigurationTest.TLS_HANDSHAKE_TIMEOUT_NAME, value = "1")
    public void shouldTimeoutHandshake() throws Exception
    {
        k3po.finish();
    }
}
