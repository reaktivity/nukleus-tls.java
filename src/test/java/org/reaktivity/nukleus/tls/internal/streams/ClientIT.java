/**
 * Copyright 2016-2020 The Reaktivity Project
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
import static org.reaktivity.nukleus.tls.internal.TlsConfiguration.TLS_HANDSHAKE_TIMEOUT_NAME;
import static org.reaktivity.reaktor.test.ReaktorRule.EXTERNAL_AFFINITY_MASK;

import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.DisableOnDebug;
import org.junit.rules.TestRule;
import org.junit.rules.Timeout;
import org.kaazing.k3po.junit.annotation.ScriptProperty;
import org.kaazing.k3po.junit.annotation.Specification;
import org.kaazing.k3po.junit.rules.K3poRule;
import org.reaktivity.reaktor.test.ReaktorRule;
import org.reaktivity.reaktor.test.annotation.Configure;

public class ClientIT
{
    private final K3poRule k3po = new K3poRule()
            .addScriptRoot("route", "org/reaktivity/specification/nukleus/tls/control/route")
            .addScriptRoot("client", "org/reaktivity/specification/nukleus/tls/streams/application")
            .addScriptRoot("server", "org/reaktivity/specification/nukleus/tls/streams/network");

    private final TestRule timeout = new DisableOnDebug(new Timeout(10, SECONDS));

    private final ReaktorRule reaktor = new ReaktorRule()
            .directory("target/nukleus-itests")
            .commandBufferCapacity(1024)
            .responseBufferCapacity(1024)
            .counterValuesBufferCapacity(8192)
            .nukleus("tls"::equals)
            .affinityMask("net#0", EXTERNAL_AFFINITY_MASK)
            .clean();

    @Rule
    public final TestRule chain = outerRule(reaktor).around(k3po).around(timeout);

    @Test
    @Specification({
        "${route}/client/controller",
        "${client}/connection.established/client",
        "${server}/connection.established/server" })
    public void shouldEstablishConnection() throws Exception
    {
        k3po.finish();
    }

    @Test
    @Specification({
        "${route}/client.default.store/controller",
        "${client}/connection.established/client",
        "${server}/connection.established/server" })
    public void shouldEstablishConnectionDefaultStore() throws Exception
    {
        k3po.finish();
    }

    @Test
    @Specification({
        "${route}/client.default.store/controller",
        "${client}/client.auth/client",
        "${server}/client.auth/server" })
    public void shouldEstablishConnectionWithClientAuth() throws Exception
    {
        k3po.finish();
    }

    @Test
    @Specification({
        "${route}/client/controller",
        "${client}/connection.established.with.extension.data/client",
        "${server}/connection.established.with.extension.data/server" })
     public void shouldEstablishConnectionWithExtensionData() throws Exception
    {
        k3po.finish();
    }

    @Test
    @Specification({
        "${route}/client.alpn/controller",
        "${client}/connection.established.with.alpn/client",
        "${server}/connection.established.with.alpn/server" })
    public void shouldEstablishConnectionWithAlpn() throws Exception
    {
        k3po.finish();
    }

    @Test
    @Specification({
        "${route}/client/controller",
        "${client}/connection.established.no.hostname.no.alpn/client",
        "${server}/connection.established.no.hostname.no.alpn/server" })
    public void shouldEstablishConnectionWithNoHostnameNoAlpn() throws Exception
    {
        k3po.finish();
    }

    @Test
    @Specification({
        "${route}/client/controller",
        "${client}/connection.established.with.alpn/client",
        "${server}/connection.established/server" })
    public void shouldNegotiateWithNoALPNAsNoProtocolRouteExists() throws Exception
    {
        k3po.finish();
    }

    @Ignore("https://github.com/k3po/k3po/issues/454 - Support connect aborted")
    @Test
    @Specification({
        "${route}/client.alpn/controller",
        "${client}/connection.established.with.alpn/client",
        "${server}/connection.established/server" })
    public void shouldFailNoAlpnNoDefaultRoute() throws Exception
    {
        k3po.finish();
    }

    @Test
    @Specification({
        "${route}/client.alpn.default/controller",
        "${client}/connection.established.with.alpn/client",
        "${server}/connection.established/server" })
    public void shouldSucceedNoALPNDefaultRoute() throws Exception
    {
        k3po.finish();
    }

    @Test
    @Specification({
        "${route}/client/controller",
        "${client}/connection.established/client",
        "${server}/connection.established/server" })
    @ScriptProperty({
        "authorization 0x0001_000000000000L"})
    public void shouldEstablishConnectionWithAuthorization() throws Exception
    {
        k3po.finish();
    }

    @Test
    @Specification({
        "${route}/client/controller",
        "${client}/echo.payload.length.10k/client",
        "${server}/echo.payload.length.10k/server"})
    public void shouldEchoPayloadLength10k() throws Exception
    {
        k3po.finish();
    }

    @Test
    @Specification({
        "${route}/client/controller",
        "${client}/echo.payload.length.10k/client",
        "${server}/echo.payload.length.10k/server"})
    public void shouldEchoPayloadLength10kWithAuthorization() throws Exception
    {
        k3po.finish();
    }

    @Test
    @Specification({
        "${route}/client/controller",
        "${client}/echo.payload.length.100k/client",
        "${server}/echo.payload.length.100k/server"})
    public void shouldEchoPayloadLength100k() throws Exception
    {
        k3po.finish();
    }

    @Test
    @Specification({
        "${route}/client/controller",
        "${client}/echo.payload.length.1000k/client",
        "${server}/echo.payload.length.1000k/server"})
    public void shouldEchoPayloadLength1000k() throws Exception
    {
        k3po.finish();
    }

    @Ignore("JDK 11")
    @Test
    @Specification({
        "${route}/client/controller",
        "${client}/server.sent.write.close/client",
        "${server}/server.sent.write.close/server"})
    public void shouldReceiveServerSentWriteClose() throws Exception
    {
        k3po.finish();
    }

    @Test
    @Specification({
        "${route}/client/controller",
        "${client}/server.sent.write.close.before.handshake/client",
        "${server}/server.sent.write.close.before.handshake/server"})
    public void shouldRejectServerSentWriteCloseBeforeHandshake() throws Exception
    {
        k3po.finish();
    }

    @Test
    @Specification({
        "${route}/client/controller",
        "${client}/client.sent.write.close/client",
        "${server}/client.sent.write.close/server"})
    public void shouldReceiveClientSentWriteClose() throws Exception
    {
        k3po.finish();
    }

    @Ignore("TODO: throttle none implies immediately connected")
    @Test
    @Specification({
        "${route}/client/controller",
        "${client}/client.sent.write.close.before.handshake/client",
        "${server}/client.sent.write.close.before.handshake/server"})
    public void shouldReceiveClientSentWriteCloseBeforeHandshake() throws Exception
    {
        k3po.finish();
    }

    @Test
    @Specification({
        "${route}/client/controller",
        "${client}/server.sent.write.abort/client",
        "${server}/server.sent.write.abort/server"})
    public void shouldReceiveServerSentWriteAbort() throws Exception
    {
        k3po.finish();
    }

    @Test
    @Specification({
        "${route}/client/controller",
        "${client}/server.sent.write.abort.before.handshake/client",
        "${server}/server.sent.write.abort.before.handshake/server"})
    public void shouldRejectServerSentWriteAbortBeforeHandshake() throws Exception
    {
        k3po.finish();
    }

    @Test
    @Specification({
        "${route}/client/controller",
        "${client}/client.sent.write.abort/client",
        "${server}/client.sent.write.abort/server"})
    public void shouldReceiveClientSentWriteAbort() throws Exception
    {
        k3po.finish();
    }

    @Ignore("TODO: throttle none implies immediately connected")
    @Test
    @Specification({
        "${route}/client/controller",
        "${client}/client.sent.write.abort.before.handshake/client",
        "${server}/client.sent.write.abort.before.handshake/server"})
    public void shouldReceiveClientSentWriteAbortBeforeHandshake() throws Exception
    {
        k3po.finish();
    }

    @Test
    @Specification({
        "${route}/client/controller",
        "${client}/server.sent.read.abort/client",
        "${server}/server.sent.read.abort/server"})
    public void shouldReceiveServerSentReadAbort() throws Exception
    {
        k3po.finish();
    }

    @Test
    @Specification({
        "${route}/client/controller",
        "${client}/server.sent.read.abort.before.handshake/client",
        "${server}/server.sent.read.abort.before.handshake/server"})
    public void shouldRejectServerSentReadAbortBeforeHandshake() throws Exception
    {
        k3po.finish();
    }

    @Test
    @Specification({
        "${route}/client/controller",
        "${client}/client.sent.read.abort/client",
        "${server}/client.sent.read.abort/server"})
    public void shouldReceiveClientSentReadAbort() throws Exception
    {
        k3po.finish();
    }

    @Ignore("TODO: throttle none implies immediately connected")
    @Test
    @Specification({
        "${route}/client/controller",
        "${client}/client.sent.read.abort.before.handshake/client",
        "${server}/client.sent.read.abort.before.handshake/server"})
    public void shouldReceiveClientSentReadAbortBeforeHandshake() throws Exception
    {
        k3po.finish();
    }

    @Test
    @Specification({
        "${route}/client/controller",
        "${client}/client.handshake.timeout/client",
        "${server}/client.handshake.timeout/server" })
    @Configure(name = TLS_HANDSHAKE_TIMEOUT_NAME, value = "1")
    public void shouldTimeoutHandshake() throws Exception
    {
        k3po.finish();
    }
}
