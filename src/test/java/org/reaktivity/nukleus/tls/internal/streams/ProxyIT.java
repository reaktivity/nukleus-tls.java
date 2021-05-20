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
import org.kaazing.k3po.junit.annotation.Specification;
import org.kaazing.k3po.junit.rules.K3poRule;
import org.reaktivity.reaktor.ReaktorConfiguration;
import org.reaktivity.reaktor.test.ReaktorRule;
import org.reaktivity.reaktor.test.annotation.Configuration;

public class ProxyIT
{
    private final K3poRule k3po = new K3poRule()
            .addScriptRoot("proxy", "org/reaktivity/specification/nukleus/tls/streams/proxy");

    private final TestRule timeout = new DisableOnDebug(new Timeout(10, SECONDS));

    private final ReaktorRule reaktor = new ReaktorRule()
            .directory("target/nukleus-itests")
            .commandBufferCapacity(1024)
            .responseBufferCapacity(1024)
            .counterValuesBufferCapacity(8192)
            .configurationRoot("org/reaktivity/specification/nukleus/tls/config")
            .external("net#1")
            .configure(ReaktorConfiguration.REAKTOR_DRAIN_ON_CLOSE, false)
            .clean();

    @Rule
    public final TestRule chain = outerRule(reaktor).around(k3po).around(timeout);

    @Test
    @Configuration("proxy.sni.json")
    @Specification({
        "${proxy}/client/client.hello.with.sni/client",
        "${proxy}/server/client.hello.with.sni/server" })
    public void shouldProxyClientHelloWithServerName() throws Exception
    {
        k3po.finish();
    }

    @Test
    @Configuration("proxy.sni.json")
    @Specification({
        "${proxy}/client/reject.client.hello.with.sni/client" })
    public void shouldRejectClientHelloWithServerName() throws Exception
    {
        k3po.finish();
    }
}
