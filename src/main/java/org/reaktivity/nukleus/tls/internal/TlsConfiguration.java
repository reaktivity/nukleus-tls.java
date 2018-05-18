/**
 * Copyright 2016-2017 The Reaktivity Project
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

import org.reaktivity.nukleus.Configuration;

public class TlsConfiguration extends Configuration
{
    public static final String HANDSHAKE_WINDOW_BYTES_PROPERTY_NAME = "nukleus.tls.handshake.window.bytes";

    public static final String HANDSHAKE_WINDOW_FRAMES_PROPERTY_NAME = "nukleus.tls.handshake.window.frames";
    public static final String KEY_MANAGER_ALGORITHM = "nukleus.tls.key.manager.algorithm";

    public static final int HANDSHAKE_WINDOW_BYTES_DEFAULT = 65536;
    // PKIX has support for choosing server certificate using SNI in a keystore with multiple keys
    public static final String KEY_MANAGER_ALGORITHM_DEFAULT = "PKIX";

    public TlsConfiguration(
        Configuration config)
    {
        super(config);
    }

    public int handshakeWindowBytes()
    {
        return getInteger(HANDSHAKE_WINDOW_BYTES_PROPERTY_NAME, HANDSHAKE_WINDOW_BYTES_DEFAULT);
    }

    String keyManagerAlgorithm()
    {
        return getProperty(KEY_MANAGER_ALGORITHM, KEY_MANAGER_ALGORITHM_DEFAULT);
    }

}
