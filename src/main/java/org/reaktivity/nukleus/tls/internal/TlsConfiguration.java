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
    public static final String APPLICATION_TRANSFER_CAPACITY = "nukleus.tls.application.transfer.capacity";

    public static final int APPLICATION_TRANSFER_CAPACITY_DEFAULT = 1 << 16;

    public static final String NETWORK_TRANSFER_CAPACITY = "nukleus.tls.network.transfer.capacity";

    public static final int NETWORK_TRANSFER_CAPACITY_DEFAULT = 1 << 16;

    public TlsConfiguration(
        Configuration config)
    {
        super(config);
    }

    public int applicationTransferCapacity()
    {
        return getInteger(APPLICATION_TRANSFER_CAPACITY, APPLICATION_TRANSFER_CAPACITY_DEFAULT);
    }

    public int networkTransferCapacity()
    {
        return getInteger(NETWORK_TRANSFER_CAPACITY, NETWORK_TRANSFER_CAPACITY_DEFAULT);
    }
}
