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

import static java.lang.String.format;
import static org.agrona.BitUtil.isPowerOfTwo;

import org.reaktivity.nukleus.Configuration;

public class TlsConfiguration extends Configuration
{
    public static final String TRANSFER_CAPACITY = "nukleus.tls.transfer.capacity";

    public static final int TRANSFER_CAPACITY_DEFAULT = 1 << 16;

    public TlsConfiguration(
        Configuration config)
    {
        super(config);
    }

    public int transferCapacity()
    {
        int transferCapacity = getInteger(TRANSFER_CAPACITY, TRANSFER_CAPACITY_DEFAULT);
        if (!isPowerOfTwo(transferCapacity))
        {
            throw new IllegalArgumentException(format("%s is not a power of 2", TRANSFER_CAPACITY));
        }
        return transferCapacity;
    }

}
