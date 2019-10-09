/**
 * Copyright 2016-2019 The Reaktivity Project
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
package org.reaktivity.nukleus.tls.internal.util.function;

import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;

import java.util.Random;

import org.junit.Test;

public class ObjectLongBiFunctionTest
{
    @Test
    @SuppressWarnings("unchecked")
    public void shouldInvokePrimitiveAccept()
    {
        final ObjectLongBiFunction<Object, Object> function = spy(ObjectLongBiFunction.class);

        final Object object = new Object();
        final Long value = new Random().nextLong();

        function.apply(object, value);

        verify(function).apply(object, value.longValue());
    }
}
