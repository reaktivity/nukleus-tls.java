/**
 * Copyright 2016-2018 The Reaktivity Project
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

import static java.util.concurrent.Executors.newFixedThreadPool;

import java.util.Deque;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.Executor;

import org.reaktivity.nukleus.Nukleus;

public final class TlsExecutor implements Nukleus
{
    private static final Executor IMMEDIATE = Runnable::run;

    private final Deque<Runnable> queue;
    private final Executor executor;

    private int workQueued;

    public TlsExecutor(
        TlsConfiguration config)
    {
        final int handshakeParallelism = config.handshakeParallelism();
        this.executor = handshakeParallelism <= 0 ? IMMEDIATE : newFixedThreadPool(handshakeParallelism);
        this.queue = new ConcurrentLinkedDeque<>();
    }

    public void executeTask(
        Runnable task,
        Runnable notify)
    {
        executor.execute(new Runnable()
        {
            @Override
            public void run()
            {
                try
                {
                    task.run();
                }
                finally
                {
                    queue.addLast(notify);
                }
            }
        });
        workQueued++;
    }

    @Override
    public int process()
    {
        int workDone = 0;

        if (workQueued != 0)
        {
            Runnable task = queue.pollFirst();
            while (task != null)
            {
                task.run();
                workDone++;
                task = queue.pollFirst();
            }

            workQueued -= workDone;
        }

        return workDone;
    }

    @Override
    public String name()
    {
        return "executor";
    }

    @Override
    public void close()
    {
    }
}
