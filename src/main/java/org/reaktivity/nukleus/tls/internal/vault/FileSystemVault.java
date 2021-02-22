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
package org.reaktivity.nukleus.tls.internal.vault;

import java.io.InputStream;
import java.net.URL;
import java.net.URLConnection;
import java.security.KeyStore;
import java.util.Collection;
import java.util.Optional;
import java.util.function.Function;

import org.agrona.LangUtil;
import org.reaktivity.nukleus.tls.internal.vault.config.FileSystemOptions;
import org.reaktivity.nukleus.tls.internal.vault.config.FileSystemStore;
import org.reaktivity.reaktor.nukleus.vault.BindingVault;

public class FileSystemVault implements BindingVault
{
    private static final String TYPE_DEFAULT = "PKCS12";

    private final Function<String, KeyStore.Entry> lookupKey;
    private final Function<String, KeyStore.Entry> lookupTrust;

    public FileSystemVault(
        FileSystemOptions options,
        Function<String, URL> resolvePath)
    {
        lookupKey = supplyLookupAlias(resolvePath, options.keys);
        lookupTrust = supplyLookupAlias(resolvePath, options.trust);
    }

    @Override
    public KeyStore newKeys(
        char[] password,
        Collection<String> aliases)
    {
        return newStore(password, aliases, lookupKey);
    }

    @Override
    public KeyStore newTrust(
        Collection<String> aliases)
    {
        return newStore(null, aliases, lookupTrust);
    }

    private KeyStore newStore(
        char[] password,
        Collection<String> aliases,
        Function<String, KeyStore.Entry> lookupAlias)
    {
        KeyStore store = null;

        try
        {
            if (aliases != null)
            {
                store = KeyStore.getInstance(TYPE_DEFAULT);
                store.load(null, password);

                for (String alias : aliases)
                {
                    KeyStore.Entry entry = lookupAlias.apply(alias);
                    if (entry != null)
                    {
                        KeyStore.ProtectionParameter protection = new KeyStore.PasswordProtection(password);
                        store.setEntry(alias, entry, protection);
                    }
                }
            }
        }
        catch (Exception ex)
        {
            LangUtil.rethrowUnchecked(ex);
        }

        return store;
    }

    private static Function<String, KeyStore.Entry> supplyLookupAlias(
        Function<String, URL> resolvePath,
        FileSystemStore aliases)
    {
        Function<String, KeyStore.Entry> lookupAlias = a -> null;

        if (aliases != null)
        {
            try
            {
                URL storeURL = resolvePath.apply(aliases.store);
                URLConnection connection = storeURL.openConnection();
                try (InputStream input = connection.getInputStream())
                {
                    String type = Optional.ofNullable(aliases.type).orElse(TYPE_DEFAULT);
                    char[] password = Optional.ofNullable(aliases.password).map(String::toCharArray).orElse(null);

                    KeyStore store = KeyStore.getInstance(type);
                    store.load(input, password);
                    KeyStore.ProtectionParameter protection = new KeyStore.PasswordProtection(password);

                    lookupAlias = alias -> lookupAlias(alias, store, protection);
                }
            }
            catch (Exception ex)
            {
                LangUtil.rethrowUnchecked(ex);
            }
        }

        return lookupAlias;
    }

    private static KeyStore.Entry lookupAlias(
        String alias,
        KeyStore store,
        KeyStore.ProtectionParameter protection)
    {
        KeyStore.Entry entry = null;

        try
        {
            entry = store.getEntry(alias, protection);
        }
        catch (Exception ex)
        {
            try
            {
                entry = store.getEntry(alias, null);
            }
            catch (Exception e)
            {
                e.addSuppressed(ex);
                LangUtil.rethrowUnchecked(e);
            }
        }

        return entry;
    }
}
