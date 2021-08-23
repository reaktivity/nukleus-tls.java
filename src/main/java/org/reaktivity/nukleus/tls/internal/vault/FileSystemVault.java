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
import java.security.KeyStore.Entry;
import java.util.Optional;
import java.util.function.Function;

import org.agrona.LangUtil;
import org.reaktivity.nukleus.tls.internal.vault.config.FileSystemOptions;
import org.reaktivity.nukleus.tls.internal.vault.config.FileSystemStore;
import org.reaktivity.reaktor.nukleus.vault.BindingVault;

public class FileSystemVault implements BindingVault
{
    private static final String TYPE_DEFAULT = "PKCS12";

    private final Function<String, KeyStore.PrivateKeyEntry> lookupKey;
    private final Function<String, KeyStore.TrustedCertificateEntry> lookupTrust;

    public FileSystemVault(
        FileSystemOptions options,
        Function<String, URL> resolvePath)
    {
        lookupKey = supplyLookupPrivateKeyEntry(resolvePath, options.keys);
        lookupTrust = supplyLookupTrustedCertificateEntry(resolvePath, options.trust);
    }

    @Override
    public KeyStore.PrivateKeyEntry key(
        String alias)
    {
        return lookupKey.apply(alias);
    }

    @Override
    public KeyStore.TrustedCertificateEntry certificate(
        String alias)
    {
        return lookupTrust.apply(alias);
    }

    private static Function<String, KeyStore.PrivateKeyEntry> supplyLookupPrivateKeyEntry(
        Function<String, URL> resolvePath,
        FileSystemStore aliases)
    {
        return supplyLookupAlias(resolvePath, aliases, FileSystemVault::lookupPrivateKeyEntry);
    }

    private static Function<String, KeyStore.TrustedCertificateEntry> supplyLookupTrustedCertificateEntry(
        Function<String, URL> resolvePath,
        FileSystemStore aliases)
    {
        return supplyLookupAlias(resolvePath, aliases, FileSystemVault::lookupTrustedCertificateEntry);
    }

    private static <R> Function<String, R> supplyLookupAlias(
        Function<String, URL> resolvePath,
        FileSystemStore aliases,
        Lookup<R> lookup)
    {
        Function<String, R> lookupAlias = a -> null;

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
                    KeyStore.PasswordProtection protection = new KeyStore.PasswordProtection(password);

                    lookupAlias = alias -> lookup.apply(alias, store, protection);
                }
            }
            catch (Exception ex)
            {
                LangUtil.rethrowUnchecked(ex);
            }
        }

        return lookupAlias;
    }

    private static KeyStore.Entry lookupEntry(
        String alias,
        KeyStore store,
        KeyStore.PasswordProtection protection)
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

    private static KeyStore.PrivateKeyEntry lookupPrivateKeyEntry(
        String alias,
        KeyStore store,
        KeyStore.PasswordProtection protection)
    {
        Entry entry = lookupEntry(alias, store, protection);

        return entry instanceof KeyStore.PrivateKeyEntry ? (KeyStore.PrivateKeyEntry) entry : null;
    }

    private static KeyStore.TrustedCertificateEntry lookupTrustedCertificateEntry(
        String alias,
        KeyStore store,
        KeyStore.PasswordProtection protection)
    {
        Entry entry = lookupEntry(alias, store, protection);

        return entry instanceof KeyStore.TrustedCertificateEntry ? (KeyStore.TrustedCertificateEntry) entry : null;
    }

    @FunctionalInterface
    private interface Lookup<T>
    {
        T apply(String alias, KeyStore store, KeyStore.PasswordProtection protection);
    }
}
