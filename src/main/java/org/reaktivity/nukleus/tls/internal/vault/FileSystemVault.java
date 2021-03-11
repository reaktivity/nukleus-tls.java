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

import static java.util.Collections.unmodifiableMap;
import static java.util.stream.Collectors.toList;
import static org.bouncycastle.asn1.x509.Extension.authorityKeyIdentifier;
import static org.bouncycastle.asn1.x509.Extension.keyUsage;
import static org.bouncycastle.asn1.x509.Extension.subjectAlternativeName;
import static org.bouncycastle.asn1.x509.Extension.subjectKeyIdentifier;
import static org.bouncycastle.asn1.x509.GeneralName.dNSName;
import static org.bouncycastle.asn1.x509.KeyUsage.digitalSignature;
import static org.bouncycastle.asn1.x509.KeyUsage.keyEncipherment;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.URL;
import java.net.URLConnection;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;
import java.util.function.Function;

import javax.security.auth.x500.X500Principal;

import org.agrona.LangUtil;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.RFC4519Style;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.reaktivity.nukleus.tls.internal.vault.config.FileSystemOptions;
import org.reaktivity.nukleus.tls.internal.vault.config.FileSystemStore;
import org.reaktivity.reaktor.nukleus.vault.BindingVault;

public class FileSystemVault implements BindingVault
{
    private static final String TYPE_DEFAULT = "PKCS12";

    private static final Map<String, String> SIG_TYPES_BY_KEY_TYPES;

    static
    {
        Map<String, String> sigAlgsByKeyAlgs = new TreeMap<>(String::compareToIgnoreCase);
        sigAlgsByKeyAlgs.put("EC", "SHA256withECDSA");
        sigAlgsByKeyAlgs.put("RSA", "SHA256WithRSA");
        sigAlgsByKeyAlgs.put("DSA", "SHA1WithDSA");
        SIG_TYPES_BY_KEY_TYPES = unmodifiableMap(sigAlgsByKeyAlgs);
    }

    private final Function<String, KeyStore.Entry> lookupKey;
    private final Function<String, KeyStore.Entry> lookupTrust;
    private final Function<String, X509Certificate> lookupSignerCert;
    private final Function<String, PrivateKey> lookupSignerKey;
    private final SecureRandom random;

    private CertificateFactory factory;

    public FileSystemVault(
        FileSystemOptions options,
        Function<String, URL> resolvePath)
    {
        lookupKey = supplyLookupEntry(resolvePath, options.keys);
        lookupTrust = supplyLookupEntry(resolvePath, options.trust);
        lookupSignerCert = supplyLookupX509Certificate(resolvePath, options.signers);
        lookupSignerKey = supplyLookupPrivateKey(resolvePath, options.signers);
        random = new SecureRandom();
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

    @Override
    public X509Certificate[] sign(
        String signerAlias,
        PublicKey publicKey,
        String distinguishedName,
        Instant notBefore,
        Instant notAfter,
        List<String> subjectNames)
    {
        X509Certificate[] chain = null;

        sign:
        try
        {
            String keyType = publicKey.getAlgorithm();
            String sigType = SIG_TYPES_BY_KEY_TYPES.get(keyType);
            if (sigType == null)
            {
                break sign;
            }

            X509Certificate signerCert = lookupSignerCert.apply(signerAlias);
            PrivateKey signerKey = lookupSignerKey.apply(signerAlias);

            if (signerCert == null || signerKey == null)
            {
                break sign;
            }

            if (factory == null)
            {
                factory = CertificateFactory.getInstance("X509");
            }

            X500Principal issuerX500 = signerCert.getIssuerX500Principal();
            X500Name issuer = new X500Name(RFC4519Style.INSTANCE, issuerX500.getName());
            X500Name dnameX500 = new X500Name(RFC4519Style.INSTANCE, distinguishedName);

            ContentSigner signer = new JcaContentSignerBuilder(sigType)
                .setSecureRandom(random)
                .build(signerKey);
            SubjectPublicKeyInfo publicKeyInfo =
                new JcaPKCS10CertificationRequestBuilder(dnameX500, publicKey)
                    .build(signer)
                    .getSubjectPublicKeyInfo();

            JcaX509ExtensionUtils utils = new JcaX509ExtensionUtils();
            X509v3CertificateBuilder builder =
                new X509v3CertificateBuilder(
                        issuer,
                        new BigInteger(Long.SIZE, random),
                        Date.from(notBefore),
                        Date.from(notAfter),
                        dnameX500,
                        publicKeyInfo)
                    .addExtension(authorityKeyIdentifier, false, utils.createAuthorityKeyIdentifier(signerCert))
                    .addExtension(keyUsage, true, new KeyUsage(digitalSignature | keyEncipherment));

            if (subjectNames != null && !subjectNames.isEmpty())
            {
                List<ASN1Encodable> encodableNames = subjectNames.stream()
                    .map(n -> new GeneralName(dNSName, n))
                    .map(ASN1Encodable.class::cast)
                    .collect(toList());

                ASN1Encodable[] encodableArray = encodableNames.toArray(new ASN1Encodable[encodableNames.size()]);

                builder.addExtension(subjectAlternativeName, false, new DERSequence(encodableArray));
            }

            X509CertificateHolder holder = builder
                    .addExtension(subjectKeyIdentifier, false, utils.createSubjectKeyIdentifier(publicKeyInfo))
                    .build(signer);
            X509Certificate issued = new JcaX509CertificateConverter()
                .getCertificate(holder);

            InputStream encoded = new ByteArrayInputStream(issued.getEncoded());
            X509Certificate signedCert = (X509Certificate) factory.generateCertificate(encoded);

            signedCert.verify(signerCert.getPublicKey());

            chain = new X509Certificate[] { issued, signerCert };
        }
        catch (Exception ex)
        {
            // sign failed
        }

        return chain;
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

    private static Function<String, KeyStore.Entry> supplyLookupEntry(
        Function<String, URL> resolvePath,
        FileSystemStore aliases)
    {
        return supplyLookupAlias(resolvePath, aliases, FileSystemVault::lookupEntry);
    }

    private static Function<String, X509Certificate> supplyLookupX509Certificate(
        Function<String, URL> resolvePath,
        FileSystemStore aliases)
    {
        return supplyLookupAlias(resolvePath, aliases, FileSystemVault::lookupX509Certificate);
    }

    private static Function<String, PrivateKey> supplyLookupPrivateKey(
        Function<String, URL> resolvePath,
        FileSystemStore aliases)
    {
        return supplyLookupAlias(resolvePath, aliases, FileSystemVault::lookupPrivateKey);
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

    private static X509Certificate lookupX509Certificate(
        String alias,
        KeyStore store,
        KeyStore.PasswordProtection protection)
    {
        X509Certificate x509 = null;

        try
        {
            Certificate certificate = store.getCertificate(alias);
            x509 = certificate instanceof X509Certificate ? (X509Certificate) certificate : null;
        }
        catch (Exception ex)
        {
            LangUtil.rethrowUnchecked(ex);
        }

        return x509;
    }

    private static PrivateKey lookupPrivateKey(
        String alias,
        KeyStore store,
        KeyStore.PasswordProtection protection)
    {
        PrivateKey privateKey = null;

        try
        {
            Key key = store.getKey(alias, protection.getPassword());
            privateKey = key instanceof PrivateKey ? (PrivateKey) key : null;
        }
        catch (Exception ex)
        {
            LangUtil.rethrowUnchecked(ex);
        }

        return privateKey;
    }

    @FunctionalInterface
    private interface Lookup<T>
    {
        T apply(String alias, KeyStore store, KeyStore.PasswordProtection protection);
    }
}
