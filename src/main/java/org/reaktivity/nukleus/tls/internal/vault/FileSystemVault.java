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
import java.security.KeyStore;
import java.security.KeyStore.Entry;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
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
import org.reaktivity.reaktor.nukleus.vault.CertificateRequest;

public class FileSystemVault implements BindingVault
{
    private static final String TYPE_DEFAULT = "PKCS12";

    private static final Map<String, String> SIG_TYPES_BY_KEY_TYPES;

    static
    {
        Map<String, String> sigAlgsByKeyAlgs = new TreeMap<>(String::compareToIgnoreCase);
        sigAlgsByKeyAlgs.put("EC", "SHA256WithECDSA");
        sigAlgsByKeyAlgs.put("RSA", "SHA256WithRSA");
        sigAlgsByKeyAlgs.put("DSA", "SHA1WithDSA");
        SIG_TYPES_BY_KEY_TYPES = unmodifiableMap(sigAlgsByKeyAlgs);
    }

    private final Function<String, KeyStore.PrivateKeyEntry> lookupKey;
    private final Function<String, KeyStore.TrustedCertificateEntry> lookupTrust;
    private final Function<String, KeyStore.PrivateKeyEntry> lookupSigner;
    private final SecureRandom random;

    private CertificateFactory factory;

    public FileSystemVault(
        FileSystemOptions options,
        Function<String, URL> resolvePath)
    {
        lookupKey = supplyLookupPrivateKeyEntry(resolvePath, options.keys);
        lookupTrust = supplyLookupTrustedCertificateEntry(resolvePath, options.trust);
        lookupSigner = supplyLookupPrivateKeyEntry(resolvePath, options.signers);
        random = new SecureRandom();
    }

    @Override
    public KeyStore.PrivateKeyEntry key(
        String alias)
    {
        return lookupKey.apply(alias);
    }

    @Override
    public KeyStore.TrustedCertificateEntry trust(
        String alias)
    {
        return lookupTrust.apply(alias);
    }

    @Override
    public String signedRef(
        String signer,
        String dname,
        String keyType)
    {
        return null;
    }

    @Override
    public X509Certificate[] sign(
        String signerAlias,
        CertificateRequest request)
    {
        X509Certificate[] chain = null;

        sign:
        try
        {
            KeyStore.PrivateKeyEntry signerEntry = lookupSigner.apply(signerAlias);

            if (signerEntry == null ||
                signerEntry.getPrivateKey() == null ||
                !X509Certificate.class.isInstance(signerEntry.getCertificate()))
            {
                break sign;
            }

            if (factory == null)
            {
                factory = CertificateFactory.getInstance("X509");
            }

            PrivateKey signerKey = signerEntry.getPrivateKey();
            X509Certificate signerX509 = (X509Certificate) signerEntry.getCertificate();
            X500Principal issuerX500 = signerX509.getIssuerX500Principal();
            X500Name issuer = new X500Name(RFC4519Style.INSTANCE, issuerX500.getName());
            X500Name dnameX500 = new X500Name(RFC4519Style.INSTANCE, request.dname);

            String keyType = signerKey.getAlgorithm();
            String sigType = SIG_TYPES_BY_KEY_TYPES.get(keyType);
            if (sigType == null)
            {
                break sign;
            }

            ContentSigner signer = new JcaContentSignerBuilder(sigType)
                .setSecureRandom(random)
                .build(signerKey);
            SubjectPublicKeyInfo publicKeyInfo =
                new JcaPKCS10CertificationRequestBuilder(dnameX500, request.publicKey)
                    .build(signer)
                    .getSubjectPublicKeyInfo();

            JcaX509ExtensionUtils utils = new JcaX509ExtensionUtils();
            X509v3CertificateBuilder builder =
                new X509v3CertificateBuilder(
                        issuer,
                        new BigInteger(Long.SIZE, random),
                        Date.from(request.notBefore),
                        Date.from(request.notAfter),
                        dnameX500,
                        publicKeyInfo)
                    .addExtension(authorityKeyIdentifier, false, utils.createAuthorityKeyIdentifier(signerX509))
                    .addExtension(keyUsage, true, new KeyUsage(digitalSignature | keyEncipherment));

            if (request.subjectNames != null && !request.subjectNames.isEmpty())
            {
                List<ASN1Encodable> encodableNames = request.subjectNames.stream()
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

            signedCert.verify(signerX509.getPublicKey());

            chain = new X509Certificate[] { issued, signerX509 };
        }
        catch (Exception ex)
        {
            // sign failed
        }

        return chain;
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
