/*
 * Copyright 2019-2022 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package nl.altindag.ssl;

import nl.altindag.ssl.exception.GenericKeyStoreException;
import nl.altindag.ssl.exception.GenericSecurityException;
import nl.altindag.ssl.model.KeyStoreHolder;
import nl.altindag.ssl.model.SSLMaterial;
import nl.altindag.ssl.trustmanager.ChainAndAuthTypeValidator;
import nl.altindag.ssl.trustmanager.ChainAndAuthTypeWithSSLEngineValidator;
import nl.altindag.ssl.trustmanager.ChainAndAuthTypeWithSocketValidator;
import nl.altindag.ssl.trustmanager.TrustAnchorTrustOptions;
import nl.altindag.ssl.trustmanager.TrustStoreTrustOptions;
import nl.altindag.ssl.util.HostnameVerifierUtils;
import nl.altindag.ssl.util.KeyManagerUtils;
import nl.altindag.ssl.util.KeyStoreUtils;
import nl.altindag.ssl.util.SSLContextUtils;
import nl.altindag.ssl.util.SSLParametersUtils;
import nl.altindag.ssl.util.SSLSessionUtils;
import nl.altindag.ssl.util.SSLSocketUtils;
import nl.altindag.ssl.util.StringUtils;
import nl.altindag.ssl.util.TrustManagerUtils;
import nl.altindag.ssl.util.UriUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.CertPathTrustManagerParameters;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.ManagerFactoryParameters;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;
import java.io.InputStream;
import java.net.URI;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyStore;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import static java.util.Objects.isNull;
import static java.util.Objects.nonNull;
import static nl.altindag.ssl.util.ValidationUtils.requireNotBlank;
import static nl.altindag.ssl.util.ValidationUtils.requireNotEmpty;

/**
 * @author Hakan Altindag
 */
public final class SSLFactory {

    private static final Logger LOGGER = LoggerFactory.getLogger(SSLFactory.class);

    private final SSLMaterial sslMaterial;

    private SSLFactory(SSLMaterial sslMaterial) {
        this.sslMaterial = sslMaterial;
    }

    public SSLContext getSslContext() {
        return sslMaterial.getSslContext();
    }

    public SSLSocketFactory getSslSocketFactory() {
        return SSLSocketUtils.createSslSocketFactory(sslMaterial.getSslContext(), getSslParameters());
    }

    public SSLServerSocketFactory getSslServerSocketFactory() {
        return SSLSocketUtils.createSslServerSocketFactory(sslMaterial.getSslContext(), getSslParameters());
    }

    public Optional<X509ExtendedKeyManager> getKeyManager() {
        return Optional.ofNullable(sslMaterial.getKeyManager());
    }

    public Optional<KeyManagerFactory> getKeyManagerFactory() {
        return getKeyManager().map(KeyManagerUtils::createKeyManagerFactory);
    }

    public Optional<X509ExtendedTrustManager> getTrustManager() {
        return Optional.ofNullable(sslMaterial.getTrustManager());
    }

    public Optional<TrustManagerFactory> getTrustManagerFactory() {
        return getTrustManager().map(TrustManagerUtils::createTrustManagerFactory);
    }

    public List<X509Certificate> getTrustedCertificates() {
        return getTrustManager()
                .map(X509ExtendedTrustManager::getAcceptedIssuers)
                .map(Arrays::asList)
                .map(Collections::unmodifiableList)
                .orElseGet(Collections::emptyList);
    }

    public HostnameVerifier getHostnameVerifier() {
        return sslMaterial.getHostnameVerifier();
    }

    public List<String> getCiphers() {
        return sslMaterial.getCiphers();
    }

    public List<String> getProtocols() {
        return sslMaterial.getProtocols();
    }

    public SSLParameters getSslParameters() {
        return SSLParametersUtils.copy(sslMaterial.getSslParameters());
    }

    public SSLEngine getSSLEngine() {
        return getSSLEngine(null, null);
    }

    public SSLEngine getSSLEngine(String peerHost, Integer peerPort) {
        SSLEngine sslEngine;
        if (nonNull(peerHost) && nonNull(peerPort)) {
            sslEngine = sslMaterial.getSslContext().createSSLEngine(peerHost, peerPort);
        } else {
            sslEngine = sslMaterial.getSslContext().createSSLEngine();
        }

        sslEngine.setSSLParameters(getSslParameters());
        return sslEngine;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {

        private static final String TRUST_STORE_VALIDATION_EXCEPTION_MESSAGE = "TrustStore details are empty, which are required to be present when SSL/TLS is enabled";
        private static final String IDENTITY_VALIDATION_EXCEPTION_MESSAGE = "Identity details are empty, which are required to be present when SSL/TLS is enabled";
        private static final String IDENTITY_AND_TRUST_MATERIAL_VALIDATION_EXCEPTION_MESSAGE = "Could not create instance of SSLFactory because Identity " +
                "and Trust material are not present. Please provide at least a Trust material.";
        private static final String CERTIFICATE_VALIDATION_EXCEPTION_MESSAGE = "Failed to load the certificate(s). No certificate has been provided.";
        private static final String SYSTEM_PROPERTY_VALIDATION_EXCEPTION_MESSAGE = "Failed to load the System property for [%s] because it does not contain any value";

        private String sslContextAlgorithm = "TLS";
        private Provider securityProvider = null;
        private String securityProviderName = null;
        private SecureRandom secureRandom = null;
        private HostnameVerifier hostnameVerifier = HostnameVerifierUtils.createBasic();

        private final List<KeyStoreHolder> identities = new ArrayList<>();
        private final List<KeyStore> trustStores = new ArrayList<>();
        private final List<X509ExtendedKeyManager> identityManagers = new ArrayList<>();
        private final List<X509ExtendedTrustManager> trustManagers = new ArrayList<>();
        private final SSLParameters sslParameters = new SSLParameters();
        private final Map<String, List<URI>> preferredAliasToHost = new HashMap<>();
        private final List<String> protocols = new ArrayList<>();
        private final List<String> ciphers = new ArrayList<>();

        private boolean swappableKeyManagerEnabled = false;
        private boolean swappableTrustManagerEnabled = false;

        private int sessionTimeoutInSeconds = -1;
        private int sessionCacheSizeInBytes = -1;

        private ChainAndAuthTypeValidator chainAndAuthTypeValidator = null;
        private ChainAndAuthTypeWithSocketValidator chainAndAuthTypeWithSocketValidator = null;
        private ChainAndAuthTypeWithSSLEngineValidator chainAndAuthTypeWithSSLEngineValidator = null;

        private Builder() {}

        public Builder withSystemTrustMaterial() {
            TrustManagerUtils.createTrustManagerWithSystemTrustedCertificates().ifPresent(trustManagers::add);
            return this;
        }

        public Builder withDefaultTrustMaterial() {
            trustManagers.add(TrustManagerUtils.createTrustManagerWithJdkTrustedCertificates());
            return this;
        }

        public Builder withSystemPropertyDerivedTrustMaterial() {
            return withSystemPropertyDerivedMaterial(
                    "javax.net.ssl.trustStore",
                    "javax.net.ssl.trustStorePassword",
                    "javax.net.ssl.trustStoreType",
                    "javax.net.ssl.trustStoreProvider",
                    this::withTrustMaterial
            );
        }

        /**
         * A shorter method for using the unsafe trust material
         *
         * @see Builder#withTrustingAllCertificatesWithoutValidation()
         * @return {@link Builder}
         */
        public Builder withUnsafeTrustMaterial() {
            return withTrustingAllCertificatesWithoutValidation();
        }

        public Builder withDummyTrustMaterial() {
            trustManagers.add(TrustManagerUtils.createDummyTrustManager());
            return this;
        }

        /**
         * Enables the possibility to swap the underlying TrustManager at runtime.
         * After this option has been enabled the TrustManager can be swapped
         * with {@link TrustManagerUtils#swapTrustManager(X509TrustManager, X509TrustManager) TrustManagerUtils#swapTrustManager(swappableTrustManager, newTrustManager)}
         *
         * @return {@link Builder}
         */
        public Builder withSwappableTrustMaterial() {
            swappableTrustManagerEnabled = true;
            return this;
        }

        public <T extends X509TrustManager> Builder withTrustMaterial(T trustManager) {
            trustManagers.add(TrustManagerUtils.wrapIfNeeded(trustManager));
            return this;
        }

        public <T extends ManagerFactoryParameters> Builder withTrustMaterial(T managerFactoryParameters) {
            trustManagers.add(TrustManagerUtils.createTrustManager(managerFactoryParameters));
            return this;
        }

        public <T extends X509TrustManager> Builder withTrustMaterial(T trustManager,
                                                                      TrustStoreTrustOptions<? extends CertPathTrustManagerParameters> trustOptions) {

            KeyStore trustStore = KeyStoreUtils.createTrustStore(trustManager.getAcceptedIssuers());
            return withTrustMaterial(trustStore, trustOptions);
        }

        public <T extends TrustManagerFactory> Builder withTrustMaterial(T trustManagerFactory) {
            X509ExtendedTrustManager trustManager = TrustManagerUtils.getTrustManager(trustManagerFactory);
            this.trustManagers.add(trustManager);
            return this;
        }

        public Builder withTrustMaterial(String trustStorePath, char[] trustStorePassword) {
            return withTrustMaterial(trustStorePath, trustStorePassword, KeyStore.getDefaultType());
        }

        public Builder withTrustMaterial(String trustStorePath,
                                         char[] trustStorePassword,
                                         TrustStoreTrustOptions<? extends CertPathTrustManagerParameters> trustOptions) {

            return withTrustMaterial(trustStorePath, trustStorePassword, KeyStore.getDefaultType(), trustOptions);
        }

        public Builder withTrustMaterial(String trustStorePath, char[] trustStorePassword, String trustStoreType) {
            if (StringUtils.isBlank(trustStorePath)  || StringUtils.isBlank(trustStoreType)) {
                throw new GenericKeyStoreException(TRUST_STORE_VALIDATION_EXCEPTION_MESSAGE);
            }

            KeyStore trustStore = KeyStoreUtils.loadKeyStore(trustStorePath, trustStorePassword, trustStoreType);
            trustStores.add(trustStore);

            return this;
        }

        public Builder withTrustMaterial(String trustStorePath,
                                         char[] trustStorePassword,
                                         String trustStoreType,
                                         TrustStoreTrustOptions<? extends CertPathTrustManagerParameters> trustOptions) {

            if (StringUtils.isBlank(trustStorePath) || StringUtils.isBlank(trustStoreType)) {
                throw new GenericKeyStoreException(TRUST_STORE_VALIDATION_EXCEPTION_MESSAGE);
            }

            KeyStore trustStore = KeyStoreUtils.loadKeyStore(trustStorePath, trustStorePassword, trustStoreType);
            return withTrustMaterial(trustStore, trustOptions);
        }

        public Builder withTrustMaterial(Path trustStorePath, char[] trustStorePassword) {
            return withTrustMaterial(trustStorePath, trustStorePassword, KeyStore.getDefaultType());
        }

        public Builder withTrustMaterial(Path trustStorePath,
                                         char[] trustStorePassword,
                                         TrustStoreTrustOptions<? extends CertPathTrustManagerParameters> trustOptions) {

            return withTrustMaterial(trustStorePath, trustStorePassword, KeyStore.getDefaultType(), trustOptions);
        }

        public Builder withTrustMaterial(Path trustStorePath, char[] trustStorePassword, String trustStoreType) {
            if (isNull(trustStorePath) || StringUtils.isBlank(trustStoreType)) {
                throw new GenericKeyStoreException(TRUST_STORE_VALIDATION_EXCEPTION_MESSAGE);
            }

            KeyStore trustStore = KeyStoreUtils.loadKeyStore(trustStorePath, trustStorePassword, trustStoreType);
            trustStores.add(trustStore);

            return this;
        }

        private Builder withTrustMaterial(Path trustStorePath, char[] trustStorePassword, String trustStoreType, String securityProviderName) {
            if (isNull(trustStorePath)) {
                throw new GenericKeyStoreException(TRUST_STORE_VALIDATION_EXCEPTION_MESSAGE);
            }

            KeyStore trustStore = KeyStoreUtils.loadKeyStore(trustStorePath, trustStorePassword, trustStoreType);

            X509ExtendedTrustManager trustManager = securityProviderName == null
                    ? TrustManagerUtils.createTrustManager(trustStore, TrustManagerFactory.getDefaultAlgorithm())
                    : TrustManagerUtils.createTrustManager(trustStore, TrustManagerFactory.getDefaultAlgorithm(), securityProviderName);

            trustManagers.add(trustManager);

            return this;
        }

        public Builder withTrustMaterial(Path trustStorePath,
                                         char[] trustStorePassword,
                                         String trustStoreType,
                                         TrustStoreTrustOptions<? extends CertPathTrustManagerParameters> trustOptions) {

            if (isNull(trustStorePath) || StringUtils.isBlank(trustStoreType)) {
                throw new GenericKeyStoreException(TRUST_STORE_VALIDATION_EXCEPTION_MESSAGE);
            }

            KeyStore trustStore = KeyStoreUtils.loadKeyStore(trustStorePath, trustStorePassword, trustStoreType);
            return withTrustMaterial(trustStore, trustOptions);
        }

        public Builder withTrustMaterial(InputStream trustStoreStream, char[] trustStorePassword) {
            return withTrustMaterial(trustStoreStream, trustStorePassword, KeyStore.getDefaultType());
        }

        public Builder withTrustMaterial(InputStream trustStoreStream,
                                         char[] trustStorePassword,
                                         TrustStoreTrustOptions<? extends CertPathTrustManagerParameters> trustOptions) {

            return withTrustMaterial(trustStoreStream, trustStorePassword, KeyStore.getDefaultType(), trustOptions);
        }

        public Builder withTrustMaterial(InputStream trustStoreStream, char[] trustStorePassword, String trustStoreType) {
            KeyStore trustStore = KeyStoreUtils.loadKeyStore(trustStoreStream, trustStorePassword, trustStoreType);
            trustStores.add(trustStore);
            return this;
        }

        public Builder withTrustMaterial(InputStream trustStoreStream,
                                         char[] trustStorePassword,
                                         String trustStoreType, TrustStoreTrustOptions<? extends CertPathTrustManagerParameters> trustOptions) {

            KeyStore trustStore = KeyStoreUtils.loadKeyStore(trustStoreStream, trustStorePassword, trustStoreType);
            return withTrustMaterial(trustStore, trustOptions);
        }

        public Builder withTrustMaterial(KeyStore trustStore) {
            validateKeyStore(trustStore, TRUST_STORE_VALIDATION_EXCEPTION_MESSAGE);
            trustStores.add(trustStore);

            return this;
        }

        public Builder withTrustMaterial(KeyStore trustStore, TrustStoreTrustOptions<? extends CertPathTrustManagerParameters> trustOptions) {
            try {
                CertPathTrustManagerParameters certPathTrustManagerParameters = trustOptions.apply(trustStore);
                return withTrustMaterial(certPathTrustManagerParameters);
            } catch (Exception e) {
                throw new GenericSecurityException(e);
            }
        }

        public Builder withTrustMaterial(Set<X509Certificate> certificates, TrustAnchorTrustOptions<? extends CertPathTrustManagerParameters> trustOptions) {
            try {
                Set<TrustAnchor> trustAnchors = certificates.stream()
                        .map(certificate -> new TrustAnchor(certificate, null))
                        .collect(Collectors.toSet());

                CertPathTrustManagerParameters certPathTrustManagerParameters = trustOptions.apply(trustAnchors);
                return withTrustMaterial(certPathTrustManagerParameters);
            } catch (Exception e) {
                throw new GenericSecurityException(e);
            }
        }

        @SafeVarargs
        public final <T extends Certificate> Builder withTrustMaterial(T... certificates) {
            return withTrustMaterial(Arrays.asList(certificates));
        }

        public final <T extends Certificate> Builder withTrustMaterial(T[] certificates,
                                                                       TrustStoreTrustOptions<? extends CertPathTrustManagerParameters> trustOptions) {

            return withTrustMaterial(Arrays.asList(certificates), trustOptions);
        }

        public <T extends Certificate> Builder withTrustMaterial(List<T> certificates) {
            KeyStore trustStore = KeyStoreUtils.createTrustStore(requireNotEmpty(certificates, CERTIFICATE_VALIDATION_EXCEPTION_MESSAGE));
            trustStores.add(trustStore);
            return this;
        }

        public <T extends Certificate> Builder withTrustMaterial(List<T> certificates,
                                                                 TrustStoreTrustOptions<? extends CertPathTrustManagerParameters> trustOptions) {
            KeyStore trustStore = KeyStoreUtils.createTrustStore(requireNotEmpty(certificates, CERTIFICATE_VALIDATION_EXCEPTION_MESSAGE));
            return withTrustMaterial(trustStore, trustOptions);
        }

        public Builder withSystemPropertyDerivedIdentityMaterial() {
            return withSystemPropertyDerivedMaterial(
                    "javax.net.ssl.keyStore",
                    "javax.net.ssl.keyStorePassword",
                    "javax.net.ssl.keyStoreType",
                    "javax.net.ssl.keyStoreProvider",
                    this::withIdentityMaterial
            );
        }

        public Builder withIdentityMaterial(String identityStorePath, char[] identityStorePassword) {
            return withIdentityMaterial(identityStorePath, identityStorePassword, identityStorePassword, KeyStore.getDefaultType());
        }

        public Builder withIdentityMaterial(String identityStorePath, char[] identityStorePassword, char[] identityPassword) {
            return withIdentityMaterial(identityStorePath, identityStorePassword, identityPassword, KeyStore.getDefaultType());
        }

        public Builder withIdentityMaterial(String identityStorePath, char[] identityStorePassword, String identityStoreType) {
            return withIdentityMaterial(identityStorePath, identityStorePassword, identityStorePassword, identityStoreType);
        }

        public Builder withIdentityMaterial(String identityStorePath, char[] identityStorePassword, char[] identityPassword, String identityStoreType) {
            if (StringUtils.isBlank(identityStorePath) || StringUtils.isBlank(identityStoreType)) {
                throw new GenericKeyStoreException(IDENTITY_VALIDATION_EXCEPTION_MESSAGE);
            }

            KeyStore identity = KeyStoreUtils.loadKeyStore(identityStorePath, identityStorePassword, identityStoreType);
            KeyStoreHolder identityHolder = new KeyStoreHolder(identity, identityPassword);
            identities.add(identityHolder);
            return this;
        }

        public Builder withIdentityMaterial(Path identityStorePath, char[] identityStorePassword) {
            return withIdentityMaterial(identityStorePath, identityStorePassword, identityStorePassword, KeyStore.getDefaultType());
        }

        public Builder withIdentityMaterial(Path identityStorePath, char[] identityStorePassword, char[] identityPassword) {
            return withIdentityMaterial(identityStorePath, identityStorePassword, identityPassword, KeyStore.getDefaultType());
        }

        public Builder withIdentityMaterial(Path identityStorePath, char[] identityStorePassword, String identityStoreType) {
            return withIdentityMaterial(identityStorePath, identityStorePassword, identityStorePassword, identityStoreType);
        }

        public Builder withIdentityMaterial(Path identityStorePath, char[] identityStorePassword, char[] identityPassword, String identityStoreType) {
            if (isNull(identityStorePath) || StringUtils.isBlank(identityStoreType)) {
                throw new GenericKeyStoreException(IDENTITY_VALIDATION_EXCEPTION_MESSAGE);
            }

            KeyStore identity = KeyStoreUtils.loadKeyStore(identityStorePath, identityStorePassword, identityStoreType);
            KeyStoreHolder identityHolder = new KeyStoreHolder(identity, identityPassword);
            identities.add(identityHolder);
            return this;
        }

        private Builder withIdentityMaterial(Path identityStorePath, char[] identityStorePassword, String identityStoreType, String securityProviderName) {
            if (isNull(identityStorePath)) {
                throw new GenericKeyStoreException(IDENTITY_VALIDATION_EXCEPTION_MESSAGE);
            }

            KeyStore identity = KeyStoreUtils.loadKeyStore(identityStorePath, identityStorePassword, identityStoreType);

            X509ExtendedKeyManager keyManager = securityProviderName == null
                    ? KeyManagerUtils.createKeyManager(identity, identityStorePassword, KeyManagerFactory.getDefaultAlgorithm())
                    : KeyManagerUtils.createKeyManager(identity, identityStorePassword, KeyManagerFactory.getDefaultAlgorithm(), securityProviderName);

            identityManagers.add(keyManager);
            return this;
        }

        public Builder withIdentityMaterial(InputStream identityStream, char[] identityStorePassword) {
            return withIdentityMaterial(identityStream, identityStorePassword, identityStorePassword);
        }

        public Builder withIdentityMaterial(InputStream identityStream, char[] identityStorePassword, char[] identityPassword) {
            return withIdentityMaterial(identityStream, identityStorePassword, identityPassword, KeyStore.getDefaultType());
        }

        public Builder withIdentityMaterial(InputStream identityStream, char[] identityStorePassword, String identityStoreType) {
            return withIdentityMaterial(identityStream, identityStorePassword, identityStorePassword, identityStoreType);
        }

        public Builder withIdentityMaterial(InputStream identityStream, char[] identityStorePassword, char[] identityPassword, String identityStoreType) {
            if (isNull(identityStream) || StringUtils.isBlank(identityStoreType)) {
                throw new GenericKeyStoreException(IDENTITY_VALIDATION_EXCEPTION_MESSAGE);
            }

            KeyStore identity = KeyStoreUtils.loadKeyStore(identityStream, identityStorePassword, identityStoreType);
            KeyStoreHolder identityHolder = new KeyStoreHolder(identity, identityPassword);
            identities.add(identityHolder);
            return this;
        }

        public Builder withIdentityMaterial(KeyStore identityStore, char[] identityPassword) {
            validateKeyStore(identityStore, IDENTITY_VALIDATION_EXCEPTION_MESSAGE);
            KeyStoreHolder identityHolder = new KeyStoreHolder(identityStore, identityPassword);
            identities.add(identityHolder);
            return this;
        }

        public Builder withIdentityMaterial(Key privateKey, char[] privateKeyPassword, Certificate... certificateChain) {
            return withIdentityMaterial(privateKey, privateKeyPassword, null, certificateChain);
        }

        public Builder withIdentityMaterial(Key privateKey, char[] privateKeyPassword, String alias, Certificate... certificateChain) {
            KeyStore identityStore = KeyStoreUtils.createIdentityStore(privateKey, privateKeyPassword, alias, certificateChain);
            identities.add(new KeyStoreHolder(identityStore, privateKeyPassword));
            return this;
        }

        public <T extends X509KeyManager> Builder withIdentityMaterial(T keyManager) {
            identityManagers.add(KeyManagerUtils.wrapIfNeeded(keyManager));
            return this;
        }

        public <T extends KeyManagerFactory> Builder withIdentityMaterial(T keyManagerFactory) {
            X509ExtendedKeyManager keyManager = KeyManagerUtils.getKeyManager(keyManagerFactory);
            this.identityManagers.add(keyManager);
            return this;
        }

        public Builder withDummyIdentityMaterial() {
            this.identityManagers.add(KeyManagerUtils.createDummyKeyManager());
            return this;
        }

        /**
         * Enables the possibility to swap the underlying KeyManager at runtime.
         * After this option has been enabled the KeyManager can be swapped
         * with {@link KeyManagerUtils#swapKeyManager(X509KeyManager, X509KeyManager) KeyManagerUtils#swapKeyManager(swappableKeyManager, newKeyManager)}
         *
         * @return {@link Builder}
         */
        public Builder withSwappableIdentityMaterial() {
            swappableKeyManagerEnabled = true;
            return this;
        }

        private void validateKeyStore(KeyStore keyStore, String exceptionMessage) {
            if (isNull(keyStore)) {
                throw new GenericKeyStoreException(exceptionMessage);
            }
        }

        public Builder withIdentityRoute(String alias, String... hosts) {
            return withIdentityRoute(
                    alias,
                    Arrays.stream(hosts)
                            .map(URI::create)
                            .collect(Collectors.toList())
            );
        }

        public Builder withIdentityRoute(Map<String, List<String>> aliasesToHosts) {
            aliasesToHosts.entrySet().stream()
                    .map(aliasToHosts -> new AbstractMap.SimpleEntry<>(
                            aliasToHosts.getKey(),
                            aliasToHosts.getValue().stream()
                                    .map(URI::create)
                                    .collect(Collectors.toList())))
                    .forEach(aliasToHosts -> withIdentityRoute(aliasToHosts.getKey(), aliasToHosts.getValue()));
            return this;
        }

        private Builder withIdentityRoute(String alias, List<URI> hosts) {
            if (StringUtils.isBlank(alias)) {
                throw new IllegalArgumentException("alias should be present");
            }

            requireNotEmpty(hosts, String.format("At least one host should be present. No host(s) found for the given alias: [%s]", alias));

            for (URI host : hosts) {
                UriUtils.validate(host);

                if (preferredAliasToHost.containsKey(alias)) {
                    preferredAliasToHost.get(alias).add(host);
                } else {
                    preferredAliasToHost.put(alias, new ArrayList<>(Collections.singletonList(host)));
                }
            }
            return this;
        }

        public <T extends HostnameVerifier> Builder withHostnameVerifier(T hostnameVerifier) {
            this.hostnameVerifier = hostnameVerifier;
            return this;
        }

        public Builder withUnsafeHostnameVerifier() {
            this.hostnameVerifier = HostnameVerifierUtils.createUnsafe();
            return this;
        }

        public Builder withCiphers(String... ciphers) {
            this.ciphers.addAll(Arrays.asList(ciphers));
            return this;
        }

        public Builder withSystemPropertyDerivedCiphers() {
            ciphers.addAll(extractPropertyValues("https.cipherSuites"));
            return this;
        }

        public Builder withProtocols(String... protocols) {
            this.protocols.addAll(Arrays.asList(protocols));
            return this;
        }

        public Builder withSystemPropertyDerivedProtocols() {
            protocols.addAll(extractPropertyValues("https.protocols"));
            return this;
        }

        private List<String> extractPropertyValues(String systemProperty) {
            String propertyValue = requireNotBlank(System.getProperty(systemProperty), String.format(SYSTEM_PROPERTY_VALIDATION_EXCEPTION_MESSAGE, systemProperty));

            List<String> propertyValues = Arrays.stream(propertyValue.split(","))
                    .map(String::trim)
                    .filter(StringUtils::isNotBlank)
                    .distinct().collect(Collectors.toList());

            return requireNotEmpty(propertyValues, String.format(SYSTEM_PROPERTY_VALIDATION_EXCEPTION_MESSAGE, systemProperty));
        }

        public Builder withNeedClientAuthentication() {
            return withNeedClientAuthentication(true);
        }

        public Builder withNeedClientAuthentication(boolean needClientAuthentication) {
            sslParameters.setNeedClientAuth(needClientAuthentication);
            return this;
        }

        public Builder withWantClientAuthentication() {
            return withWantClientAuthentication(true);
        }

        public Builder withWantClientAuthentication(boolean wantClientAuthentication) {
            sslParameters.setWantClientAuth(wantClientAuthentication);
            return this;
        }

        public Builder withSessionTimeout(int timeoutInSeconds) {
            this.sessionTimeoutInSeconds = timeoutInSeconds;
            return this;
        }

        public Builder withSessionCacheSize(int cacheSizeInBytes) {
            this.sessionCacheSizeInBytes = cacheSizeInBytes;
            return this;
        }

        public Builder withSslContextAlgorithm(String sslContextAlgorithm) {
            this.sslContextAlgorithm = sslContextAlgorithm;
            return this;
        }

        public <T extends Provider> Builder withSecurityProvider(T securityProvider) {
            this.securityProvider = securityProvider;
            return this;
        }

        public Builder withSecurityProvider(String securityProviderName) {
            this.securityProviderName = securityProviderName;
            return this;
        }

        public <T extends SecureRandom> Builder withSecureRandom(T secureRandom) {
            this.secureRandom = secureRandom;
            return this;
        }

        public Builder withTrustingAllCertificatesWithoutValidation() {
            LOGGER.warn("UnsafeTrustManager is being used. Client/Server certificates will be accepted without validation.");
            trustManagers.add(TrustManagerUtils.createUnsafeTrustManager());
            return this;
        }

        public Builder withTrustEnhancer(ChainAndAuthTypeValidator validator) {
            this.chainAndAuthTypeValidator = validator;
            return this;
        }

        public Builder withTrustEnhancer(ChainAndAuthTypeWithSocketValidator validator) {
            this.chainAndAuthTypeWithSocketValidator = validator;
            return this;
        }

        public Builder withTrustEnhancer(ChainAndAuthTypeWithSSLEngineValidator validator) {
            this.chainAndAuthTypeWithSSLEngineValidator = validator;
            return this;
        }

        private Builder withSystemPropertyDerivedMaterial(String keyStorePathProperty,
                                                          String keyStorePasswordProperty,
                                                          String keyStoreTypeProperty,
                                                          String securityProviderNameProperty,
                                                          QuadConsumer<Path, char[], String, String> keyStorePropertyConsumer) {

            Path keystore = Optional.ofNullable(System.getProperty(keyStorePathProperty))
                    .map(String::trim)
                    .filter(StringUtils::isNotBlank)
                    .map(Paths::get)
                    .orElse(null);

            char[] keystorePassword = Optional.ofNullable(System.getProperty(keyStorePasswordProperty))
                    .map(String::trim)
                    .filter(StringUtils::isNotBlank)
                    .map(String::toCharArray)
                    .orElse(null);

            String keystoreType = Optional.ofNullable(System.getProperty(keyStoreTypeProperty))
                    .map(String::trim)
                    .filter(StringUtils::isNotBlank)
                    .orElseGet(KeyStore::getDefaultType);

            String securityProvideName = Optional.ofNullable(System.getProperty(securityProviderNameProperty))
                    .map(String::trim)
                    .filter(StringUtils::isNotBlank)
                    .orElse(null);

            keyStorePropertyConsumer.accept(keystore, keystorePassword, keystoreType, securityProvideName);
            return this;
        }

        private interface QuadConsumer<T, U, V, W> {
            void accept(T t, U u, V v, W w);
        }

        public SSLFactory build() {
            if (!isIdentityMaterialPresent() && !isTrustMaterialPresent()) {
                throw new GenericSecurityException(IDENTITY_AND_TRUST_MATERIAL_VALIDATION_EXCEPTION_MESSAGE);
            }

            X509ExtendedKeyManager keyManager = isIdentityMaterialPresent() ? createKeyManager() : null;
            X509ExtendedTrustManager trustManager = isTrustMaterialPresent() ? createTrustManager() : null;
            SSLContext sslContext = SSLContextUtils.createSslContext(
                    keyManager,
                    trustManager,
                    secureRandom,
                    sslContextAlgorithm,
                    securityProviderName,
                    securityProvider
            );

            if (sessionTimeoutInSeconds >= 0) {
                SSLSessionUtils.updateSessionTimeout(sslContext, sessionTimeoutInSeconds);
            }

            if (sessionCacheSizeInBytes >= 0) {
                SSLSessionUtils.updateSessionCacheSize(sslContext, sessionCacheSizeInBytes);
            }

            sslParameters.setCipherSuites(ciphers.isEmpty() ? null : ciphers.stream().distinct().toArray(String[]::new));
            sslParameters.setProtocols(protocols.isEmpty() ? null : protocols.stream().distinct().toArray(String[]::new));
            SSLParameters baseSslParameters = SSLParametersUtils.merge(sslParameters, sslContext.getDefaultSSLParameters());

            SSLMaterial sslMaterial = new SSLMaterial.Builder()
                    .withSslContext(sslContext)
                    .withKeyManager(keyManager)
                    .withTrustManager(trustManager)
                    .withSslParameters(baseSslParameters)
                    .withHostnameVerifier(hostnameVerifier)
                    .withCiphers(Collections.unmodifiableList(Arrays.asList(baseSslParameters.getCipherSuites())))
                    .withProtocols(Collections.unmodifiableList(Arrays.asList(baseSslParameters.getProtocols())))
                    .build();

            return new SSLFactory(sslMaterial);
        }

        private boolean isTrustMaterialPresent() {
            return !trustStores.isEmpty()
                    || !trustManagers.isEmpty();
        }

        private boolean isIdentityMaterialPresent() {
            return !identities.isEmpty()
                    || !identityManagers.isEmpty();
        }

        private X509ExtendedKeyManager createKeyManager() {
            return KeyManagerUtils.keyManagerBuilder()
                    .withKeyManagers(identityManagers)
                    .withIdentities(identities)
                    .withSwappableKeyManager(swappableKeyManagerEnabled)
                    .withIdentityRoute(preferredAliasToHost)
                    .build();
        }

        private X509ExtendedTrustManager createTrustManager() {
            return TrustManagerUtils.trustManagerBuilder()
                    .withTrustManagers(trustManagers)
                    .withTrustStores(trustStores)
                    .withSwappableTrustManager(swappableTrustManagerEnabled)
                    .withTrustEnhancer(chainAndAuthTypeValidator)
                    .withTrustEnhancer(chainAndAuthTypeWithSocketValidator)
                    .withTrustEnhancer(chainAndAuthTypeWithSSLEngineValidator)
                    .build();
        }

    }
}
