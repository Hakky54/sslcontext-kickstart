/*
 * Copyright 2019-2021 the original author or authors.
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
import nl.altindag.ssl.model.IdentityMaterial;
import nl.altindag.ssl.model.KeyStoreHolder;
import nl.altindag.ssl.model.SSLMaterial;
import nl.altindag.ssl.model.TrustMaterial;
import nl.altindag.ssl.util.KeyManagerUtils;
import nl.altindag.ssl.util.KeyStoreUtils;
import nl.altindag.ssl.util.SSLContextUtils;
import nl.altindag.ssl.util.SSLParametersUtils;
import nl.altindag.ssl.util.SocketUtils;
import nl.altindag.ssl.util.TrustManagerUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.KeyManagerFactory;
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
import java.nio.file.Path;
import java.security.Key;
import java.security.KeyStore;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.function.BiFunction;
import java.util.function.Supplier;

import static java.util.Objects.isNull;
import static java.util.Objects.nonNull;
import static java.util.stream.Collectors.toList;

/**
 * @author Hakan Altindag
 */
public final class SSLFactory {

    private static final Logger LOGGER = LoggerFactory.getLogger(SSLFactory.class);

    private final SSLMaterial sslMaterial;

    private SSLFactory(SSLMaterial sslMaterial) {
        this.sslMaterial = sslMaterial;
    }

    public List<KeyStoreHolder> getIdentities() {
        return sslMaterial.getIdentityMaterial().getIdentities();
    }

    public List<KeyStoreHolder> getTrustStores() {
        return sslMaterial.getTrustMaterial().getTrustStores();
    }

    public SSLContext getSslContext() {
        return sslMaterial.getSslContext();
    }

    public SSLSocketFactory getSslSocketFactory() {
        return sslMaterial.getSslSocketFactory();
    }

    public SSLServerSocketFactory getSslServerSocketFactory() {
        return sslMaterial.getSslServerSocketFactory();
    }

    public Optional<X509ExtendedKeyManager> getKeyManager() {
        return Optional.ofNullable(sslMaterial.getIdentityMaterial().getKeyManager());
    }

    public Optional<KeyManagerFactory> getKeyManagerFactory() {
        return Optional.ofNullable(sslMaterial.getIdentityMaterial().getKeyManagerFactory());
    }

    public Optional<X509ExtendedTrustManager> getTrustManager() {
        return Optional.ofNullable(sslMaterial.getTrustMaterial().getTrustManager());
    }

    public Optional<TrustManagerFactory> getTrustManagerFactory() {
        return Optional.ofNullable(sslMaterial.getTrustMaterial().getTrustManagerFactory());
    }

    public List<X509Certificate> getTrustedCertificates() {
        return sslMaterial.getTrustMaterial().getTrustedCertificates();
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
        return sslMaterial.getSslEngine().apply(null, null);
    }

    public SSLEngine getSSLEngine(String peerHost, Integer peerPort) {
        return sslMaterial.getSslEngine().apply(peerHost, peerPort);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {

        private static final String TRUST_STORE_VALIDATION_EXCEPTION_MESSAGE = "TrustStore details are empty, which are required to be present when SSL/TLS is enabled";
        private static final String IDENTITY_VALIDATION_EXCEPTION_MESSAGE = "Identity details are empty, which are required to be present when SSL/TLS is enabled";
        private static final String IDENTITY_AND_TRUST_MATERIAL_VALIDATION_EXCEPTION_MESSAGE = "Could not create instance of SSLFactory because Identity " +
                "and Trust material are not present. Please provide at least a Trust material.";

        private static final char[] EMPTY_PASSWORD = {};

        private String sslContextAlgorithm = "TLS";
        private Provider securityProvider = null;
        private String securityProviderName = null;
        private SecureRandom secureRandom = null;
        private HostnameVerifier hostnameVerifier = (host, sslSession) -> host.equalsIgnoreCase(sslSession.getPeerHost());

        private final List<KeyStoreHolder> identities = new ArrayList<>();
        private final List<KeyStoreHolder> trustStores = new ArrayList<>();
        private final List<X509ExtendedKeyManager> identityManagers = new ArrayList<>();
        private final List<X509ExtendedTrustManager> trustManagers = new ArrayList<>();
        private final SSLParameters sslParameters = new SSLParameters();

        private boolean passwordCachingEnabled = false;
        private boolean swappableKeyManagerEnabled = false;
        private boolean swappableTrustManagerEnabled = false;

        private Builder() {}

        public Builder withSystemTrustMaterial() {
            TrustManagerUtils.createTrustManagerWithSystemTrustedCertificates().ifPresent(trustManagers::add);
            return this;
        }

        public Builder withDefaultTrustMaterial() {
            trustManagers.add(TrustManagerUtils.createTrustManagerWithJdkTrustedCertificates());
            return this;
        }

        /**
         * Enables the possibility to swap the underlying TrustManager at runtime.
         * After this option has been enabled the TrustManager can be swapped
         * with {@link TrustManagerUtils#swapTrustManager(X509TrustManager, X509TrustManager) TrustManagerUtils#swapTrustManager(swappableTrustManager, newTrustManager)}
         */
        public Builder withSwappableTrustMaterial() {
            swappableTrustManagerEnabled = true;
            return this;
        }

        public <T extends X509TrustManager> Builder withTrustMaterial(T trustManager) {
            trustManagers.add(TrustManagerUtils.wrapIfNeeded(trustManager));
            return this;
        }

        public <T extends TrustManagerFactory> Builder withTrustMaterial(T trustManagerFactory) {
            X509ExtendedTrustManager trustManager = TrustManagerUtils.getTrustManager(trustManagerFactory);
            this.trustManagers.add(trustManager);
            return this;
        }

        public Builder withTrustMaterial(String trustStorePath, char[] trustStorePassword) {
            return withTrustMaterial(trustStorePath, trustStorePassword, KeyStore.getDefaultType());
        }

        public Builder withTrustMaterial(String trustStorePath, char[] trustStorePassword, String trustStoreType) {
            if (isBlank(trustStorePath)) {
                throw new GenericKeyStoreException(TRUST_STORE_VALIDATION_EXCEPTION_MESSAGE);
            }

            KeyStore trustStore = KeyStoreUtils.loadKeyStore(trustStorePath, trustStorePassword, trustStoreType);
            KeyStoreHolder trustStoreHolder = new KeyStoreHolder(trustStore, trustStorePassword);
            trustStores.add(trustStoreHolder);

            return this;
        }

        public Builder withTrustMaterial(Path trustStorePath, char[] trustStorePassword) {
            return withTrustMaterial(trustStorePath, trustStorePassword, KeyStore.getDefaultType());
        }

        public Builder withTrustMaterial(Path trustStorePath, char[] trustStorePassword, String trustStoreType) {
            if (isNull(trustStorePath) || isBlank(trustStoreType)) {
                throw new GenericKeyStoreException(TRUST_STORE_VALIDATION_EXCEPTION_MESSAGE);
            }

            KeyStore trustStore = KeyStoreUtils.loadKeyStore(trustStorePath, trustStorePassword, trustStoreType);
            KeyStoreHolder trustStoreHolder = new KeyStoreHolder(trustStore, trustStorePassword);
            trustStores.add(trustStoreHolder);

            return this;
        }

        public Builder withTrustMaterial(InputStream trustStoreStream, char[] trustStorePassword) {
            return withTrustMaterial(trustStoreStream, trustStorePassword, KeyStore.getDefaultType());
        }

        public Builder withTrustMaterial(InputStream trustStoreStream, char[] trustStorePassword, String trustStoreType) {
            KeyStore trustStore = KeyStoreUtils.loadKeyStore(trustStoreStream, trustStorePassword, trustStoreType);
            KeyStoreHolder trustStoreHolder = new KeyStoreHolder(trustStore, trustStorePassword);
            trustStores.add(trustStoreHolder);
            return this;
        }

        public Builder withTrustMaterial(KeyStore trustStore) {
            withTrustMaterial(trustStore, EMPTY_PASSWORD);
            return this;
        }

        public Builder withTrustMaterial(KeyStore trustStore, char[] trustStorePassword) {
            validateKeyStore(trustStore, TRUST_STORE_VALIDATION_EXCEPTION_MESSAGE);
            KeyStoreHolder trustStoreHolder = new KeyStoreHolder(trustStore, trustStorePassword);
            trustStores.add(trustStoreHolder);

            return this;
        }

        @SafeVarargs
        public final <T extends Certificate> Builder withTrustMaterial(T... certificates) {
            return withTrustMaterial(Arrays.asList(certificates));
        }

        public <T extends Certificate> Builder withTrustMaterial(List<T> certificates) {
            KeyStore trustStore = KeyStoreUtils.createTrustStore(certificates);
            KeyStoreHolder trustStoreHolder = new KeyStoreHolder(trustStore, KeyStoreUtils.DUMMY_PASSWORD.toCharArray());
            trustStores.add(trustStoreHolder);
            return this;
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
            if (isBlank(identityStorePath) || isBlank(identityStoreType)) {
                throw new GenericKeyStoreException(IDENTITY_VALIDATION_EXCEPTION_MESSAGE);
            }

            KeyStore identity = KeyStoreUtils.loadKeyStore(identityStorePath, identityStorePassword, identityStoreType);
            KeyStoreHolder identityHolder = new KeyStoreHolder(identity, identityStorePassword, identityPassword);
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
            if (isNull(identityStorePath) || isBlank(identityStoreType)) {
                throw new GenericKeyStoreException(IDENTITY_VALIDATION_EXCEPTION_MESSAGE);
            }

            KeyStore identity = KeyStoreUtils.loadKeyStore(identityStorePath, identityStorePassword, identityStoreType);
            KeyStoreHolder identityHolder = new KeyStoreHolder(identity, identityStorePassword, identityPassword);
            identities.add(identityHolder);
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
            if (isNull(identityStream) || isBlank(identityStoreType)) {
                throw new GenericKeyStoreException(IDENTITY_VALIDATION_EXCEPTION_MESSAGE);
            }

            KeyStore identity = KeyStoreUtils.loadKeyStore(identityStream, identityStorePassword, identityStoreType);
            KeyStoreHolder identityHolder = new KeyStoreHolder(identity, identityStorePassword, identityPassword);
            identities.add(identityHolder);
            return this;
        }

        public Builder withIdentityMaterial(KeyStore identityStore, char[] identityStorePassword) {
            return withIdentityMaterial(identityStore, identityStorePassword, identityStorePassword);
        }

        public Builder withIdentityMaterial(KeyStore identityStore, char[] identityStorePassword, char[] identityPassword) {
            validateKeyStore(identityStore, IDENTITY_VALIDATION_EXCEPTION_MESSAGE);
            KeyStoreHolder identityHolder = new KeyStoreHolder(identityStore, identityStorePassword, identityPassword);
            identities.add(identityHolder);
            return this;
        }

        public Builder withIdentityMaterial(Key privateKey, char[] privateKeyPassword, Certificate... certificateChain) {
            KeyStore identityStore = KeyStoreUtils.createIdentityStore(privateKey, privateKeyPassword, certificateChain);
            identities.add(new KeyStoreHolder(identityStore, KeyStoreUtils.DUMMY_PASSWORD.toCharArray(), privateKeyPassword));
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

        /**
         * Enables the possibility to swap the underlying KeyManager at runtime.
         * After this option has been enabled the KeyManager can be swapped
         * with {@link KeyManagerUtils#swapKeyManager(X509KeyManager, X509KeyManager) KeyManagerUtils#swapKeyManager(swappableKeyManager, newKeyManager)}
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

        public <T extends HostnameVerifier> Builder withHostnameVerifier(T hostnameVerifier) {
            this.hostnameVerifier = hostnameVerifier;
            return this;
        }

        public Builder withCiphers(String... ciphers) {
            sslParameters.setCipherSuites(ciphers);
            return this;
        }

        public Builder withProtocols(String... protocols) {
            sslParameters.setProtocols(protocols);
            return this;
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
            LOGGER.warn("UnsafeTrustManager is being used. Client/Server certificates will be accepted without validation. Please don't use this configuration at production.");
            trustManagers.add(TrustManagerUtils.createUnsafeTrustManager());
            return this;
        }

        public Builder withPasswordCaching() {
            passwordCachingEnabled = true;
            return this;
        }

        public SSLFactory build() {
            if (!isIdentityMaterialPresent() && !isTrustMaterialPresent()) {
                throw new GenericSecurityException(IDENTITY_AND_TRUST_MATERIAL_VALIDATION_EXCEPTION_MESSAGE);
            }

            X509ExtendedKeyManager keyManager = isIdentityMaterialPresent() ? createKeyManager() : null;
            X509ExtendedTrustManager trustManager = isTrustMaterialPresent() ? createTrustManagers() : null;
            SSLContext sslContext = SSLContextUtils.createSslContext(
                    keyManager,
                    trustManager,
                    secureRandom,
                    sslContextAlgorithm,
                    securityProviderName,
                    securityProvider
            );

            KeyManagerFactory keyManagerFactory = keyManager != null ? KeyManagerUtils.createKeyManagerFactory(keyManager) : null;
            TrustManagerFactory trustManagerFactory = trustManager != null ? TrustManagerUtils.createTrustManagerFactory(trustManager) : null;

            SSLParameters baseSslParameters = SSLParametersUtils.merge(sslParameters, sslContext.getDefaultSSLParameters());
            SSLSocketFactory sslSocketFactory = SocketUtils.createSslSocketFactory(sslContext.getSocketFactory(), SSLParametersUtils.copy(baseSslParameters));
            SSLServerSocketFactory sslServerSocketFactory = SocketUtils.createSslServerSocketFactory(sslContext.getServerSocketFactory(), SSLParametersUtils.copy(baseSslParameters));
            Supplier<List<X509Certificate>> trustedCertificates = () -> Optional.ofNullable(trustManager)
                    .map(X509ExtendedTrustManager::getAcceptedIssuers)
                    .flatMap(x509Certificates -> Optional.of(Arrays.asList(x509Certificates)))
                    .map(Collections::unmodifiableList)
                    .orElse(Collections.emptyList());

            BiFunction<String, Integer, SSLEngine> sslEngine = (peerHost, peerPort) -> {
                SSLParameters parameters = SSLParametersUtils.copy(baseSslParameters);
                SSLEngine engine = nonNull(peerHost) && nonNull(peerPort) ? sslContext.createSSLEngine(peerHost, peerPort) : sslContext.createSSLEngine();
                engine.setSSLParameters(parameters);
                return engine;
            };

            if (!passwordCachingEnabled && !identities.isEmpty()) {
                KeyStoreUtils.sanitizeKeyStores(identities);
            }

            if (!passwordCachingEnabled && !trustStores.isEmpty()) {
                KeyStoreUtils.sanitizeKeyStores(trustStores);
            }

            IdentityMaterial identityMaterial = new IdentityMaterial.Builder()
                    .withKeyManager(keyManager)
                    .withKeyManagerFactory(keyManagerFactory)
                    .withIdentities(Collections.unmodifiableList(identities))
                    .build();

            TrustMaterial trustMaterial = new TrustMaterial.Builder()
                    .withTrustManager(trustManager)
                    .withTrustManagerFactory(trustManagerFactory)
                    .withTrustStores(Collections.unmodifiableList(trustStores))
                    .withTrustedCertificates(trustedCertificates)
                    .build();

            SSLMaterial sslMaterial = new SSLMaterial.Builder()
                    .withSslContext(sslContext)
                    .withSslSocketFactory(sslSocketFactory)
                    .withSslServerSocketFactory(sslServerSocketFactory)
                    .withSslEngine(sslEngine)
                    .withIdentityMaterial(identityMaterial)
                    .withTrustMaterial(trustMaterial)
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

        private boolean isBlank(CharSequence charSequence) {
            int length = isNull(charSequence) ? 0 : charSequence.length();
            if (length != 0) {
                for (int i = 0; i < length; ++i) {
                    if (!Character.isWhitespace(charSequence.charAt(i))) {
                        return false;
                    }
                }
            }
            return true;
        }

        private X509ExtendedKeyManager createKeyManager() {
            return KeyManagerUtils.keyManagerBuilder()
                    .withKeyManagers(identityManagers)
                    .withIdentities(identities)
                    .withSwappableKeyManager(swappableKeyManagerEnabled)
                    .build();
        }

        private X509ExtendedTrustManager createTrustManagers() {
            return TrustManagerUtils.trustManagerBuilder()
                    .withTrustManagers(trustManagers)
                    .withTrustStores(trustStores.stream()
                            .map(KeyStoreHolder::getKeyStore)
                            .collect(toList()))
                    .withSwappableTrustManager(swappableTrustManagerEnabled)
                    .build();
        }

    }
}
