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
import nl.altindag.ssl.exception.GenericSSLContextException;
import nl.altindag.ssl.exception.GenericSecurityException;
import nl.altindag.ssl.keymanager.CompositeX509ExtendedKeyManager;
import nl.altindag.ssl.model.KeyStoreHolder;
import nl.altindag.ssl.socket.CompositeSSLServerSocketFactory;
import nl.altindag.ssl.socket.CompositeSSLSocketFactory;
import nl.altindag.ssl.trustmanager.CompositeX509ExtendedTrustManager;
import nl.altindag.ssl.util.KeyManagerUtils;
import nl.altindag.ssl.util.KeyStoreUtils;
import nl.altindag.ssl.util.TrustManagerUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Path;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

import static java.util.Objects.isNull;
import static java.util.Objects.nonNull;
import static java.util.stream.Collectors.toList;

/**
 * @author Hakan Altindag
 */
public final class SSLFactory {

    private static final Logger LOGGER = LoggerFactory.getLogger(SSLFactory.class);
    private static final char[] EMPTY_PASSWORD = {};

    private final String sslContextProtocol;
    private final Provider securityProvider;
    private final String securityProviderName;
    private final SecureRandom secureRandom;
    private final HostnameVerifier hostnameVerifier;

    private final List<KeyStoreHolder> identities = new ArrayList<>();
    private final List<X509ExtendedKeyManager> identityManagers = new ArrayList<>();

    private final List<KeyStoreHolder> trustStores = new ArrayList<>();
    private final List<X509ExtendedTrustManager> trustManagers = new ArrayList<>();
    private final boolean passwordCachingEnabled;
    private final SSLParameters sslParameters;

    private SSLContext sslContext;
    private SSLSocketFactory sslSocketFactory;
    private SSLServerSocketFactory sslServerSocketFactory;
    private X509ExtendedTrustManager trustManager;
    private X509ExtendedKeyManager keyManager;
    private KeyManagerFactory keyManagerFactory;
    private TrustManagerFactory trustManagerFactory;
    private List<X509Certificate> trustedCertificates;
    private List<String> ciphers;
    private List<String> protocols;

    @SuppressWarnings("java:S107")
    private SSLFactory(String sslContextProtocol,
                       Provider securityProvider,
                       String securityProviderName,
                       SecureRandom secureRandom,
                       HostnameVerifier hostnameVerifier,
                       List<KeyStoreHolder> identities,
                       List<X509ExtendedKeyManager> identityManagers,
                       List<KeyStoreHolder> trustStores,
                       List<X509ExtendedTrustManager> trustManagers,
                       boolean passwordCachingEnabled,
                       SSLParameters sslParameters) {

        this.sslContextProtocol = sslContextProtocol;
        this.securityProvider = securityProvider;
        this.securityProviderName = securityProviderName;
        this.secureRandom = secureRandom;
        this.hostnameVerifier = hostnameVerifier;
        this.identities.addAll(identities);
        this.identityManagers.addAll(identityManagers);
        this.trustStores.addAll(trustStores);
        this.trustManagers.addAll(trustManagers);
        this.passwordCachingEnabled = passwordCachingEnabled;
        this.sslParameters = sslParameters;
    }

    private void createSSLContextWithIdentityMaterial() {
        createSSLContext(createKeyManager(), null);
    }

    private void createSSLContextWithTrustMaterial() {
        createSSLContext(null, createTrustManagers());
    }

    private void createSSLContextWithIdentityMaterialAndTrustMaterial() {
        createSSLContext(createKeyManager(), createTrustManagers());
    }

    private void createSSLContext(KeyManager[] keyManagers, TrustManager[] trustManagers)  {
        try {
            if (nonNull(securityProvider)) {
                sslContext = SSLContext.getInstance(sslContextProtocol, securityProvider);
            } else if (nonNull(securityProviderName)) {
                sslContext = SSLContext.getInstance(sslContextProtocol, securityProviderName);
            } else {
                sslContext = SSLContext.getInstance(sslContextProtocol);
            }

            sslContext.init(keyManagers, trustManagers, secureRandom);
            postConstructRemainingSslMaterials();
        } catch (NoSuchAlgorithmException | NoSuchProviderException | KeyManagementException e) {
            throw new GenericSSLContextException(e);
        }
    }

    private KeyManager[] createKeyManager() {
        keyManager = CompositeX509ExtendedKeyManager.builder()
                .withKeyManagers(identityManagers)
                .withIdentities(identities)
                .build();

        if (!passwordCachingEnabled && !identities.isEmpty()) {
            sanitizeKeyStores(identities);
        }

        return new X509ExtendedKeyManager[] {keyManager};
    }

    private TrustManager[] createTrustManagers() {
        trustManager = CompositeX509ExtendedTrustManager.builder()
                .withTrustManagers(trustManagers)
                .withTrustStores(trustStores.stream()
                        .map(KeyStoreHolder::getKeyStore)
                        .collect(toList())
                ).build();

        if (!passwordCachingEnabled && !trustStores.isEmpty()) {
            sanitizeKeyStores(trustStores);
        }

        return new TrustManager[] {trustManager};
    }

    private void sanitizeKeyStores(List<KeyStoreHolder> keyStores) {
        List<KeyStoreHolder> sanitizedKeyStores = keyStores.stream()
                .map(keyStoreHolder -> new KeyStoreHolder(keyStoreHolder.getKeyStore(), EMPTY_PASSWORD, EMPTY_PASSWORD))
                .collect(toList());

        keyStores.clear();
        keyStores.addAll(sanitizedKeyStores);
    }

    private void postConstructRemainingSslMaterials() {
        reinitializeSslParameters();
        sslSocketFactory = new CompositeSSLSocketFactory(sslContext.getSocketFactory(), sslParameters);
        sslServerSocketFactory = new CompositeSSLServerSocketFactory(sslContext.getServerSocketFactory(), sslParameters);
        trustedCertificates = Optional.ofNullable(trustManager)
                .map(X509ExtendedTrustManager::getAcceptedIssuers)
                .flatMap(x509Certificates -> Optional.of(Arrays.asList(x509Certificates)))
                .map(Collections::unmodifiableList)
                .orElse(Collections.emptyList());

        keyManagerFactory = getKeyManager()
                .map(KeyManagerUtils::createKeyManagerFactory)
                .orElse(null);

        trustManagerFactory = getTrustManager()
                .map(TrustManagerUtils::createTrustManagerFactory)
                .orElse(null);
    }

    private void reinitializeSslParameters() {
        SSLParameters defaultSSLParameters = sslContext.getDefaultSSLParameters();

        String[] someCiphers = Optional.ofNullable(sslParameters.getCipherSuites())
                .orElse(defaultSSLParameters.getCipherSuites());

        String[] someProtocols = Optional.ofNullable(sslParameters.getProtocols())
                .orElse(defaultSSLParameters.getProtocols());

        sslParameters.setCipherSuites(someCiphers);
        sslParameters.setProtocols(someProtocols);

        ciphers = Collections.unmodifiableList(Arrays.asList(someCiphers));
        protocols = Collections.unmodifiableList(Arrays.asList(someProtocols));
    }

    public List<KeyStoreHolder> getIdentities() {
        return Collections.unmodifiableList(identities);
    }

    public List<KeyStoreHolder> getTrustStores() {
        return Collections.unmodifiableList(trustStores);
    }

    public SSLContext getSslContext() {
        return sslContext;
    }

    public SSLSocketFactory getSslSocketFactory() {
        return sslSocketFactory;
    }

    public SSLServerSocketFactory getSslServerSocketFactory() {
        return sslServerSocketFactory;
    }

    public Optional<X509ExtendedKeyManager> getKeyManager() {
        return Optional.ofNullable(keyManager);
    }

    public Optional<KeyManagerFactory> getKeyManagerFactory() {
        return Optional.ofNullable(keyManagerFactory);
    }

    public Optional<X509ExtendedTrustManager> getTrustManager() {
        return Optional.ofNullable(trustManager);
    }

    public Optional<TrustManagerFactory> getTrustManagerFactory() {
        return Optional.ofNullable(trustManagerFactory);
    }

    public List<X509Certificate> getTrustedCertificates() {
        return trustedCertificates;
    }

    public HostnameVerifier getHostnameVerifier() {
        return hostnameVerifier;
    }

    public List<String> getCiphers() {
        return ciphers;
    }

    public List<String> getProtocols() {
        return protocols;
    }

    public SSLParameters getSslParameters() {
        return sslParameters;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {

        private static final String TRUST_STORE_VALIDATION_EXCEPTION_MESSAGE = "TrustStore details are empty, which are required to be present when SSL/TLS is enabled";
        private static final String IDENTITY_VALIDATION_EXCEPTION_MESSAGE = "Identity details are empty, which are required to be present when SSL/TLS is enabled";
        private static final String KEY_STORE_LOADING_EXCEPTION = "Failed to load the keystore";
        private static final String KEY_MANAGER_FACTORY_EXCEPTION = "KeyManagerFactory does not contain any KeyManagers of type X509ExtendedKeyManager";
        private static final String TRUST_MANAGER_FACTORY_EXCEPTION = "TrustManagerFactory does not contain any TrustManagers of type X509ExtendedTrustManager";
        private static final String IDENTITY_AND_TRUST_MATERIAL_VALIDATION_EXCEPTION_MESSAGE = "Could not create instance of SSLFactory because Identity " +
                "and Trust material are not present. Please provide at least a Trust material.";

        private String sslContextProtocol = "TLS";
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

        private Builder() {}

        public Builder withSystemTrustMaterial() {
            trustManagers.add(TrustManagerUtils.createTrustManagerWithSystemTrustedCertificates());
            return this;
        }

        public Builder withDefaultTrustMaterial() {
            trustManagers.add(TrustManagerUtils.createTrustManagerWithJdkTrustedCertificates());
            return this;
        }

        public <T extends X509TrustManager> Builder withTrustMaterial(T trustManager) {
            trustManagers.add(TrustManagerUtils.wrapIfNeeded(trustManager));
            return this;
        }

        public <T extends TrustManagerFactory> Builder withTrustMaterial(T trustManagerFactory) {
            boolean isTrustManagerAdded = false;
            for (TrustManager trustManager : trustManagerFactory.getTrustManagers()) {
                if (trustManager instanceof X509TrustManager) {
                    trustManagers.add(TrustManagerUtils.wrapIfNeeded((X509TrustManager) trustManager));
                    isTrustManagerAdded = true;
                }
            }

            if (!isTrustManagerAdded) {
                throw new GenericSecurityException(TRUST_MANAGER_FACTORY_EXCEPTION);
            }

            return this;
        }

        public Builder withTrustMaterial(String trustStorePath, char[] trustStorePassword) {
            return withTrustMaterial(trustStorePath, trustStorePassword, KeyStore.getDefaultType());
        }

        public Builder withTrustMaterial(String trustStorePath, char[] trustStorePassword, String trustStoreType) {
            if (isBlank(trustStorePath)) {
                throw new GenericKeyStoreException(TRUST_STORE_VALIDATION_EXCEPTION_MESSAGE);
            }

            try {
                KeyStore trustStore = KeyStoreUtils.loadKeyStore(trustStorePath, trustStorePassword, trustStoreType);
                KeyStoreHolder trustStoreHolder = new KeyStoreHolder(trustStore, trustStorePassword);
                trustStores.add(trustStoreHolder);
            } catch (IOException | KeyStoreException | NoSuchAlgorithmException | CertificateException e) {
                throw new GenericKeyStoreException(KEY_STORE_LOADING_EXCEPTION, e);
            }

            return this;
        }

        public Builder withTrustMaterial(Path trustStorePath, char[] trustStorePassword) {
            return withTrustMaterial(trustStorePath, trustStorePassword, KeyStore.getDefaultType());
        }

        public Builder withTrustMaterial(Path trustStorePath, char[] trustStorePassword, String trustStoreType) {
            if (isNull(trustStorePath) || isBlank(trustStoreType)) {
                throw new GenericKeyStoreException(TRUST_STORE_VALIDATION_EXCEPTION_MESSAGE);
            }

            try {
                KeyStore trustStore = KeyStoreUtils.loadKeyStore(trustStorePath, trustStorePassword, trustStoreType);
                KeyStoreHolder trustStoreHolder = new KeyStoreHolder(trustStore, trustStorePassword);
                trustStores.add(trustStoreHolder);
            } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
                throw new GenericKeyStoreException(KEY_STORE_LOADING_EXCEPTION, e);
            }

            return this;
        }

        public Builder withTrustMaterial(InputStream trustStoreStream, char[] trustStorePassword) {
            return withTrustMaterial(trustStoreStream, trustStorePassword, KeyStore.getDefaultType());
        }

        public Builder withTrustMaterial(InputStream trustStoreStream, char[] trustStorePassword, String trustStoreType) {
            try {
                KeyStore trustStore = KeyStoreUtils.loadKeyStore(trustStoreStream, trustStorePassword, trustStoreType);
                KeyStoreHolder trustStoreHolder = new KeyStoreHolder(trustStore, trustStorePassword);
                trustStores.add(trustStoreHolder);
            } catch (KeyStoreException | CertificateException | NoSuchAlgorithmException | IOException e) {
                throw new GenericKeyStoreException(KEY_STORE_LOADING_EXCEPTION, e);
            }

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
            try {
                KeyStore trustStore = KeyStoreUtils.createTrustStore(certificates);
                KeyStoreHolder trustStoreHolder = new KeyStoreHolder(trustStore, KeyStoreUtils.DUMMY_PASSWORD.toCharArray());
                trustStores.add(trustStoreHolder);
            } catch (CertificateException | NoSuchAlgorithmException | KeyStoreException | IOException e) {
                throw new GenericKeyStoreException(e);
            }
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

            try {
                KeyStore identity = KeyStoreUtils.loadKeyStore(identityStorePath, identityStorePassword, identityStoreType);
                KeyStoreHolder identityHolder = new KeyStoreHolder(identity, identityStorePassword, identityPassword);
                identities.add(identityHolder);
            } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
                throw new GenericKeyStoreException(KEY_STORE_LOADING_EXCEPTION, e);
            }
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

            try {
                KeyStore identity = KeyStoreUtils.loadKeyStore(identityStorePath, identityStorePassword, identityStoreType);
                KeyStoreHolder identityHolder = new KeyStoreHolder(identity, identityStorePassword, identityPassword);
                identities.add(identityHolder);
            } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
                throw new GenericKeyStoreException(KEY_STORE_LOADING_EXCEPTION, e);
            }
            return this;
        }

        public Builder withIdentityMaterial(InputStream identityStorePath, char[] identityStorePassword) {
            return withIdentityMaterial(identityStorePath, identityStorePassword, identityStorePassword);
        }

        public Builder withIdentityMaterial(InputStream identityStorePath, char[] identityStorePassword, char[] identityPassword) {
            return withIdentityMaterial(identityStorePath, identityStorePassword, identityPassword, KeyStore.getDefaultType());
        }

        public Builder withIdentityMaterial(InputStream identityStorePath, char[] identityStorePassword, String identityStoreType) {
            return withIdentityMaterial(identityStorePath, identityStorePassword, identityStorePassword, identityStoreType);
        }

        public Builder withIdentityMaterial(InputStream identityStream, char[] identityStorePassword, char[] identityPassword, String identityStoreType) {
            if (isNull(identityStream) || isBlank(identityStoreType)) {
                throw new GenericKeyStoreException(IDENTITY_VALIDATION_EXCEPTION_MESSAGE);
            }

            try {
                KeyStore identity = KeyStoreUtils.loadKeyStore(identityStream, identityStorePassword, identityStoreType);
                KeyStoreHolder identityHolder = new KeyStoreHolder(identity, identityStorePassword, identityPassword);
                identities.add(identityHolder);
            } catch (KeyStoreException | CertificateException | NoSuchAlgorithmException | IOException e) {
                throw new GenericKeyStoreException(KEY_STORE_LOADING_EXCEPTION, e);
            }

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

        public Builder withIdentityMaterial(PrivateKey privateKey, char[] privateKeyPassword, Certificate... certificateChain) {
            try {
                KeyStore identityStore = KeyStoreUtils.createIdentityStore(privateKey, privateKeyPassword, certificateChain);
                identities.add(new KeyStoreHolder(identityStore, KeyStoreUtils.DUMMY_PASSWORD.toCharArray(), privateKeyPassword));
            } catch (CertificateException | NoSuchAlgorithmException | KeyStoreException | IOException e) {
                throw new GenericKeyStoreException(e);
            }
            return this;
        }

        public <T extends X509KeyManager> Builder withIdentityMaterial(T keyManager) {
            identityManagers.add(KeyManagerUtils.wrapIfNeeded(keyManager));
            return this;
        }

        public <T extends KeyManagerFactory> Builder withIdentityMaterial(T keyManagerFactory) {
            boolean isKeyManagerAdded = false;
            for (KeyManager keyManager : keyManagerFactory.getKeyManagers()) {
                if (keyManager instanceof X509KeyManager) {
                    identityManagers.add(KeyManagerUtils.wrapIfNeeded((X509KeyManager) keyManager));
                    isKeyManagerAdded = true;
                }
            }

            if (!isKeyManagerAdded) {
                throw new GenericSecurityException(KEY_MANAGER_FACTORY_EXCEPTION);
            }

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

        public Builder withSslContextProtocol(String sslContextProtocol) {
            this.sslContextProtocol = sslContextProtocol;
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
            if (isIdentityMaterialNotPresent() && isTrustMaterialNotPresent()) {
                throw new GenericSecurityException(IDENTITY_AND_TRUST_MATERIAL_VALIDATION_EXCEPTION_MESSAGE);
            }

            SSLFactory sslFactory = new SSLFactory(
                    sslContextProtocol,
                    securityProvider,
                    securityProviderName,
                    secureRandom,
                    hostnameVerifier,
                    identities,
                    identityManagers,
                    trustStores,
                    trustManagers,
                    passwordCachingEnabled,
                    sslParameters
            );

            if (isIdentityMaterialPresent() && isTrustMaterialPresent()) {
                sslFactory.createSSLContextWithIdentityMaterialAndTrustMaterial();
            } else if (isIdentityMaterialPresent()) {
                sslFactory.createSSLContextWithIdentityMaterial();
            } else {
                sslFactory.createSSLContextWithTrustMaterial();
            }

            return sslFactory;
        }

        private boolean isTrustMaterialPresent() {
            return !trustStores.isEmpty()
                    || !trustManagers.isEmpty();
        }

        private boolean isTrustMaterialNotPresent() {
            return !isTrustMaterialPresent();
        }

        private boolean isIdentityMaterialPresent() {
            return !identities.isEmpty()
                    || !identityManagers.isEmpty();
        }

        private boolean isIdentityMaterialNotPresent() {
            return !isIdentityMaterialPresent();
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

    }
}
