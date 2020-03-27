package nl.altindag.sslcontext;

import com.google.common.collect.ImmutableList;
import nl.altindag.sslcontext.exception.GenericKeyStoreException;
import nl.altindag.sslcontext.exception.GenericSSLContextException;
import nl.altindag.sslcontext.keymanager.CompositeX509KeyManager;
import nl.altindag.sslcontext.keymanager.KeyManagerFactoryWrapper;
import nl.altindag.sslcontext.model.KeyStoreHolder;
import nl.altindag.sslcontext.trustmanager.CompositeX509TrustManager;
import nl.altindag.sslcontext.trustmanager.TrustManagerFactoryWrapper;
import nl.altindag.sslcontext.trustmanager.UnsafeTrustManager;
import nl.altindag.sslcontext.util.KeyStoreUtils;
import nl.altindag.sslcontext.util.TrustManagerUtils;
import org.apache.http.conn.ssl.DefaultHostnameVerifier;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.net.ssl.*;
import java.io.IOException;
import java.nio.file.Path;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static java.util.Objects.isNull;
import static java.util.stream.Collectors.toList;
import static org.apache.commons.lang3.ArrayUtils.isEmpty;
import static org.apache.commons.lang3.StringUtils.isBlank;

public class SSLFactory {

    private static final Logger LOGGER = LogManager.getLogger(SSLFactory.class);

    private final List<KeyStoreHolder> identities = new ArrayList<>();
    private final List<KeyStoreHolder> trustStores = new ArrayList<>();
    private final List<X509KeyManager> identityManagers = new ArrayList<>();
    private final List<X509TrustManager> trustManagers = new ArrayList<>();

    private boolean securityEnabled;
    private boolean oneWayAuthenticationEnabled;
    private boolean twoWayAuthenticationEnabled;
    private boolean includeDefaultJdkTrustStore;
    private boolean trustingAllCertificatesWithoutValidationEnabled;

    private String protocol;
    private SSLContext sslContext;
    private CompositeX509TrustManager trustManager;
    private TrustManagerFactory trustManagerFactory;
    private CompositeX509KeyManager keyManager;
    private KeyManagerFactory keyManagerFactory;
    private HostnameVerifier hostnameVerifier;

    private SSLFactory() {}

    private void createSSLContextWithTrustStore() {
        try {
            createSSLContext(null, createTrustManagerFactory().getTrustManagers());
        } catch (NoSuchAlgorithmException | KeyManagementException e) {
            throw new GenericSSLContextException(e);
        }
    }

    private void createSSLContextWithKeyStoreAndTrustStore() {
        try {
            createSSLContext(createKeyManagerFactory().getKeyManagers(),
                             createTrustManagerFactory().getTrustManagers());
        } catch (NoSuchAlgorithmException | KeyManagementException e) {
            throw new GenericSSLContextException(e);
        }
    }

    private void createSSLContext(KeyManager[] keyManagers, TrustManager[] trustManagers) throws NoSuchAlgorithmException, KeyManagementException {
        sslContext = SSLContext.getInstance(protocol);
        sslContext.init(keyManagers, trustManagers , null);
    }

    private KeyManagerFactory createKeyManagerFactory() {
        keyManager = CompositeX509KeyManager.builder()
                .withKeyManagers(identityManagers)
                .withIdentities(identities)
                .build();
        keyManagerFactory = new KeyManagerFactoryWrapper(keyManager);
        return keyManagerFactory;
    }

    private TrustManagerFactory createTrustManagerFactory() {
        CompositeX509TrustManager.Builder trustManagerBuilder = CompositeX509TrustManager.builder()
                .withTrustManagers(trustManagers)
                .withTrustStores(trustStores.stream()
                        .map(KeyStoreHolder::getKeyStore)
                        .collect(toList())
                );

        if (trustingAllCertificatesWithoutValidationEnabled) {
            LOGGER.warn("UnsafeTrustManager is being used. Client/Server certificates will be accepted without validation. Please don't use this configuration at production.");
            trustManagerBuilder.withTrustManagers(UnsafeTrustManager.INSTANCE);
        }

        if (includeDefaultJdkTrustStore) {
            trustManagerBuilder.withTrustManagers(TrustManagerUtils.createTrustManagerWithJdkTrustedCertificates());
        }

        trustManager = trustManagerBuilder.build();
        trustManagerFactory = new TrustManagerFactoryWrapper(trustManager);
        return trustManagerFactory;
    }

    public List<KeyStoreHolder> getIdentities() {
        return ImmutableList.copyOf(identities);
    }

    public List<KeyStoreHolder> getTrustStores() {
        return ImmutableList.copyOf(trustStores);
    }

    public boolean isSecurityEnabled() {
        return securityEnabled;
    }

    public boolean isOneWayAuthenticationEnabled() {
        return oneWayAuthenticationEnabled;
    }

    public boolean isTwoWayAuthenticationEnabled() {
        return twoWayAuthenticationEnabled;
    }

    public SSLContext getSslContext() {
        return sslContext;
    }

    public X509KeyManager getKeyManager() {
        return keyManager;
    }

    public KeyManagerFactory getKeyManagerFactory() {
        return keyManagerFactory;
    }

    public X509TrustManager getTrustManager() {
        return trustManager;
    }

    public TrustManagerFactory getTrustManagerFactory() {
        return trustManagerFactory;
    }

    public X509Certificate[] getTrustedCertificates() {
        return Optional.ofNullable(trustManager)
                .map(X509TrustManager::getAcceptedIssuers)
                .orElse(new X509Certificate[]{});
    }

    public HostnameVerifier getHostnameVerifier() {
        return hostnameVerifier;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {

        private static final String TRUST_STORE_VALIDATION_EXCEPTION_MESSAGE = "TrustStore details are empty, which are required to be present when SSL/TLS is enabled";
        private static final String TRUST_STRATEGY_VALIDATION_EXCEPTION_MESSAGE = "Trust strategy is missing. Please validate if the TrustStore is present, "
                + "or including default JDK trustStore is enabled or "
                + "trusting all certificates without validation is enabled";

        private static final String IDENTITY_VALIDATION_EXCEPTION_MESSAGE = "Identity details are empty, which are required to be present when SSL/TLS is enabled";
        private static final String KEY_STORE_LOADING_EXCEPTION = "Failed to load the keystore";

        private String protocol = "TLSv1.2";
        private boolean hostnameVerifierEnabled = true;

        private final List<KeyStoreHolder> identities = new ArrayList<>();
        private final List<KeyStoreHolder> trustStores = new ArrayList<>();
        private final List<X509KeyManager> identityManagers = new ArrayList<>();
        private final List<X509TrustManager> trustManagers = new ArrayList<>();

        private boolean oneWayAuthenticationEnabled;
        private boolean twoWayAuthenticationEnabled;
        private boolean includeDefaultJdkTrustStore = false;
        private boolean trustingAllCertificatesWithoutValidationEnabled = false;

        private Builder() {}

        public Builder withDefaultJdkTrustStore() {
            this.includeDefaultJdkTrustStore = true;
            this.oneWayAuthenticationEnabled = true;
            return this;
        }

        public Builder withTrustManager(X509TrustManager trustManager) {
            trustManagers.add(trustManager);
            this.oneWayAuthenticationEnabled = true;
            return this;
        }

        public Builder withTrustStore(String trustStorePath, char[] trustStorePassword) {
            return withTrustStore(trustStorePath, trustStorePassword, KeyStore.getDefaultType());
        }

        public Builder withTrustStore(String trustStorePath, char[] trustStorePassword, String trustStoreType) {
            if (isBlank(trustStorePath) || isEmpty(trustStorePassword)) {
                throw new GenericKeyStoreException(TRUST_STORE_VALIDATION_EXCEPTION_MESSAGE);
            }

            try {
                KeyStore trustStore = KeyStoreUtils.loadKeyStore(trustStorePath, trustStorePassword, trustStoreType);
                KeyStoreHolder trustStoreHolder = new KeyStoreHolder(trustStore, trustStorePassword);
                trustStores.add(trustStoreHolder);
            } catch (IOException | KeyStoreException | NoSuchAlgorithmException | CertificateException e) {
                throw new GenericKeyStoreException(KEY_STORE_LOADING_EXCEPTION, e);
            }

            this.oneWayAuthenticationEnabled = true;
            return this;
        }

        public Builder withTrustStore(Path trustStorePath, char[] trustStorePassword) {
            return withTrustStore(trustStorePath, trustStorePassword, KeyStore.getDefaultType());
        }

        public Builder withTrustStore(Path trustStorePath, char[] trustStorePassword, String trustStoreType) {
            if (isNull(trustStorePath) || isEmpty(trustStorePassword) || isBlank(trustStoreType)) {
                throw new GenericKeyStoreException(TRUST_STORE_VALIDATION_EXCEPTION_MESSAGE);
            }

            try {
                KeyStore trustStore = KeyStoreUtils.loadKeyStore(trustStorePath, trustStorePassword, trustStoreType);
                KeyStoreHolder trustStoreHolder = new KeyStoreHolder(trustStore, trustStorePassword);
                trustStores.add(trustStoreHolder);
            } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
                throw new GenericKeyStoreException(KEY_STORE_LOADING_EXCEPTION, e);
            }

            this.oneWayAuthenticationEnabled = true;
            return this;
        }

        public Builder withTrustStore(KeyStore trustStore, char[] trustStorePassword) {
            validateKeyStore(trustStore, trustStorePassword, TRUST_STORE_VALIDATION_EXCEPTION_MESSAGE);
            KeyStoreHolder trustStoreHolder = new KeyStoreHolder(trustStore, trustStorePassword);
            trustStores.add(trustStoreHolder);

            this.oneWayAuthenticationEnabled = true;
            return this;
        }

        public Builder withIdentity(String identityPath, char[] identityPassword) {
            return withIdentity(identityPath, identityPassword, KeyStore.getDefaultType());
        }

        public Builder withIdentity(String identityPath, char[] identityPassword, String identityType) {
            if (isBlank(identityPath) || isEmpty(identityPassword) || isBlank(identityType)) {
                throw new GenericKeyStoreException(IDENTITY_VALIDATION_EXCEPTION_MESSAGE);
            }

            try {
                KeyStore identity = KeyStoreUtils.loadKeyStore(identityPath, identityPassword, identityType);
                KeyStoreHolder identityHolder = new KeyStoreHolder(identity, identityPassword);
                identities.add(identityHolder);
                this.twoWayAuthenticationEnabled = true;
            } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
                throw new GenericKeyStoreException(KEY_STORE_LOADING_EXCEPTION, e);
            }
            return this;
        }

        public Builder withIdentity(Path identityPath, char[] identityPassword) {
            return withIdentity(identityPath, identityPassword, KeyStore.getDefaultType());
        }

        public Builder withIdentity(Path identityPath, char[] identityPassword, String identityType) {
            if (isNull(identityPath) || isEmpty(identityPassword) || isBlank(identityType)) {
                throw new GenericKeyStoreException(IDENTITY_VALIDATION_EXCEPTION_MESSAGE);
            }

            try {
                KeyStore identity = KeyStoreUtils.loadKeyStore(identityPath, identityPassword, identityType);
                KeyStoreHolder identityHolder = new KeyStoreHolder(identity, identityPassword);
                identities.add(identityHolder);
                this.twoWayAuthenticationEnabled = true;
            } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
                throw new GenericKeyStoreException(KEY_STORE_LOADING_EXCEPTION, e);
            }
            return this;
        }

        public Builder withIdentity(KeyStore identity, char[] identityPassword) {
            validateKeyStore(identity, identityPassword, IDENTITY_VALIDATION_EXCEPTION_MESSAGE);
            KeyStoreHolder identityHolder = new KeyStoreHolder(identity, identityPassword);
            identities.add(identityHolder);
            this.twoWayAuthenticationEnabled = true;
            return this;
        }

        public Builder withKeyManager(X509KeyManager keyManager) {
            identityManagers.add(keyManager);
            this.twoWayAuthenticationEnabled = true;
            return this;
        }

        private void validateKeyStore(KeyStore keyStore, char[] keyStorePassword, String exceptionMessage) {
            if (isNull(keyStore) || isEmpty(keyStorePassword)) {
                throw new GenericKeyStoreException(exceptionMessage);
            }
        }

        public Builder withHostnameVerifierEnabled(boolean hostnameVerifierEnabled) {
            this.hostnameVerifierEnabled = hostnameVerifierEnabled;
            return this;
        }

        public Builder withProtocol(String protocol) {
            this.protocol = protocol;
            return this;
        }

        public Builder withTrustingAllCertificatesWithoutValidation() {
            trustingAllCertificatesWithoutValidationEnabled = true;
            oneWayAuthenticationEnabled = true;
            return this;
        }

        public SSLFactory build() {
            SSLFactory sslFactory = new SSLFactory();
            if (!oneWayAuthenticationEnabled && !twoWayAuthenticationEnabled) {
                return sslFactory;
            }

            validateTrustStore();
            buildHostnameVerifier(sslFactory);
            sslFactory.protocol = protocol;
            sslFactory.securityEnabled = true;
            sslFactory.includeDefaultJdkTrustStore = includeDefaultJdkTrustStore;
            sslFactory.trustingAllCertificatesWithoutValidationEnabled = trustingAllCertificatesWithoutValidationEnabled;

            if (twoWayAuthenticationEnabled) {
                oneWayAuthenticationEnabled = false;
            }

            buildSLLContextForOneWayAuthenticationIfEnabled(sslFactory);
            buildSLLContextForTwoWayAuthenticationIfEnabled(sslFactory);
            return sslFactory;
        }

        private void buildHostnameVerifier(SSLFactory sslFactory) {
            if (hostnameVerifierEnabled) {
                sslFactory.hostnameVerifier = new DefaultHostnameVerifier();
            } else {
                sslFactory.hostnameVerifier = new NoopHostnameVerifier();
            }
        }

        private void buildSLLContextForOneWayAuthenticationIfEnabled(SSLFactory sslFactory) {
            if (oneWayAuthenticationEnabled) {
                sslFactory.oneWayAuthenticationEnabled = true;
                sslFactory.trustStores.addAll(trustStores);
                sslFactory.trustManagers.addAll(trustManagers);
                sslFactory.createSSLContextWithTrustStore();
            }
        }

        private void buildSLLContextForTwoWayAuthenticationIfEnabled(SSLFactory sslFactory) {
            if (twoWayAuthenticationEnabled) {
                sslFactory.twoWayAuthenticationEnabled = true;
                sslFactory.identities.addAll(identities);
                sslFactory.trustStores.addAll(trustStores);
                sslFactory.identityManagers.addAll(identityManagers);
                sslFactory.trustManagers.addAll(trustManagers);
                sslFactory.createSSLContextWithKeyStoreAndTrustStore();
            }
        }

        private void validateTrustStore() {
            if (trustStores.isEmpty()
                    && trustManagers.isEmpty()
                    && !includeDefaultJdkTrustStore
                    && !trustingAllCertificatesWithoutValidationEnabled) {
                throw new GenericKeyStoreException(TRUST_STRATEGY_VALIDATION_EXCEPTION_MESSAGE);
            }
        }
    }
}
