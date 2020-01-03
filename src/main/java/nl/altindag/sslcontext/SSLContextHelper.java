package nl.altindag.sslcontext;

import static java.util.Objects.isNull;
import static java.util.Objects.nonNull;
import static org.apache.commons.lang3.StringUtils.isBlank;

import java.io.IOException;
import java.nio.file.Path;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import org.apache.http.conn.ssl.DefaultHostnameVerifier;
import org.apache.http.conn.ssl.NoopHostnameVerifier;

import nl.altindag.sslcontext.util.KeystoreUtils;

public class SSLContextHelper {

    private KeyStore identity;
    private String identityPassword;
    private KeyStore trustStore;
    private String trustStorePassword;

    private boolean securityEnabled;
    private boolean oneWayAuthenticationEnabled;
    private boolean twoWayAuthenticationEnabled;
    private boolean includeDefaultJdkTrustStore;

    private String protocol;
    private String trustManagerAlgorithm;
    private String keyManagerAlgorithm;

    private SSLContext sslContext;
    private CompositeX509TrustManager trustManager;
    private KeyManagerFactory keyManagerFactory;
    private HostnameVerifier hostnameVerifier;

    private SSLContextHelper() {}

    private void createSSLContextWithOnlyJdkTrustStore() {
        try {
            createSSLContext(null, getTrustManager(null));
        } catch (NoSuchAlgorithmException | KeyManagementException e) {
            throw new RuntimeException(e);
        }
    }

    private void createSSLContextWithTrustStore() {
        try {
            createSSLContext(null, getTrustManager(trustStore));
        } catch (NoSuchAlgorithmException | KeyManagementException e) {
            throw new RuntimeException(e);
        }
    }

    private void createSSLContextWithKeyStoreAndTrustStore() {
        try {
            createSSLContext(getKeyManagerFactory(identity, identityPassword).getKeyManagers(),
                             getTrustManager(trustStore));
        } catch (UnrecoverableKeyException | NoSuchAlgorithmException | KeyStoreException | KeyManagementException e) {
            throw new RuntimeException(e);
        }
    }

    private void createSSLContext(KeyManager[] keyManagers, X509TrustManager trustManager) throws NoSuchAlgorithmException, KeyManagementException {
        sslContext = SSLContext.getInstance(protocol);
        sslContext.init(keyManagers, new TrustManager[]{trustManager} , null);
    }

    private KeyManagerFactory getKeyManagerFactory(KeyStore keyStore, String keystorePassword) throws NoSuchAlgorithmException, KeyStoreException, UnrecoverableKeyException {
        keyManagerFactory = KeyManagerFactory.getInstance(keyManagerAlgorithm);
        keyManagerFactory.init(keyStore, keystorePassword.toCharArray());
        return keyManagerFactory;
    }

    private X509TrustManager getTrustManager(KeyStore trustStore) {
        if (isNull(trustStore)) {
            trustManager = CompositeX509TrustManager.builder()
                                                    .withDefaultJdkTrustStore(includeDefaultJdkTrustStore)
                                                    .build();
        } else {
            trustManager = CompositeX509TrustManager.builder()
                                                    .withDefaultJdkTrustStore(includeDefaultJdkTrustStore)
                                                    .withTrustStore(trustStore, trustManagerAlgorithm)
                                                    .build();
        }
        return trustManager;
    }

    public KeyStore getIdentity() {
        return identity;
    }

    public String getIdentityPassword() {
        return identityPassword;
    }

    public KeyStore getTrustStore() {
        return trustStore;
    }

    public String getTrustStorePassword() {
        return trustStorePassword;
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

    public KeyManagerFactory getKeyManagerFactory() {
        return keyManagerFactory;
    }

    public X509TrustManager getX509TrustManager() {
        return trustManager;
    }

    public X509Certificate[] getTrustedX509Certificate() {
        if (isNull(trustManager)) {
            throw new RuntimeException("The trusted certificates could not be provided because it is not available");
        }
        return trustManager.getAcceptedIssuers();
    }

    public HostnameVerifier getHostnameVerifier() {
        return hostnameVerifier;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {

        private static final String TRUST_STORE_VALIDATION_EXCEPTION_MESSAGE = "TrustStore details are empty, which are required to be present when SSL/TLS is enabled";
        private static final String KEY_STORE_AND_TRUST_STORE_VALIDATION_EXCEPTION_MESSAGE = "TrustStore or KeyStore details are empty, which are required to be present when SSL/TLS is enabled";

        private String protocol = "TLSv1.2";
        private String keyManagerAlgorithm = KeyManagerFactory.getDefaultAlgorithm();
        private String trustManagerAlgorithm = TrustManagerFactory.getDefaultAlgorithm();
        private boolean hostnameVerifierEnabled = true;

        private KeyStore identity;
        private String identityPassword;
        private KeyStore trustStore;
        private String trustStorePassword;

        private boolean oneWayAuthenticationEnabled;
        private boolean twoWayAuthenticationEnabled;
        private boolean includeDefaultJdkTrustStore = true;

        public Builder withoutSecurity() {
            oneWayAuthenticationEnabled = false;
            twoWayAuthenticationEnabled = false;
            return this;
        }

        public Builder withOneWayAuthentication() {
            this.oneWayAuthenticationEnabled = true;
            this.twoWayAuthenticationEnabled = false;
            trustStore = null;
            return this;
        }

        public Builder withOneWayAuthentication(String trustStorePath, String trustStorePassword) {
            return withOneWayAuthentication(trustStorePath, trustStorePassword, KeyStore.getDefaultType());
        }

        public Builder withOneWayAuthentication(String trustStorePath, String trustStorePassword, String trustStoreType) {
            if (isBlank(trustStorePath) || isBlank(trustStorePassword)) {
                throw new RuntimeException(TRUST_STORE_VALIDATION_EXCEPTION_MESSAGE);
            }

            try {
                this.trustStore = KeystoreUtils.loadKeyStore(trustStorePath, trustStorePassword, trustStoreType);
                this.trustStorePassword = trustStorePassword;
            } catch (IOException | KeyStoreException | NoSuchAlgorithmException | CertificateException e) {
                throw new RuntimeException("BOOM");
            }

            this.oneWayAuthenticationEnabled = true;
            this.twoWayAuthenticationEnabled = false;
            return this;
        }

        public Builder withOneWayAuthentication(Path trustStorePath, String trustStorePassword) {
            return withOneWayAuthentication(trustStorePath, trustStorePassword, KeyStore.getDefaultType());
        }

        public Builder withOneWayAuthentication(Path trustStorePath, String trustStorePassword, String trustStoreType) {
            if (isNull(trustStorePath) || isBlank(trustStorePassword) || isBlank(trustStoreType)) {
                throw new RuntimeException(TRUST_STORE_VALIDATION_EXCEPTION_MESSAGE);
            }

            try {
                this.trustStore = KeystoreUtils.loadKeyStore(trustStorePath, trustStorePassword, trustStoreType);
                this.trustStorePassword = trustStorePassword;
            } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
                throw new RuntimeException("BOOM");
            }

            this.oneWayAuthenticationEnabled = true;
            this.twoWayAuthenticationEnabled = false;
            return this;
        }

        public Builder withOneWayAuthentication(KeyStore trustStore, String trustStorePassword) {
            if (isNull(trustStore) || isBlank(trustStorePassword)) {
                throw new RuntimeException(TRUST_STORE_VALIDATION_EXCEPTION_MESSAGE);
            }

            this.trustStore = trustStore;
            this.trustStorePassword = trustStorePassword;
            this.oneWayAuthenticationEnabled = true;
            this.twoWayAuthenticationEnabled = false;
            return this;
        }

        public Builder withTwoWayAuthentication(String identityPath, String identityPassword, String trustStorePath, String trustStorePassword) {
            return withTwoWayAuthentication(identityPath, identityPassword, KeyStore.getDefaultType(), trustStorePath, trustStorePassword, KeyStore.getDefaultType());
        }

        public Builder withTwoWayAuthentication(String identityPath, String identityPassword, String keyStoreType,
                                                String trustStorePath, String trustStorePassword, String trustStoreType) {
            if (isBlank(identityPath) || isBlank(identityPassword) || isBlank(keyStoreType)
                    || isBlank(trustStorePath) || isBlank(trustStorePassword) || isBlank(trustStoreType)) {
                throw new RuntimeException("TrustStore or Identity details are empty, which are required to be present when SSL is enabled");
            }

            try {
                this.identity = KeystoreUtils.loadKeyStore(identityPath, identityPassword, keyStoreType);
                this.identityPassword = identityPassword;
                this.trustStore = KeystoreUtils.loadKeyStore(trustStorePath, trustStorePassword, trustStoreType);
                this.trustStorePassword = trustStorePassword;
                this.oneWayAuthenticationEnabled = false;
                this.twoWayAuthenticationEnabled = true;
            } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
                throw new RuntimeException("BOOM");
            }
            return this;
        }

        public Builder withTwoWayAuthentication(Path identityPath, String identityPassword, Path trustStorePath, String trustStorePassword) {
            return withTwoWayAuthentication(identityPath, identityPassword, KeyStore.getDefaultType(), trustStorePath, trustStorePassword, KeyStore.getDefaultType());
        }

        public Builder withTwoWayAuthentication(Path identityPath, String identityPassword, String keyStoreType, Path trustStorePath, String trustStorePassword, String trustStoreType) {
            if (isNull(identityPath) || isBlank(identityPassword) || isBlank(keyStoreType)
                    || isNull(trustStorePath) || isBlank(trustStorePassword) || isBlank(trustStoreType)) {
                throw new RuntimeException(KEY_STORE_AND_TRUST_STORE_VALIDATION_EXCEPTION_MESSAGE);
            }

            try {
                this.identity = KeystoreUtils.loadKeyStore(identityPath, trustStorePassword, trustStoreType);
                this.identityPassword = identityPassword;
                this.trustStore = KeystoreUtils.loadKeyStore(trustStorePath, trustStorePassword, trustStoreType);
                this.trustStorePassword = trustStorePassword;
                this.oneWayAuthenticationEnabled = false;
                this.twoWayAuthenticationEnabled = true;
            } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
                throw new RuntimeException("BOOM");
            }
            return this;
        }

        public Builder withTwoWayAuthentication(KeyStore identity, String identityPassword, KeyStore trustStore, String trustStorePassword) {
            if (isNull(identity) || isBlank(identityPassword)
                    || isNull(trustStore) || isBlank(trustStorePassword)) {
                throw new RuntimeException(TRUST_STORE_VALIDATION_EXCEPTION_MESSAGE);
            }

            this.identity = identity;
            this.identityPassword = identityPassword;
            this.trustStore = trustStore;
            this.trustStorePassword = trustStorePassword;
            this.oneWayAuthenticationEnabled = false;
            this.twoWayAuthenticationEnabled = true;
            return this;
        }

        public Builder withDefaultJdkTrustStore(boolean includeDefaultJdkTrustStore) {
            this.includeDefaultJdkTrustStore = includeDefaultJdkTrustStore;
            this.oneWayAuthenticationEnabled = true;
            return this;
        }

        public Builder withHostnameVerifierEnabled(boolean hostnameVerifierEnabled) {
            this.hostnameVerifierEnabled = hostnameVerifierEnabled;
            return this;
        }

        public Builder withProtocol(String protocol) {
            this.protocol = protocol;
            return this;
        }

        public Builder withKeyManagerAlgorithm(String keyManagerAlgorithm) {
            this.keyManagerAlgorithm = keyManagerAlgorithm;
            return this;
        }

        public Builder withTrustManagerAlgorithm(String trustManagerAlgorithm) {
            this.trustManagerAlgorithm = trustManagerAlgorithm;
            return this;
        }

        public SSLContextHelper build() {
            SSLContextHelper sslContextHelper = new SSLContextHelper();
            buildHostnameVerifier(sslContextHelper);
            sslContextHelper.protocol = protocol;
            sslContextHelper.keyManagerAlgorithm = keyManagerAlgorithm;
            sslContextHelper.trustManagerAlgorithm = trustManagerAlgorithm;
            sslContextHelper.includeDefaultJdkTrustStore = includeDefaultJdkTrustStore;

            if (oneWayAuthenticationEnabled || twoWayAuthenticationEnabled) {
                sslContextHelper.securityEnabled = true;
                buildSLLContextForOneWayAuthenticationIfEnabled(sslContextHelper);
                buildSLLContextForTwoWayAuthenticationIfEnabled(sslContextHelper);
            }
            return sslContextHelper;
        }

        private void buildHostnameVerifier(SSLContextHelper sslContextHelper) {
            if (hostnameVerifierEnabled) {
                sslContextHelper.hostnameVerifier = new DefaultHostnameVerifier();
            } else {
                sslContextHelper.hostnameVerifier = new NoopHostnameVerifier();
            }
        }

        private void buildSLLContextForTwoWayAuthenticationIfEnabled(SSLContextHelper sslContextHelper) {
            if (twoWayAuthenticationEnabled) {
                sslContextHelper.twoWayAuthenticationEnabled = true;
                sslContextHelper.identity = identity;
                sslContextHelper.identityPassword = identityPassword;
                sslContextHelper.trustStore = trustStore;
                sslContextHelper.trustStorePassword = trustStorePassword;
                sslContextHelper.createSSLContextWithKeyStoreAndTrustStore();
            }
        }

        private void buildSLLContextForOneWayAuthenticationIfEnabled(SSLContextHelper sslContextHelper) {
            if (oneWayAuthenticationEnabled) {
                sslContextHelper.oneWayAuthenticationEnabled = true;
                if (nonNull(trustStore)) {
                    sslContextHelper.trustStore = trustStore;
                    sslContextHelper.trustStorePassword = trustStorePassword;
                    sslContextHelper.createSSLContextWithTrustStore();
                } else {
                    sslContextHelper.createSSLContextWithOnlyJdkTrustStore();
                }
            }
        }

    }

}
