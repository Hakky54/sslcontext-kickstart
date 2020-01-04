package nl.altindag.sslcontext;

import static java.util.Objects.isNull;
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
    private SSLContext sslContext;
    private CompositeX509TrustManager trustManager;
    private KeyManagerFactory keyManagerFactory;
    private HostnameVerifier hostnameVerifier;

    private SSLContextHelper() {}

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
        keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
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
                                                    .withTrustStore(trustStore, TrustManagerFactory.getDefaultAlgorithm())
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
        private static final String IDENTITY_VALIDATION_EXCEPTION_MESSAGE = "Identity details are empty, which are required to be present when SSL/TLS is enabled";

        private String protocol = "TLSv1.2";
        private boolean hostnameVerifierEnabled = true;

        private KeyStore identity;
        private String identityPassword;
        private KeyStore trustStore;
        private String trustStorePassword;

        private boolean oneWayAuthenticationEnabled;
        private boolean twoWayAuthenticationEnabled;
        private boolean includeDefaultJdkTrustStore = true;

        public Builder withOnlyDefaultJdkTrustStore(boolean includeDefaultJdkTrustStore) {
            this.includeDefaultJdkTrustStore = includeDefaultJdkTrustStore;
            this.oneWayAuthenticationEnabled = true;
            return this;
        }

        public Builder withTrustStore(String trustStorePath, String trustStorePassword) {
            return withTrustStore(trustStorePath, trustStorePassword, KeyStore.getDefaultType());
        }

        public Builder withTrustStore(String trustStorePath, String trustStorePassword, String trustStoreType) {
            if (isBlank(trustStorePath) || isBlank(trustStorePassword)) {
                throw new RuntimeException(TRUST_STORE_VALIDATION_EXCEPTION_MESSAGE);
            }

            try {
                this.trustStore = KeystoreUtils.loadKeyStore((String) trustStorePath, trustStorePassword, trustStoreType);
                this.trustStorePassword = trustStorePassword;
            } catch (IOException | KeyStoreException | NoSuchAlgorithmException | CertificateException e) {
                throw new RuntimeException("BOOM");
            }

            this.oneWayAuthenticationEnabled = true;
            return this;
        }

        public Builder withTrustStore(Path trustStorePath, String trustStorePassword) {
            return withTrustStore(trustStorePath, trustStorePassword, KeyStore.getDefaultType());
        }

        public Builder withTrustStore(Path trustStorePath, String trustStorePassword, String trustStoreType) {
            if (isNull(trustStorePath) || isBlank(trustStorePassword) || isBlank(trustStoreType)) {
                throw new RuntimeException(TRUST_STORE_VALIDATION_EXCEPTION_MESSAGE);
            }

            try {
                this.trustStore = KeystoreUtils.loadKeyStore((Path) trustStorePath, trustStorePassword, trustStoreType);
                this.trustStorePassword = trustStorePassword;
            } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
                throw new RuntimeException("BOOM");
            }

            this.oneWayAuthenticationEnabled = true;
            return this;
        }

        public Builder withTrustStore(KeyStore trustStore, String trustStorePassword) {
            validateKeyStore(trustStore, trustStorePassword, TRUST_STORE_VALIDATION_EXCEPTION_MESSAGE);
            this.trustStore = trustStore;
            this.trustStorePassword = trustStorePassword;
            this.oneWayAuthenticationEnabled = true;
            return this;
        }

        public Builder withIdentity(String identityPath, String identityPassword) {
            return withIdentity(identityPath, identityPassword, KeyStore.getDefaultType());
        }

        public Builder withIdentity(String identityPath, String identityPassword, String identityType) {
            if (isBlank(identityPath) || isBlank(identityPassword) || isBlank(identityType)) {
                throw new RuntimeException(IDENTITY_VALIDATION_EXCEPTION_MESSAGE);
            }

            try {
                this.identity = KeystoreUtils.loadKeyStore((String) identityPath, identityPassword, identityType);
                this.identityPassword = identityPassword;
                this.twoWayAuthenticationEnabled = true;
            } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
                throw new RuntimeException("BOOM");
            }
            return this;
        }

        public Builder withIdentity(Path identityPath, String identityPassword) {
            return withIdentity(identityPath, identityPassword, KeyStore.getDefaultType());
        }

        public Builder withIdentity(Path identityPath, String identityPassword, String identityType) {
            if (isNull((Path) identityPath) || isBlank(identityPassword) || isBlank(identityType)) {
                throw new RuntimeException(IDENTITY_VALIDATION_EXCEPTION_MESSAGE);
            }

            try {
                this.identity = KeystoreUtils.loadKeyStore((Path) identityPath, identityPassword, identityType);
                this.identityPassword = identityPassword;
                this.twoWayAuthenticationEnabled = true;
            } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
                throw new RuntimeException("BOOM");
            }
            return this;
        }

        public Builder withIdentity(KeyStore identity, String identityPassword) {
            validateKeyStore(identity, identityPassword, IDENTITY_VALIDATION_EXCEPTION_MESSAGE);
            this.identity = identity;
            this.identityPassword = identityPassword;
            this.twoWayAuthenticationEnabled = true;
            return this;
        }

        private void validateKeyStore(KeyStore keyStore, String keyStorePassword, String exceptionMessage) {
            if (isNull(keyStore) || isBlank(keyStorePassword)) {
                throw new RuntimeException(exceptionMessage);
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

        public SSLContextHelper build() {
            SSLContextHelper sslContextHelper = new SSLContextHelper();
            buildHostnameVerifier(sslContextHelper);
            sslContextHelper.protocol = protocol;
            sslContextHelper.securityEnabled = true;
            sslContextHelper.includeDefaultJdkTrustStore = includeDefaultJdkTrustStore;

            if (twoWayAuthenticationEnabled) {
                oneWayAuthenticationEnabled = false;
            }

            buildSLLContextForOneWayAuthenticationIfEnabled(sslContextHelper);
            buildSLLContextForTwoWayAuthenticationIfEnabled(sslContextHelper);
            return sslContextHelper;
        }

        private void buildHostnameVerifier(SSLContextHelper sslContextHelper) {
            if (hostnameVerifierEnabled) {
                sslContextHelper.hostnameVerifier = new DefaultHostnameVerifier();
            } else {
                sslContextHelper.hostnameVerifier = new NoopHostnameVerifier();
            }
        }

        private void buildSLLContextForOneWayAuthenticationIfEnabled(SSLContextHelper sslContextHelper) {
            if (oneWayAuthenticationEnabled) {
                if (isNull(trustStore) && !includeDefaultJdkTrustStore) {
                    throw new RuntimeException(TRUST_STORE_VALIDATION_EXCEPTION_MESSAGE);
                }

                sslContextHelper.oneWayAuthenticationEnabled = true;
                sslContextHelper.trustStore = trustStore;
                sslContextHelper.trustStorePassword = trustStorePassword;
                sslContextHelper.createSSLContextWithTrustStore();
            }
        }

        private void buildSLLContextForTwoWayAuthenticationIfEnabled(SSLContextHelper sslContextHelper) {
            if (twoWayAuthenticationEnabled) {
                if (isNull(trustStore) && !includeDefaultJdkTrustStore) {
                    throw new RuntimeException(TRUST_STORE_VALIDATION_EXCEPTION_MESSAGE);
                }

                sslContextHelper.twoWayAuthenticationEnabled = true;
                sslContextHelper.identity = identity;
                sslContextHelper.identityPassword = identityPassword;
                sslContextHelper.trustStore = trustStore;
                sslContextHelper.trustStorePassword = trustStorePassword;
                sslContextHelper.createSSLContextWithKeyStoreAndTrustStore();
            }
        }
    }
}
