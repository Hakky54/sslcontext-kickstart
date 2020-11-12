package nl.altindag.sslcontext;

import nl.altindag.sslcontext.exception.GenericKeyStoreException;
import nl.altindag.sslcontext.exception.GenericSSLContextException;
import nl.altindag.sslcontext.exception.GenericSecurityException;
import nl.altindag.sslcontext.keymanager.CompositeX509ExtendedKeyManager;
import nl.altindag.sslcontext.model.KeyStoreHolder;
import nl.altindag.sslcontext.socket.CompositeSSLServerSocketFactory;
import nl.altindag.sslcontext.socket.CompositeSSLSocketFactory;
import nl.altindag.sslcontext.trustmanager.CompositeX509ExtendedTrustManager;
import nl.altindag.sslcontext.trustmanager.UnsafeX509ExtendedTrustManager;
import nl.altindag.sslcontext.util.KeyStoreUtils;
import nl.altindag.sslcontext.util.TrustManagerUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509ExtendedTrustManager;
import java.io.IOException;
import java.nio.file.Path;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
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
    private CompositeSSLSocketFactory sslSocketFactory;
    private CompositeSSLServerSocketFactory sslServerSocketFactory;
    private CompositeX509ExtendedTrustManager trustManager;
    private CompositeX509ExtendedKeyManager keyManager;
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

    public Optional<X509ExtendedTrustManager> getTrustManager() {
        return Optional.ofNullable(trustManager);
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
        public static final String IDENTITY_AND_TRUST_MATERIAL_VALIDATION_EXCEPTION_MESSAGE = "Could not create instance of SSLFactory because Identity " +
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

        public Builder withTrustMaterial(X509ExtendedTrustManager trustManager) {
            trustManagers.add(trustManager);
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

        public <T extends Certificate> Builder withTrustMaterial(T... certificates) {
            try {
                KeyStore trustStore = KeyStoreUtils.createTrustStore(certificates);
                KeyStoreHolder trustStoreHolder = new KeyStoreHolder(trustStore, EMPTY_PASSWORD);
                trustStores.add(trustStoreHolder);
            } catch (CertificateException | NoSuchAlgorithmException | KeyStoreException | IOException e) {
                throw new GenericKeyStoreException(KEY_STORE_LOADING_EXCEPTION, e);
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

        public Builder withIdentityMaterial(KeyStore identityStore, char[] identityStorePassword) {
            return withIdentityMaterial(identityStore, identityStorePassword, identityStorePassword);
        }

        public Builder withIdentityMaterial(KeyStore identityStore, char[] identityStorePassword, char[] identityPassword) {
            validateKeyStore(identityStore, IDENTITY_VALIDATION_EXCEPTION_MESSAGE);
            KeyStoreHolder identityHolder = new KeyStoreHolder(identityStore, identityStorePassword, identityPassword);
            identities.add(identityHolder);
            return this;
        }

        public Builder withIdentityMaterial(X509ExtendedKeyManager keyManager) {
            identityManagers.add(keyManager);
            return this;
        }

        private void validateKeyStore(KeyStore keyStore, String exceptionMessage) {
            if (isNull(keyStore)) {
                throw new GenericKeyStoreException(exceptionMessage);
            }
        }

        public Builder withHostnameVerifier(HostnameVerifier hostnameVerifier) {
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

        /**
         * @deprecated  Will be removed with version 6.0.0 as it will provide by
         *              default the latest list of supported protocols. Currently
         *              it will create SSLContext instance with the protocol name TLS,
         *              this will result into TLSv1, TLSv1.1 and TLSv1.2 for Java 1.8.
         *              However if you are using Java 11 it will automatically include TLSv1.3
         *              therefore it doesn't make sense to explicitly set the protocol
         */
        @Deprecated
        public Builder withProtocol(String protocol) {
            this.sslContextProtocol = protocol;
            return this;
        }

        public Builder withSslContextProtocol(String sslContextProtocol) {
            this.sslContextProtocol = sslContextProtocol;
            return this;
        }

        public Builder withSecurityProvider(Provider securityProvider) {
            this.securityProvider = securityProvider;
            return this;
        }

        public Builder withSecurityProvider(String securityProviderName) {
            this.securityProviderName = securityProviderName;
            return this;
        }

        public Builder withSecureRandom(SecureRandom secureRandom) {
            this.secureRandom = secureRandom;
            return this;
        }

        public Builder withTrustingAllCertificatesWithoutValidation() {
            LOGGER.warn("UnsafeTrustManager is being used. Client/Server certificates will be accepted without validation. Please don't use this configuration at production.");
            trustManagers.add(UnsafeX509ExtendedTrustManager.INSTANCE);
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
