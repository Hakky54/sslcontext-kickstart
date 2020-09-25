package nl.altindag.sslcontext;

import nl.altindag.sslcontext.exception.GenericKeyStoreException;
import nl.altindag.sslcontext.exception.GenericSSLContextException;
import nl.altindag.sslcontext.exception.GenericSecurityException;
import nl.altindag.sslcontext.keymanager.CompositeX509ExtendedKeyManager;
import nl.altindag.sslcontext.model.KeyStoreHolder;
import nl.altindag.sslcontext.trustmanager.CompositeX509ExtendedTrustManager;
import nl.altindag.sslcontext.trustmanager.UnsafeX509ExtendedTrustManager;
import nl.altindag.sslcontext.util.KeyStoreUtils;
import nl.altindag.sslcontext.util.TrustManagerUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509ExtendedTrustManager;
import java.io.IOException;
import java.nio.file.Path;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static java.util.Objects.isNull;
import static java.util.stream.Collectors.toList;

public final class SSLFactory {

    private static final Logger LOGGER = LoggerFactory.getLogger(SSLFactory.class);
    private static final char[] EMPTY_PASSWORD = {};

    private final String protocol;
    private final SecureRandom secureRandom;
    private final HostnameVerifier hostnameVerifier;

    private final List<KeyStoreHolder> identities = new ArrayList<>();
    private final List<X509ExtendedKeyManager> identityManagers = new ArrayList<>();

    private final List<KeyStoreHolder> trustStores = new ArrayList<>();
    private final List<X509ExtendedTrustManager> trustManagers = new ArrayList<>();
    private final boolean passwordCachingEnabled;

    private SSLContext sslContext;
    private CompositeX509ExtendedTrustManager trustManager;
    private CompositeX509ExtendedKeyManager keyManager;
    private List<X509Certificate> trustedCertificates;

    private List<String> supportedCiphers;
    private List<String> supportedProtocols;
    private final List<String> allowedCiphers;
    private final List<String> allowedProtocols;

    @SuppressWarnings("java:S107")
    private SSLFactory(String protocol,
                       SecureRandom secureRandom,
                       HostnameVerifier hostnameVerifier,
                       List<KeyStoreHolder> identities,
                       List<X509ExtendedKeyManager> identityManagers,
                       List<KeyStoreHolder> trustStores,
                       List<X509ExtendedTrustManager> trustManagers,
                       boolean passwordCachingEnabled,
                       List<String> allowedCiphers,
                       List<String> allowedProtocols) {

        this.protocol = protocol;
        this.secureRandom = secureRandom;
        this.hostnameVerifier = hostnameVerifier;
        this.identities.addAll(identities);
        this.identityManagers.addAll(identityManagers);
        this.trustStores.addAll(trustStores);
        this.trustManagers.addAll(trustManagers);
        this.passwordCachingEnabled = passwordCachingEnabled;
        this.allowedCiphers = allowedCiphers;
        this.allowedProtocols = allowedProtocols;
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
            sslContext = SSLContext.getInstance(protocol);
            sslContext.init(keyManagers, trustManagers, secureRandom);
        } catch (NoSuchAlgorithmException | KeyManagementException e) {
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

    public List<KeyStoreHolder> getIdentities() {
        return Collections.unmodifiableList(identities);
    }

    public List<KeyStoreHolder> getTrustStores() {
        return Collections.unmodifiableList(trustStores);
    }

    public SSLContext getSslContext() {
        return sslContext;
    }

    public Optional<X509ExtendedKeyManager> getKeyManager() {
        return Optional.ofNullable(keyManager);
    }

    public Optional<X509ExtendedTrustManager> getTrustManager() {
        return Optional.ofNullable(trustManager);
    }

    public List<X509Certificate> getTrustedCertificates() {
        if (isNull(trustedCertificates)) {
            trustedCertificates = Optional.ofNullable(trustManager)
                    .map(X509ExtendedTrustManager::getAcceptedIssuers)
                    .flatMap(x509Certificates -> Optional.of(Arrays.asList(x509Certificates)))
                    .map(Collections::unmodifiableList)
                    .orElse(Collections.emptyList());
        }
        return trustedCertificates;
    }

    public HostnameVerifier getHostnameVerifier() {
        return hostnameVerifier;
    }

    public List<String> getSupportedCiphers() {
        if (isNull(supportedCiphers)) {
            supportedCiphers = Collections.unmodifiableList(Arrays.asList(sslContext.getDefaultSSLParameters().getCipherSuites()));
        }
        return supportedCiphers;
    }

    public List<String> getSupportedProtocols() {
        if (isNull(supportedProtocols)) {
            supportedProtocols = Collections.unmodifiableList(Arrays.asList(sslContext.getDefaultSSLParameters().getProtocols()));
        }
        return supportedProtocols;
    }

    public List<String> getAllowedCiphers() {
        if (allowedCiphers.isEmpty()) {
            return getSupportedCiphers();
        } else {
            return allowedCiphers;
        }
    }

    public List<String> getAllowedProtocols() {
        if (allowedProtocols.isEmpty()) {
            return getSupportedProtocols();
        } else {
            return allowedProtocols;
        }
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

        private String protocol = "TLSv1.2";
        private SecureRandom secureRandom = null;
        private HostnameVerifier hostnameVerifier = (host, sslSession) -> host.equalsIgnoreCase(sslSession.getPeerHost());

        private final List<KeyStoreHolder> identities = new ArrayList<>();
        private final List<KeyStoreHolder> trustStores = new ArrayList<>();
        private final List<X509ExtendedKeyManager> identityManagers = new ArrayList<>();
        private final List<X509ExtendedTrustManager> trustManagers = new ArrayList<>();

        private final Set<String> allowedCiphers = new HashSet<>();
        private final Set<String> allowedProtocols = new HashSet<>();

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

        /**
         * Adds the provided cipher to the list of allowed ciphers. Duplicates will be ignored.
         * <pre>
         * NOTE: This option won't force your client/server by default to use one of the provided ciphers.
         *       It acts as a storage for your supplied allowed ciphers to use at a later moment. It is unfortunately
         *       not possible to apply the properties within the resulting {@link SSLContext}. However it is possible
         *       to modify the properties after creating a {@link SSLEngine} which also can be used to start a ssl handshake
         * </pre>
         *
         * @param   allowedCipher a single cipher
         * @return  {@link SSLFactory.Builder}
         */
        public Builder withAllowedCipher(String allowedCipher) {
            this.allowedCiphers.add(allowedCipher);
            return this;
        }

        /**
         * Adds the provided ciphers to the list of allowed ciphers. Duplicates will be ignored.
         * <pre>
         * NOTE: This option won't force your client/server by default to use one of the provided ciphers.
         *       It acts as a storage for your supplied allowed ciphers to use at a later moment. It is unfortunately
         *       not possible to apply the properties within the resulting {@link SSLContext}. However it is possible
         *       to modify the properties after creating a {@link SSLEngine} which also can be used to start a ssl handshake
         * </pre>
         *
         * @param   allowedCiphers ciphers
         * @return  {@link SSLFactory.Builder}
         */
        public Builder withAllowedCiphers(String... allowedCiphers) {
            this.allowedCiphers.addAll(Arrays.asList(allowedCiphers));
            return this;
        }

        /**
         * Adds the provided protocol to the list of allowed protocols. Duplicates will be ignored.
         * <pre>
         * NOTE: This option won't force your client/server by default to use one of the provided protocol.
         *       It acts as a storage for your supplied allowed protocols to use at a later moment. It is unfortunately
         *       not possible to apply the properties within the resulting {@link SSLContext}. However it is possible
         *       to modify the properties after creating a {@link SSLEngine}, which also can be used to start a ssl handshake
         * <pre>
         *
         * @param   allowedProtocol a single protocol
         * @return  {@link SSLFactory.Builder}
         */
        public Builder withAllowedProtocol(String allowedProtocol) {
            this.allowedProtocols.add(allowedProtocol);
            return this;
        }

        /**
         * Adds the provided protocols to the list of allowed protocols. Duplicates will be ignored.
         * <pre>
         * NOTE: This option won't force your client/server by default to use one of the provided protocol.
         *       It acts as a storage for your supplied allowed protocols to use at a later moment. It is unfortunately
         *       not possible to apply the properties within the resulting {@link SSLContext}. However it is possible
         *       to modify the properties after creating a {@link SSLEngine}, which also can be used to start a ssl handshake
         * <pre>
         *
         * @param   allowedProtocols protocols
         * @return  {@link SSLFactory.Builder}
         */
        public Builder withAllowedProtocols(String... allowedProtocols) {
            this.allowedProtocols.addAll(Arrays.asList(allowedProtocols));
            return this;
        }

        /**
         * The provided protocol will be used when creating an instance of {@link SSLContext}. The resulting {@link SSLContext}
         * instance can support different version of the security protocol even though a specific one is specified here. Some
         * clients/servers support limiting the protocols by supplying the protocol to a {@link SSLEngine}, which can be created
         * from a {@link SSLContext}. Please use {@link SSLFactory.Builder#withAllowedProtocol(String)} as a temporally storage
         * to fetch later when using for example the {@link SSLEngine}
         *
         * @param   protocol protocol to be used when creating
         * @return  {@link SSLFactory.Builder}
         */
        public Builder withProtocol(String protocol) {
            this.protocol = protocol;
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
                    protocol,
                    secureRandom,
                    hostnameVerifier,
                    identities,
                    identityManagers,
                    trustStores,
                    trustManagers,
                    passwordCachingEnabled,
                    Collections.unmodifiableList(new ArrayList<>(allowedCiphers)),
                    Collections.unmodifiableList(new ArrayList<>(allowedProtocols))
            );

            if (isIdentityMaterialPresent() && isTrustMaterialNotPresent()) {
                sslFactory.createSSLContextWithIdentityMaterial();
            }

            if (isIdentityMaterialNotPresent() && isTrustMaterialPresent()) {
                sslFactory.createSSLContextWithTrustMaterial();
            }

            if (isIdentityMaterialPresent() && isTrustMaterialPresent()) {
                sslFactory.createSSLContextWithIdentityMaterialAndTrustMaterial();
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
