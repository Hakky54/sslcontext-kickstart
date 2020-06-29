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
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509ExtendedTrustManager;
import java.io.IOException;
import java.lang.reflect.Array;
import java.nio.file.Path;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

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
    private final boolean includeDefaultJdkTrustStore;
    private final boolean trustingAllCertificatesWithoutValidationEnabled;
    private final boolean passwordCachingEnabled;

    private SSLContext sslContext;
    private CompositeX509ExtendedTrustManager trustManager;
    private CompositeX509ExtendedKeyManager keyManager;

    @SuppressWarnings("java:S107")
    private SSLFactory(String protocol,
                       SecureRandom secureRandom,
                       HostnameVerifier hostnameVerifier,
                       List<KeyStoreHolder> identities,
                       List<X509ExtendedKeyManager> identityManagers,
                       List<KeyStoreHolder> trustStores,
                       List<X509ExtendedTrustManager> trustManagers,
                       boolean includeDefaultJdkTrustStore,
                       boolean trustingAllCertificatesWithoutValidationEnabled,
                       boolean passwordCachingEnabled) {

        this.protocol = protocol;
        this.secureRandom = secureRandom;
        this.hostnameVerifier = hostnameVerifier;
        this.identities.addAll(identities);
        this.identityManagers.addAll(identityManagers);
        this.trustStores.addAll(trustStores);
        this.trustManagers.addAll(trustManagers);
        this.includeDefaultJdkTrustStore = includeDefaultJdkTrustStore;
        this.trustingAllCertificatesWithoutValidationEnabled = trustingAllCertificatesWithoutValidationEnabled;
        this.passwordCachingEnabled = passwordCachingEnabled;
    }

    private void createSSLContextWithTrustMaterial() {
        createSSLContext(null, createTrustManagers());
    }

    private void createSSLContextWithKeyMaterialAndTrustMaterial() {
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
            List<KeyStoreHolder> sanitizedIdentities = sanitizeKeyStores(identities);
            identities.clear();
            identities.addAll(sanitizedIdentities);
        }

        return new X509ExtendedKeyManager[] {keyManager};
    }

    private TrustManager[] createTrustManagers() {
        CompositeX509ExtendedTrustManager.Builder trustManagerBuilder = CompositeX509ExtendedTrustManager.builder()
                .withTrustManagers(trustManagers)
                .withTrustStores(trustStores.stream()
                        .map(KeyStoreHolder::getKeyStore)
                        .collect(toList())
                );

        if (trustingAllCertificatesWithoutValidationEnabled) {
            LOGGER.warn("UnsafeTrustManager is being used. Client/Server certificates will be accepted without validation. Please don't use this configuration at production.");
            trustManagerBuilder.withTrustManagers(UnsafeX509ExtendedTrustManager.INSTANCE);
        }

        if (includeDefaultJdkTrustStore) {
            trustManagerBuilder.withTrustManagers(TrustManagerUtils.createTrustManagerWithJdkTrustedCertificates());
        }

        trustManager = trustManagerBuilder.build();

        if (!passwordCachingEnabled && !trustStores.isEmpty()) {
            List<KeyStoreHolder> sanitizedTrustStores = sanitizeKeyStores(trustStores);
            trustStores.clear();
            trustStores.addAll(sanitizedTrustStores);
        }
        return new TrustManager[] {trustManager};
    }

    private List<KeyStoreHolder> sanitizeKeyStores(List<KeyStoreHolder> keyStores) {
        return keyStores.stream()
                .map(keyStoreHolder -> new KeyStoreHolder(keyStoreHolder.getKeyStore(), EMPTY_PASSWORD, EMPTY_PASSWORD))
                .collect(toList());
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

    public X509ExtendedTrustManager getTrustManager() {
        return trustManager;
    }

    public X509Certificate[] getTrustedCertificates() {
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
        private static final String TRUST_STRATEGY_VALIDATION_EXCEPTION_MESSAGE = "Trust strategy is missing. Please validate if the TrustStore is present, "
                + "or including default JDK TrustStore is enabled, "
                + "or TrustManager is present, "
                + "or trusting all certificates without validation is enabled";

        private static final String IDENTITY_VALIDATION_EXCEPTION_MESSAGE = "Identity details are empty, which are required to be present when SSL/TLS is enabled";
        private static final String KEY_STORE_LOADING_EXCEPTION = "Failed to load the keystore";
        public static final String IDENTITY_AND_TRUST_MATERIAL_VALIDATION_EXCEPTION_MESSAGE = "Could not create instance of SSLFactory because Identity " +
                "and Trust material are not present. Please provide at least a Trust material.";

        private String protocol = "TLSv1.2";
        private SecureRandom secureRandom = new SecureRandom();
        private HostnameVerifier hostnameVerifier = (host, sslSession) -> host.equalsIgnoreCase(sslSession.getPeerHost());

        private final List<KeyStoreHolder> identities = new ArrayList<>();
        private final List<KeyStoreHolder> trustStores = new ArrayList<>();
        private final List<X509ExtendedKeyManager> identityManagers = new ArrayList<>();
        private final List<X509ExtendedTrustManager> trustManagers = new ArrayList<>();

        private boolean includeDefaultJdkTrustStore = false;
        private boolean trustingAllCertificatesWithoutValidationEnabled = false;
        private boolean passwordCachingEnabled = false;

        private Builder() {}

        @Deprecated
        public Builder withDefaultJdkTrustStore() {
            this.includeDefaultJdkTrustStore = true;
            return this;
        }

        public Builder withDefaultTrustMaterial() {
            this.includeDefaultJdkTrustStore = true;
            return this;
        }

        @Deprecated
        public Builder withTrustManager(X509ExtendedTrustManager trustManager) {
            trustManagers.add(trustManager);
            return this;
        }

        public Builder withTrustMaterial(X509ExtendedTrustManager trustManager) {
            trustManagers.add(trustManager);
            return this;
        }

        @Deprecated
        public Builder withTrustStore(String trustStorePath, char[] trustStorePassword) {
            return withTrustStore(trustStorePath, trustStorePassword, KeyStore.getDefaultType());
        }

        public Builder withTrustMaterial(String trustStorePath, char[] trustStorePassword) {
            return withTrustStore(trustStorePath, trustStorePassword, KeyStore.getDefaultType());
        }

        @Deprecated
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

            return this;
        }

        public Builder withTrustMaterial(String trustStorePath, char[] trustStorePassword, String trustStoreType) {
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

            return this;
        }

        @Deprecated
        public Builder withTrustStore(Path trustStorePath, char[] trustStorePassword) {
            return withTrustStore(trustStorePath, trustStorePassword, KeyStore.getDefaultType());
        }

        public Builder withTrustMaterial(Path trustStorePath, char[] trustStorePassword) {
            return withTrustStore(trustStorePath, trustStorePassword, KeyStore.getDefaultType());
        }

        @Deprecated
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

            return this;
        }

        public Builder withTrustMaterial(Path trustStorePath, char[] trustStorePassword, String trustStoreType) {
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

            return this;
        }

        @Deprecated
        public Builder withTrustStore(KeyStore trustStore, char[] trustStorePassword) {
            validateKeyStore(trustStore, trustStorePassword, TRUST_STORE_VALIDATION_EXCEPTION_MESSAGE);
            KeyStoreHolder trustStoreHolder = new KeyStoreHolder(trustStore, trustStorePassword);
            trustStores.add(trustStoreHolder);

            return this;
        }

        public Builder withTrustMaterial(KeyStore trustStore, char[] trustStorePassword) {
            validateKeyStore(trustStore, trustStorePassword, TRUST_STORE_VALIDATION_EXCEPTION_MESSAGE);
            KeyStoreHolder trustStoreHolder = new KeyStoreHolder(trustStore, trustStorePassword);
            trustStores.add(trustStoreHolder);

            return this;
        }

        @Deprecated
        public Builder withIdentity(String identityStorePath, char[] identityStorePassword) {
            return withIdentity(identityStorePath, identityStorePassword, identityStorePassword, KeyStore.getDefaultType());
        }

        public Builder withIdentityMaterial(String identityStorePath, char[] identityStorePassword) {
            return withIdentity(identityStorePath, identityStorePassword, identityStorePassword, KeyStore.getDefaultType());
        }

        @Deprecated
        public Builder withIdentity(String identityStorePath, char[] identityStorePassword, char[] identityPassword) {
            return withIdentity(identityStorePath, identityStorePassword, identityPassword, KeyStore.getDefaultType());
        }

        public Builder withIdentityMaterial(String identityStorePath, char[] identityStorePassword, char[] identityPassword) {
            return withIdentity(identityStorePath, identityStorePassword, identityPassword, KeyStore.getDefaultType());
        }

        @Deprecated
        public Builder withIdentity(String identityStorePath, char[] identityStorePassword, String identityStoreType) {
            return withIdentity(identityStorePath, identityStorePassword, identityStorePassword, identityStoreType);
        }

        public Builder withIdentityMaterial(String identityStorePath, char[] identityStorePassword, String identityStoreType) {
            return withIdentity(identityStorePath, identityStorePassword, identityStorePassword, identityStoreType);
        }

        @Deprecated
        public Builder withIdentity(String identityStorePath, char[] identityStorePassword, char[] identityPassword, String identityStoreType) {
            if (isBlank(identityStorePath) || isEmpty(identityStorePassword) || isBlank(identityStoreType)) {
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

        public Builder withIdentityMaterial(String identityStorePath, char[] identityStorePassword, char[] identityPassword, String identityStoreType) {
            if (isBlank(identityStorePath) || isEmpty(identityStorePassword) || isBlank(identityStoreType)) {
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

        @Deprecated
        public Builder withIdentity(Path identityStorePath, char[] identityStorePassword) {
            return withIdentity(identityStorePath, identityStorePassword, identityStorePassword, KeyStore.getDefaultType());
        }

        public Builder withIdentityMaterial(Path identityStorePath, char[] identityStorePassword) {
            return withIdentity(identityStorePath, identityStorePassword, identityStorePassword, KeyStore.getDefaultType());
        }

        @Deprecated
        public Builder withIdentity(Path identityStorePath, char[] identityStorePassword, char[] identityPassword) {
            return withIdentity(identityStorePath, identityStorePassword, identityPassword, KeyStore.getDefaultType());
        }

        public Builder withIdentityMaterial(Path identityStorePath, char[] identityStorePassword, char[] identityPassword) {
            return withIdentity(identityStorePath, identityStorePassword, identityPassword, KeyStore.getDefaultType());
        }

        @Deprecated
        public Builder withIdentity(Path identityStorePath, char[] identityStorePassword, String identityStoreType) {
            return withIdentity(identityStorePath, identityStorePassword, identityStorePassword, identityStoreType);
        }

        public Builder withIdentityMaterial(Path identityStorePath, char[] identityStorePassword, String identityStoreType) {
            return withIdentity(identityStorePath, identityStorePassword, identityStorePassword, identityStoreType);
        }

        @Deprecated
        public Builder withIdentity(Path identityStorePath, char[] identityStorePassword, char[] identityPassword, String identityStoreType) {
            if (isNull(identityStorePath) || isEmpty(identityStorePassword) || isBlank(identityStoreType)) {
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

        public Builder withIdentityMaterial(Path identityStorePath, char[] identityStorePassword, char[] identityPassword, String identityStoreType) {
            if (isNull(identityStorePath) || isEmpty(identityStorePassword) || isBlank(identityStoreType)) {
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

        @Deprecated
        public Builder withIdentity(KeyStore identityStore, char[] identityStorePassword) {
            return withIdentity(identityStore, identityStorePassword, identityStorePassword);
        }

        public Builder withIdentityMaterial(KeyStore identityStore, char[] identityStorePassword) {
            return withIdentity(identityStore, identityStorePassword, identityStorePassword);
        }

        @Deprecated
        public Builder withIdentity(KeyStore identityStore, char[] identityStorePassword, char[] identityPassword) {
            validateKeyStore(identityStore, identityStorePassword, IDENTITY_VALIDATION_EXCEPTION_MESSAGE);
            KeyStoreHolder identityHolder = new KeyStoreHolder(identityStore, identityStorePassword, identityPassword);
            identities.add(identityHolder);
            return this;
        }

        public Builder withIdentityMaterial(KeyStore identityStore, char[] identityStorePassword, char[] identityPassword) {
            validateKeyStore(identityStore, identityStorePassword, IDENTITY_VALIDATION_EXCEPTION_MESSAGE);
            KeyStoreHolder identityHolder = new KeyStoreHolder(identityStore, identityStorePassword, identityPassword);
            identities.add(identityHolder);
            return this;
        }

        @Deprecated
        public Builder withKeyManager(X509ExtendedKeyManager keyManager) {
            identityManagers.add(keyManager);
            return this;
        }

        public Builder withIdentityMaterial(X509ExtendedKeyManager keyManager) {
            identityManagers.add(keyManager);
            return this;
        }

        private void validateKeyStore(KeyStore keyStore, char[] keyStorePassword, String exceptionMessage) {
            if (isNull(keyStore) || isEmpty(keyStorePassword)) {
                throw new GenericKeyStoreException(exceptionMessage);
            }
        }

        public Builder withHostnameVerifier(HostnameVerifier hostnameVerifier) {
            this.hostnameVerifier = hostnameVerifier;
            return this;
        }

        public Builder withProtocol(String protocol) {
            this.protocol = protocol;
            return this;
        }

        public Builder withSecureRandom(SecureRandom secureRandom) {
            this.secureRandom = secureRandom;
            return this;
        }

        public Builder withTrustingAllCertificatesWithoutValidation() {
            trustingAllCertificatesWithoutValidationEnabled = true;
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

            if (isTrustMaterialNotPresent()) {
                throw new GenericKeyStoreException(TRUST_STRATEGY_VALIDATION_EXCEPTION_MESSAGE);
            }

            SSLFactory sslFactory = new SSLFactory(
                    protocol,
                    secureRandom,
                    hostnameVerifier,
                    identities,
                    identityManagers,
                    trustStores,
                    trustManagers,
                    includeDefaultJdkTrustStore,
                    trustingAllCertificatesWithoutValidationEnabled,
                    passwordCachingEnabled
            );

            if (isIdentityMaterialPresent() && isTrustMaterialPresent()) {
                sslFactory.createSSLContextWithKeyMaterialAndTrustMaterial();
            }

            if (isIdentityMaterialNotPresent() && isTrustMaterialPresent()) {
                sslFactory.createSSLContextWithTrustMaterial();
            }

            return sslFactory;
        }

        private boolean isTrustMaterialPresent() {
            return !trustStores.isEmpty()
                    || !trustManagers.isEmpty()
                    || includeDefaultJdkTrustStore
                    || trustingAllCertificatesWithoutValidationEnabled;
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

        private boolean isEmpty(char[] chars) {
            int length = isNull(chars) ? 0 : Array.getLength(chars);
            return length == 0;
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
