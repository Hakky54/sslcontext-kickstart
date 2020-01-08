package nl.altindag.sslcontext;

import static java.nio.file.StandardCopyOption.REPLACE_EXISTING;
import static org.apache.commons.lang3.StringUtils.EMPTY;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import javax.security.auth.x500.X500Principal;

import org.apache.http.conn.ssl.DefaultHostnameVerifier;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.junit.Test;

import nl.altindag.sslcontext.exception.GenericKeyStoreException;
import nl.altindag.sslcontext.trustmanager.CompositeX509TrustManager;
import nl.altindag.sslcontext.util.KeystoreUtils;

@SuppressWarnings({ "squid:S1192", "squid:S2068"})
public class SSLContextHelperShould {

    private static final String GENERIC_IDENTITY_VALIDATION_EXCEPTION_MESSAGE = "Identity details are empty, which are required to be present when SSL/TLS is enabled";
    private static final String GENERIC_TRUSTSTORE_VALIDATION_EXCEPTION_MESSAGE = "TrustStore details are empty, which are required to be present when SSL/TLS is enabled";
    private static final String GENERIC_TRUST_STRATEGY_VALIDATION_EXCEPTION_MESSAGE = "Trust strategy is missing. Please validate if the TrustStore is present, or default including the JDK trustStore is enabled or trusting all certificates without validation is enabled";

    private static final String IDENTITY_FILE_NAME = "identity.jks";
    private static final String TRUSTSTORE_FILE_NAME = "truststore.jks";

    private static final String IDENTITY_PASSWORD = "secret";
    private static final String TRUSTSTORE_PASSWORD = "secret";
    private static final String KEYSTORE_LOCATION = "keystores-for-unit-tests/";
    private static final String TEMPORALLY_KEYSTORE_LOCATION = System.getProperty("user.home");

    @Test
    public void createSSLContextForOneWayAuthentication() {
        SSLContextHelper sslContextHelper = SSLContextHelper.builder()
                                                            .withTrustStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD)
                                                            .build();

        assertThat(sslContextHelper.isSecurityEnabled()).isTrue();
        assertThat(sslContextHelper.isOneWayAuthenticationEnabled()).isTrue();
        assertThat(sslContextHelper.isTwoWayAuthenticationEnabled()).isFalse();
        assertThat(sslContextHelper.getSslContext()).isNotNull();

        assertThat(sslContextHelper.getX509TrustManager()).isNotNull();
        assertThat(sslContextHelper.getTrustedX509Certificate()).isNotEmpty();
        assertThat(sslContextHelper.getTrustStore()).isNotNull();
        assertThat(sslContextHelper.getX509TrustManager()).isNotNull();
        assertThat(sslContextHelper.getTrustManagerFactory()).isNotNull();
        assertThat(sslContextHelper.getHostnameVerifier()).isNotNull();
    }

    @Test
    public void createSSLContextForOneWayAuthenticationWithPath() throws IOException {
        Path trustStorePath = copyKeystoreToHomeDirectory(KEYSTORE_LOCATION, TRUSTSTORE_FILE_NAME);

        SSLContextHelper sslContextHelper = SSLContextHelper.builder()
                                                            .withTrustStore(trustStorePath, TRUSTSTORE_PASSWORD)
                                                            .build();

        assertThat(sslContextHelper.isSecurityEnabled()).isTrue();
        assertThat(sslContextHelper.isOneWayAuthenticationEnabled()).isTrue();
        assertThat(sslContextHelper.isTwoWayAuthenticationEnabled()).isFalse();
        assertThat(sslContextHelper.getSslContext()).isNotNull();

        assertThat(sslContextHelper.getX509TrustManager()).isNotNull();
        assertThat(sslContextHelper.getTrustedX509Certificate()).isNotEmpty();
        assertThat(sslContextHelper.getTrustStore()).isNotNull();
        assertThat(sslContextHelper.getX509TrustManager()).isNotNull();
        assertThat(sslContextHelper.getTrustManagerFactory()).isNotNull();
        assertThat(sslContextHelper.getHostnameVerifier()).isNotNull();

        Files.delete(trustStorePath);
    }

    @Test
    public void createSSLContextForOneWayAuthenticationWithKeyStore() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore trustStore = KeystoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);

        SSLContextHelper sslContextHelper = SSLContextHelper.builder()
                                                            .withTrustStore(trustStore, TRUSTSTORE_PASSWORD)
                                                            .build();

        assertThat(sslContextHelper.isSecurityEnabled()).isTrue();
        assertThat(sslContextHelper.isOneWayAuthenticationEnabled()).isTrue();
        assertThat(sslContextHelper.isTwoWayAuthenticationEnabled()).isFalse();
        assertThat(sslContextHelper.getSslContext()).isNotNull();

        assertThat(sslContextHelper.getX509TrustManager()).isNotNull();
        assertThat(sslContextHelper.getTrustedX509Certificate()).isNotEmpty();
        assertThat(sslContextHelper.getTrustStore()).isNotNull();
        assertThat(sslContextHelper.getX509TrustManager()).isNotNull();
        assertThat(sslContextHelper.getTrustManagerFactory()).isNotNull();
        assertThat(sslContextHelper.getHostnameVerifier()).isNotNull();
    }

    @Test
    public void createSSLContextForOneWayAuthenticationWithOnlyJdkTrustedCertificates() {
        SSLContextHelper sslContextHelper = SSLContextHelper.builder()
                                                            .withDefaultJdkTrustStore()
                                                            .build();

        assertThat(sslContextHelper.isSecurityEnabled()).isTrue();
        assertThat(sslContextHelper.getX509TrustManager()).isNotNull();
        assertThat(sslContextHelper.getTrustStore()).isNull();
        assertThat(sslContextHelper.getTrustStorePassword()).isNull();
        assertThat(sslContextHelper.getTrustManagerFactory()).isNotNull();
        assertThat(sslContextHelper.getTrustedX509Certificate()).hasSizeGreaterThan(10);
    }

    @Test
    public void createSSLContextForOneWayAuthenticationWithJdkTrustedCertificatesAndCustomTrustStore() {
        SSLContextHelper sslContextHelper = SSLContextHelper.builder()
                                                            .withTrustStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD)
                                                            .withDefaultJdkTrustStore()
                                                            .build();

        assertThat(sslContextHelper.isSecurityEnabled()).isTrue();
        assertThat(sslContextHelper.getX509TrustManager()).isNotNull();
        assertThat(sslContextHelper.getTrustStore()).isNotNull();
        assertThat(sslContextHelper.getTrustStorePassword()).isEqualTo(TRUSTSTORE_PASSWORD);
        assertThat(sslContextHelper.getTrustedX509Certificate()).hasSizeGreaterThan(10);
        assertThat(sslContextHelper.getTrustManagerFactory()).isNotNull();
        assertThat(Arrays.stream(sslContextHelper.getTrustedX509Certificate())
                         .map(X509Certificate::getSubjectX500Principal)
                         .map(X500Principal::toString)).contains("CN=*.google.com, O=Google LLC, L=Mountain View, ST=California, C=US");
    }

    @Test
    public void createSSLContextForTwoWayAuthentication() {
        SSLContextHelper sslContextHelper = SSLContextHelper.builder()
                                                            .withIdentity(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD)
                                                            .withTrustStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD)
                                                            .build();

        assertThat(sslContextHelper.isSecurityEnabled()).isTrue();
        assertThat(sslContextHelper.isOneWayAuthenticationEnabled()).isFalse();
        assertThat(sslContextHelper.isTwoWayAuthenticationEnabled()).isTrue();
        assertThat(sslContextHelper.getSslContext()).isNotNull();

        assertThat(sslContextHelper.getKeyManagerFactory()).isNotNull();
        assertThat(sslContextHelper.getKeyManagerFactory().getKeyManagers()).isNotEmpty();
        assertThat(sslContextHelper.getIdentity()).isNotNull();
        assertThat(sslContextHelper.getIdentityPassword()).isEqualTo(IDENTITY_PASSWORD);

        assertThat(sslContextHelper.getX509TrustManager()).isNotNull();
        assertThat(sslContextHelper.getTrustedX509Certificate()).isNotEmpty();
        assertThat(sslContextHelper.getTrustStore()).isNotNull();
        assertThat(sslContextHelper.getTrustStorePassword()).isEqualTo(TRUSTSTORE_PASSWORD);
        assertThat(sslContextHelper.getX509TrustManager()).isNotNull();
        assertThat(sslContextHelper.getTrustManagerFactory()).isNotNull();
        assertThat(sslContextHelper.getHostnameVerifier()).isNotNull();
    }

    @Test
    public void createSSLContextForTwoWayAuthenticationWithOnlyJdkTrustedCertificates() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore identity = KeystoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);
        SSLContextHelper sslContextHelper = SSLContextHelper.builder()
                                                            .withIdentity(identity, IDENTITY_PASSWORD)
                                                            .withDefaultJdkTrustStore()
                                                            .build();

        assertThat(sslContextHelper.isSecurityEnabled()).isTrue();
        assertThat(sslContextHelper.isOneWayAuthenticationEnabled()).isFalse();
        assertThat(sslContextHelper.isTwoWayAuthenticationEnabled()).isTrue();
        assertThat(sslContextHelper.getSslContext()).isNotNull();

        assertThat(sslContextHelper.getKeyManagerFactory()).isNotNull();
        assertThat(sslContextHelper.getKeyManagerFactory().getKeyManagers()).isNotEmpty();
        assertThat(sslContextHelper.getIdentity()).isNotNull();
        assertThat(sslContextHelper.getIdentityPassword()).isEqualTo(IDENTITY_PASSWORD);

        assertThat(sslContextHelper.getX509TrustManager()).isNotNull();
        assertThat(sslContextHelper.getTrustedX509Certificate()).isNotEmpty();
        assertThat(sslContextHelper.getTrustStore()).isNull();
        assertThat(sslContextHelper.getTrustStorePassword()).isNull();
        assertThat(sslContextHelper.getX509TrustManager()).isNotNull();
        assertThat(sslContextHelper.getTrustManagerFactory()).isNotNull();
        assertThat(sslContextHelper.getHostnameVerifier()).isNotNull();
    }

    @Test
    public void createSSLContextForTwoWayAuthenticationWithPath() throws IOException {
        Path identityPath = copyKeystoreToHomeDirectory(KEYSTORE_LOCATION, IDENTITY_FILE_NAME);
        Path trustStorePath = copyKeystoreToHomeDirectory(KEYSTORE_LOCATION, TRUSTSTORE_FILE_NAME);

        SSLContextHelper sslContextHelper = SSLContextHelper.builder()
                                                            .withIdentity(identityPath, IDENTITY_PASSWORD)
                                                            .withTrustStore(trustStorePath, TRUSTSTORE_PASSWORD)
                                                            .build();

        assertThat(sslContextHelper.isSecurityEnabled()).isTrue();
        assertThat(sslContextHelper.isOneWayAuthenticationEnabled()).isFalse();
        assertThat(sslContextHelper.isTwoWayAuthenticationEnabled()).isTrue();
        assertThat(sslContextHelper.getSslContext()).isNotNull();

        assertThat(sslContextHelper.getKeyManagerFactory()).isNotNull();
        assertThat(sslContextHelper.getKeyManagerFactory().getKeyManagers()).isNotEmpty();
        assertThat(sslContextHelper.getIdentity()).isNotNull();
        assertThat(sslContextHelper.getIdentityPassword()).isEqualTo(IDENTITY_PASSWORD);

        assertThat(sslContextHelper.getX509TrustManager()).isNotNull();
        assertThat(sslContextHelper.getTrustedX509Certificate()).isNotEmpty();
        assertThat(sslContextHelper.getTrustStore()).isNotNull();
        assertThat(sslContextHelper.getTrustStorePassword()).isEqualTo(TRUSTSTORE_PASSWORD);
        assertThat(sslContextHelper.getX509TrustManager()).isNotNull();
        assertThat(sslContextHelper.getTrustManagerFactory()).isNotNull();
        assertThat(sslContextHelper.getHostnameVerifier()).isNotNull();

        Files.delete(identityPath);
        Files.delete(trustStorePath);
    }

    @Test
    public void createSSLContextForTwoWayAuthenticationWithKeyStore() throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException {
        KeyStore identity = KeystoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);
        KeyStore trustStore = KeystoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);

        SSLContextHelper sslContextHelper = SSLContextHelper.builder()
                                                            .withIdentity(identity, IDENTITY_PASSWORD)
                                                            .withTrustStore(trustStore, TRUSTSTORE_PASSWORD)
                                                            .build();

        assertThat(sslContextHelper.isSecurityEnabled()).isTrue();
        assertThat(sslContextHelper.isOneWayAuthenticationEnabled()).isFalse();
        assertThat(sslContextHelper.isTwoWayAuthenticationEnabled()).isTrue();
        assertThat(sslContextHelper.getSslContext()).isNotNull();

        assertThat(sslContextHelper.getKeyManagerFactory()).isNotNull();
        assertThat(sslContextHelper.getKeyManagerFactory().getKeyManagers()).isNotEmpty();
        assertThat(sslContextHelper.getIdentity()).isNotNull();
        assertThat(sslContextHelper.getIdentityPassword()).isEqualTo(IDENTITY_PASSWORD);

        assertThat(sslContextHelper.getX509TrustManager()).isNotNull();
        assertThat(sslContextHelper.getTrustedX509Certificate()).isNotEmpty();
        assertThat(sslContextHelper.getTrustStore()).isNotNull();
        assertThat(sslContextHelper.getTrustStorePassword()).isEqualTo(TRUSTSTORE_PASSWORD);
        assertThat(sslContextHelper.getX509TrustManager()).isNotNull();
        assertThat(sslContextHelper.getTrustManagerFactory()).isNotNull();
        assertThat(sslContextHelper.getHostnameVerifier()).isNotNull();
    }

    @Test
    public void createSSLContextHelperWithHostnameVerifier() {
        SSLContextHelper sslContextHelper = SSLContextHelper.builder()
                                                            .withTrustStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD)
                                                            .withHostnameVerifierEnabled(true)
                                                            .build();

        assertThat(sslContextHelper.getHostnameVerifier()).isInstanceOf(DefaultHostnameVerifier.class);
    }

    @Test
    public void createSSLContextHelperWithoutHostnameVerifier() {
        SSLContextHelper sslContextHelper = SSLContextHelper.builder()
                                                            .withTrustStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD)
                                                            .withHostnameVerifierEnabled(false)
                                                            .build();

        assertThat(sslContextHelper.getHostnameVerifier()).isInstanceOf(NoopHostnameVerifier.class);
    }

    @Test
    public void createSSLContextWithTlsProtocolVersionOneDotOne() {
        SSLContextHelper sslContextHelper = SSLContextHelper.builder()
                                                            .withTrustStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD)
                                                            .withProtocol("TLSv1.1")
                                                            .build();

        assertThat(sslContextHelper.getSslContext()).isNotNull();
        assertThat(sslContextHelper.getSslContext().getProtocol()).isEqualTo("TLSv1.1");
    }

    @Test
    public void createSSLContextWithTrustingAllCertificatesWithoutValidation() {
        SSLContextHelper sslContextHelper = SSLContextHelper.builder()
                                                            .withTrustingAllCertificatesWithoutValidation()
                                                            .build();

        assertThat(sslContextHelper.getSslContext()).isNotNull();
        assertThat(sslContextHelper.getTrustedX509Certificate()).isEmpty();
        assertThat(sslContextHelper.getTrustStore()).isNull();
        assertThat(sslContextHelper.getTrustStorePassword()).isNull();
        assertThat(sslContextHelper.getX509TrustManager()).isInstanceOf(CompositeX509TrustManager.class);
        assertThat(sslContextHelper.getTrustManagerFactory()).isNotNull();
    }

    @Test
    public void throwExceptionWhenCreateSSLContextForOneWayAuthenticationWhileProvidingWrongPassword() {
        assertThatThrownBy(() -> SSLContextHelper.builder().withTrustStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, "password"))
                .isInstanceOf(GenericKeyStoreException.class)
                .hasMessage("Failed to load the keystore");
    }

    @Test
    public void throwExceptionWhenCreateSSLContextForOneWayAuthenticationWithPathWhileProvidingWrongPassword() throws IOException {
        Path trustStorePath = copyKeystoreToHomeDirectory(KEYSTORE_LOCATION, TRUSTSTORE_FILE_NAME);

        assertThatThrownBy(() -> SSLContextHelper.builder().withTrustStore(trustStorePath, "password"))
                .isInstanceOf(GenericKeyStoreException.class)
                .hasMessage("Failed to load the keystore");

        Files.delete(trustStorePath);
    }

    @Test
    public void throwExceptionWhenCreateSSLContextForTwoWayAuthenticationWhileProvidingWrongPassword() {
        assertThatThrownBy(() -> SSLContextHelper.builder().withIdentity(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, "password"))
                .isInstanceOf(GenericKeyStoreException.class)
                .hasMessage("Failed to load the keystore");
    }

    @Test
    public void throwExceptionWhenCreateSSLContextForTwoWayAuthenticationWithPathWhileProvidingWrongPassword() throws IOException {
        Path identityPath = copyKeystoreToHomeDirectory(KEYSTORE_LOCATION, IDENTITY_FILE_NAME);

        assertThatThrownBy(() -> SSLContextHelper.builder().withIdentity(identityPath, "password"))
                .isInstanceOf(GenericKeyStoreException.class)
                .hasMessage("Failed to load the keystore");

        Files.delete(identityPath);
    }

    @Test
    public void throwExceptionWhenCreateSSLContextForOneWayAuthenticationWithNullAsTrustStorePath() {
        assertThatThrownBy(() -> SSLContextHelper.builder().withTrustStore((Path) null, "secret"))
                .isInstanceOf(GenericKeyStoreException.class)
                .hasMessage(GENERIC_TRUSTSTORE_VALIDATION_EXCEPTION_MESSAGE);
    }

    @Test
    public void throwExceptionWhenCreateSSLContextForOneWayAuthenticationWithEmptyTrustStorePassword() throws IOException {
        Path trustStorePath = copyKeystoreToHomeDirectory(KEYSTORE_LOCATION, TRUSTSTORE_FILE_NAME);

        assertThatThrownBy(() -> SSLContextHelper.builder().withTrustStore(trustStorePath, EMPTY))
                .isInstanceOf(GenericKeyStoreException.class)
                .hasMessage(GENERIC_TRUSTSTORE_VALIDATION_EXCEPTION_MESSAGE);

        Files.delete(trustStorePath);
    }

    @Test
    public void throwExceptionWhenCreateSSLContextForOneWayAuthenticationWithEmptyTrustStoreType() throws IOException {
        Path trustStorePath = copyKeystoreToHomeDirectory(KEYSTORE_LOCATION, TRUSTSTORE_FILE_NAME);

        assertThatThrownBy(() -> SSLContextHelper.builder().withTrustStore(trustStorePath, TRUSTSTORE_PASSWORD, EMPTY))
                .isInstanceOf(GenericKeyStoreException.class)
                .hasMessage(GENERIC_TRUSTSTORE_VALIDATION_EXCEPTION_MESSAGE);

        Files.delete(trustStorePath);
    }

    @Test
    public void throwExceptionWhenCreateSSLContextForOneWayAuthenticationWithNullAsTrustStore() {
        assertThatThrownBy(() -> SSLContextHelper.builder().withTrustStore((KeyStore) null, TRUSTSTORE_PASSWORD))
                .isInstanceOf(GenericKeyStoreException.class)
                .hasMessage(GENERIC_TRUSTSTORE_VALIDATION_EXCEPTION_MESSAGE);
    }

    @Test
    public void throwExceptionWhenCreateSSLContextForOneWayAuthenticationWithEmptyTrustStorePasswordWhileUsingKeyStoreObject() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore trustStore = KeystoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);

        assertThatThrownBy(() -> SSLContextHelper.builder().withTrustStore(trustStore, EMPTY))
                .isInstanceOf(GenericKeyStoreException.class)
                .hasMessage(GENERIC_TRUSTSTORE_VALIDATION_EXCEPTION_MESSAGE);
    }


    @Test
    public void throwExceptionWhenKeyStoreFileIsNotFound() {
        assertThatThrownBy(() -> SSLContextHelper.builder().withTrustStore(KEYSTORE_LOCATION + "not-existing-truststore.jks", TRUSTSTORE_PASSWORD))
                .isInstanceOf(GenericKeyStoreException.class)
                .hasMessage("Failed to load the keystore");
    }

    @Test
    public void throwExceptionOneWayAuthenticationIsEnabledWhileTrustStorePathIsNotProvided() {
        assertThatThrownBy(() -> SSLContextHelper.builder().withTrustStore(EMPTY, TRUSTSTORE_PASSWORD))
                .isInstanceOf(GenericKeyStoreException.class)
                .hasMessage(GENERIC_TRUSTSTORE_VALIDATION_EXCEPTION_MESSAGE);
    }

    @Test
    public void throwExceptionOneWayAuthenticationIsEnabledWhileTrustStorePasswordIsNotProvided() {
        assertThatThrownBy(() -> SSLContextHelper.builder().withTrustStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, EMPTY))
                .isInstanceOf(GenericKeyStoreException.class)
                .hasMessage(GENERIC_TRUSTSTORE_VALIDATION_EXCEPTION_MESSAGE);
    }

    @Test
    public void throwExceptionTwoWayAuthenticationEnabledWhileIdentityPathIsNotProvided() {
        assertThatThrownBy(() -> SSLContextHelper.builder().withIdentity(EMPTY, IDENTITY_PASSWORD))
                .isInstanceOf(GenericKeyStoreException.class)
                .hasMessage(GENERIC_IDENTITY_VALIDATION_EXCEPTION_MESSAGE);
    }

    @Test
    public void throwExceptionTwoWayAuthenticationEnabledWhileIdentityPasswordIsNotProvided() {
        assertThatThrownBy(() -> SSLContextHelper.builder().withIdentity(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, EMPTY))
                .isInstanceOf(GenericKeyStoreException.class)
                .hasMessage(GENERIC_IDENTITY_VALIDATION_EXCEPTION_MESSAGE);
    }

    @Test
    public void throwExceptionTwoWayAuthenticationEnabledWhileIdentityTypeIsNotProvided() {
        assertThatThrownBy(() -> SSLContextHelper.builder().withIdentity(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD, EMPTY))
                .isInstanceOf(GenericKeyStoreException.class)
                .hasMessage(GENERIC_IDENTITY_VALIDATION_EXCEPTION_MESSAGE);
    }

    @Test
    public void throwExceptionTwoWayAuthenticationEnabledWhileIdentityPathIsNull() {
        assertThatThrownBy(() -> SSLContextHelper.builder().withIdentity((Path) null, IDENTITY_PASSWORD))
                .isInstanceOf(GenericKeyStoreException.class)
                .hasMessage(GENERIC_IDENTITY_VALIDATION_EXCEPTION_MESSAGE);
    }

    @Test
    public void throwExceptionTwoWayAuthenticationEnabledWhileIdentityPasswordIsNotProvidedWhileUsingPath() throws IOException {
        Path identityPath = copyKeystoreToHomeDirectory(KEYSTORE_LOCATION, IDENTITY_FILE_NAME);

        assertThatThrownBy(() -> SSLContextHelper.builder().withIdentity(identityPath, EMPTY))
                .isInstanceOf(GenericKeyStoreException.class)
                .hasMessage(GENERIC_IDENTITY_VALIDATION_EXCEPTION_MESSAGE);

        Files.delete(identityPath);
    }

    @Test
    public void throwExceptionTwoWayAuthenticationEnabledWhileIdentityIsNull() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        assertThatThrownBy(() -> SSLContextHelper.builder().withIdentity((KeyStore) null, IDENTITY_PASSWORD))
                .isInstanceOf(GenericKeyStoreException.class)
                .hasMessage(GENERIC_IDENTITY_VALIDATION_EXCEPTION_MESSAGE);
    }

    @Test
    public void throwExceptionTwoWayAuthenticationEnabledWhileIdentityPasswordIsEmptyWhileUsingKeyStoreAsObject() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore identity = KeystoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);

        assertThatThrownBy(() -> SSLContextHelper.builder().withIdentity(identity, EMPTY))
                .isInstanceOf(GenericKeyStoreException.class)
                .hasMessage(GENERIC_IDENTITY_VALIDATION_EXCEPTION_MESSAGE);
    }

    @Test
    public void throwExceptionTwoWayAuthenticationEnabledWhileIdentityTypeIsNotProvidedWhileUsingPath() throws IOException {
        Path identityPath = copyKeystoreToHomeDirectory(KEYSTORE_LOCATION, IDENTITY_FILE_NAME);

        assertThatThrownBy(() -> SSLContextHelper.builder().withIdentity(identityPath, IDENTITY_PASSWORD, EMPTY))
                .isInstanceOf(GenericKeyStoreException.class)
                .hasMessage(GENERIC_IDENTITY_VALIDATION_EXCEPTION_MESSAGE);

        Files.delete(identityPath);
    }

    @Test
    public void throwExceptionWhenCreateSSLContextForOneWayAuthenticationWhileNotIncludingTrustStoreAndJdkTrustStoreAndNotTrustingAllCertificates() {
        assertThatThrownBy(() -> SSLContextHelper.builder()
                                                 .build())
                .isInstanceOf(GenericKeyStoreException.class)
                .hasMessage(GENERIC_TRUST_STRATEGY_VALIDATION_EXCEPTION_MESSAGE);
    }

    @Test
    public void throwExceptionWhenCreateSSLContextForTwoWayAuthenticationNotTrustingAllCertificatesWhileCustomTrustStoreAndJdkTrustStoreNotPresent() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore identity = KeystoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);

        assertThatThrownBy(() -> SSLContextHelper.builder()
                                                 .withIdentity(identity, IDENTITY_PASSWORD)
                                                 .build())
                .isInstanceOf(GenericKeyStoreException.class)
                .hasMessage(GENERIC_TRUST_STRATEGY_VALIDATION_EXCEPTION_MESSAGE);
    }

    private Path copyKeystoreToHomeDirectory(String path, String fileName) throws IOException {
        try(InputStream keystoreInputStream = Thread.currentThread().getContextClassLoader().getResourceAsStream(path + fileName)) {
            Path destination = Paths.get(TEMPORALLY_KEYSTORE_LOCATION, fileName);
            Files.copy(keystoreInputStream, destination, REPLACE_EXISTING);
            return destination;
        }
    }

}
