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

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManagerFactory;
import javax.security.auth.x500.X500Principal;

import org.apache.http.conn.ssl.DefaultHostnameVerifier;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.junit.Test;

import nl.altindag.sslcontext.util.KeystoreUtils;

@SuppressWarnings({"UnnecessaryLocalVariable", "squid:S1192", "squid:S2068"})
public class SSLContextHelperShould {

    private static final String GENERIC_IDENTITY_AND_TRUSTSTORE_VALIDATION_EXCEPTION_MESSAGE = "TrustStore or Identity details are empty, which are required to be present when SSL is enabled";
    private static final String GENERIC_TRUSTSTORE_VALIDATION_EXCEPTION_MESSAGE = "TrustStore details are empty, which are required to be present when SSL/TLS is enabled";

    private static final String KEYSTORE_FILE_NAME = "identity.jks";
    private static final String TRUSTSTORE_FILE_NAME = "truststore.jks";
    private static final String JCEKS_KEYSTORE_FILE_NAME = "identity.jceks";

    private static final String KEYSTORE_PASSWORD = "secret";
    private static final String TRUSTSTORE_PASSWORD = "secret";
    private static final String KEYSTORE_LOCATION = "keystores-for-unit-tests/";
    private static final String TEMPORALLY_KEYSTORE_LOCATION = System.getProperty("user.home");

    @Test
    public void createSSLContextForOneWayAuthenticationWithOnlyJdkTrustedCertificates() {
        SSLContextHelper sslContextHelper = SSLContextHelper.builder()
                                                            .withDefaultJdkTrustStore(true)
                                                            .build();

        assertThat(sslContextHelper.isSecurityEnabled()).isTrue();
        assertThat(sslContextHelper.getX509TrustManager()).isNotNull();
        assertThat(sslContextHelper.getTrustStore()).isNull();
        assertThat(sslContextHelper.getTrustStorePassword()).isNull();
        assertThat(sslContextHelper.getTrustedX509Certificate()).hasSizeGreaterThan(10);
    }

    @Test
    public void createSSLContextForOneWayAuthenticationWithoutProvidingArgumentsUsesJdkTrustedCertificates() {
        SSLContextHelper sslContextHelper = SSLContextHelper.builder()
                                                            .withOneWayAuthentication()
                                                            .build();

        assertThat(sslContextHelper.isSecurityEnabled()).isTrue();
        assertThat(sslContextHelper.getX509TrustManager()).isNotNull();
        assertThat(sslContextHelper.getTrustStore()).isNull();
        assertThat(sslContextHelper.getTrustStorePassword()).isNull();
        assertThat(sslContextHelper.getTrustedX509Certificate()).hasSizeGreaterThan(10);
    }

    @Test
    public void createSSLContextForOneWayAuthenticationWithJdkTrustedCertificatesAndCustomTrustStore() {
        SSLContextHelper sslContextHelper = SSLContextHelper.builder()
                                                            .withOneWayAuthentication(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD)
                                                            .withDefaultJdkTrustStore(true)
                                                            .build();

        assertThat(sslContextHelper.isSecurityEnabled()).isTrue();
        assertThat(sslContextHelper.getX509TrustManager()).isNotNull();
        assertThat(sslContextHelper.getTrustStore()).isNotNull();
        assertThat(sslContextHelper.getTrustStorePassword()).isEqualTo(TRUSTSTORE_PASSWORD);
        assertThat(sslContextHelper.getTrustedX509Certificate()).hasSizeGreaterThan(10);
        assertThat(Arrays.stream(sslContextHelper.getTrustedX509Certificate())
                         .map(X509Certificate::getSubjectX500Principal)
                         .map(X500Principal::toString)).contains("CN=*.google.com, O=Google LLC, L=Mountain View, ST=California, C=US");
    }

    @Test
    public void throwExceptionWhenPasswordIsWrongWhenCreatingSSLContextForOneWayAuthentication() {
        assertThatThrownBy(() -> SSLContextHelper.builder().withOneWayAuthentication(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, "password"))
                .isInstanceOf(RuntimeException.class)
                .hasMessage("BOOM");
    }

    @Test
    public void createSSLContextForTwoWayAutentication() {
        String identityPath = "keystores-for-unit-tests/identity.jks";
        String identityPassword = "secret";
        String trustStorePath = "keystores-for-unit-tests/truststore.jks";
        String trustStorePassword = "secret";

        SSLContextHelper sslContextHelper = SSLContextHelper.builder()
                                                            .withTwoWayAuthentication(identityPath, identityPassword,
                                                                                      trustStorePath, trustStorePassword)
                                                            .withKeyManagerAlgorithm(KeyManagerFactory.getDefaultAlgorithm())
                                                            .withTrustManagerAlgorithm(TrustManagerFactory.getDefaultAlgorithm())
                                                            .build();

        assertThat(sslContextHelper.isSecurityEnabled()).isTrue();
        assertThat(sslContextHelper.isOneWayAuthenticationEnabled()).isFalse();
        assertThat(sslContextHelper.isTwoWayAuthenticationEnabled()).isTrue();
        assertThat(sslContextHelper.getSslContext()).isNotNull();

        assertThat(sslContextHelper.getKeyManagerFactory()).isNotNull();
        assertThat(sslContextHelper.getKeyManagerFactory().getKeyManagers()).isNotEmpty();
        assertThat(sslContextHelper.getIdentity()).isNotNull();

        assertThat(sslContextHelper.getX509TrustManager()).isNotNull();
        assertThat(sslContextHelper.getTrustedX509Certificate()).isNotEmpty();
        assertThat(sslContextHelper.getTrustStore()).isNotNull();
        assertThat(sslContextHelper.getX509TrustManager()).isNotNull();
        assertThat(sslContextHelper.getHostnameVerifier()).isNotNull();
    }

    @Test
    public void createSSLContextForOneWayAuthentication() {
        String trustStorePath = "keystores-for-unit-tests/truststore.jks";
        String trustStorePassword = "secret";

        SSLContextHelper sslContextHelper = SSLContextHelper.builder()
                                                            .withOneWayAuthentication(trustStorePath, trustStorePassword)
                                                            .build();

        assertThat(sslContextHelper.isSecurityEnabled()).isTrue();
        assertThat(sslContextHelper.isOneWayAuthenticationEnabled()).isTrue();
        assertThat(sslContextHelper.isTwoWayAuthenticationEnabled()).isFalse();
        assertThat(sslContextHelper.getSslContext()).isNotNull();

        assertThat(sslContextHelper.getX509TrustManager()).isNotNull();
        assertThat(sslContextHelper.getTrustedX509Certificate()).isNotEmpty();
        assertThat(sslContextHelper.getTrustStore()).isNotNull();
        assertThat(sslContextHelper.getX509TrustManager()).isNotNull();
        assertThat(sslContextHelper.getHostnameVerifier()).isNotNull();
    }

    @Test
    public void createSSLContextForOneWayAuthenticationWithKeyStore() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore trustStore = KeystoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);

        SSLContextHelper sslContextHelper = SSLContextHelper.builder()
                                                            .withOneWayAuthentication(trustStore, TRUSTSTORE_PASSWORD)
                                                            .build();

        assertThat(sslContextHelper.isSecurityEnabled()).isTrue();
        assertThat(sslContextHelper.isOneWayAuthenticationEnabled()).isTrue();
        assertThat(sslContextHelper.isTwoWayAuthenticationEnabled()).isFalse();
        assertThat(sslContextHelper.getSslContext()).isNotNull();

        assertThat(sslContextHelper.getX509TrustManager()).isNotNull();
        assertThat(sslContextHelper.getTrustedX509Certificate()).isNotEmpty();
        assertThat(sslContextHelper.getTrustStore()).isNotNull();
        assertThat(sslContextHelper.getX509TrustManager()).isNotNull();
        assertThat(sslContextHelper.getHostnameVerifier()).isNotNull();
    }

    @Test
    public void createSSLContextForOneWayAuthenticationWithPath() throws IOException {
        Path trustStorePath = copyKeystoreToHomeDirectory(KEYSTORE_LOCATION, TRUSTSTORE_FILE_NAME);

        SSLContextHelper sslContextHelper = SSLContextHelper.builder()
                                                            .withOneWayAuthentication(trustStorePath, TRUSTSTORE_PASSWORD)
                                                            .build();

        assertThat(sslContextHelper.isSecurityEnabled()).isTrue();
        assertThat(sslContextHelper.isOneWayAuthenticationEnabled()).isTrue();
        assertThat(sslContextHelper.isTwoWayAuthenticationEnabled()).isFalse();
        assertThat(sslContextHelper.getSslContext()).isNotNull();

        assertThat(sslContextHelper.getX509TrustManager()).isNotNull();
        assertThat(sslContextHelper.getTrustedX509Certificate()).isNotEmpty();
        assertThat(sslContextHelper.getTrustStore()).isNotNull();
        assertThat(sslContextHelper.getX509TrustManager()).isNotNull();
        assertThat(sslContextHelper.getHostnameVerifier()).isNotNull();

        Files.delete(trustStorePath);
    }

    @Test
    public void throwExceptionWhenCreateSSLContextForOneWayAuthenticationWithPathWhileProvidingWrongPassword() throws IOException {
        Path trustStorePath = copyKeystoreToHomeDirectory(KEYSTORE_LOCATION, TRUSTSTORE_FILE_NAME);

        assertThatThrownBy(() -> SSLContextHelper.builder().withOneWayAuthentication(trustStorePath, "password"))
                .isInstanceOf(RuntimeException.class)
                .hasMessage("BOOM");

        Files.delete(trustStorePath);
    }

    @Test
    public void throwExceptionWhenCreateSSLContextForOneWayAuthenticationWithNullAsTrustStorePath() {
        assertThatThrownBy(() -> SSLContextHelper.builder().withOneWayAuthentication((Path) null, "secret"))
                .isInstanceOf(RuntimeException.class)
                .hasMessage(GENERIC_TRUSTSTORE_VALIDATION_EXCEPTION_MESSAGE);
    }

    @Test
    public void throwExceptionWhenCreateSSLContextForOneWayAuthenticationWithEmptyTrustStorePassword() throws IOException {
        Path trustStorePath = copyKeystoreToHomeDirectory(KEYSTORE_LOCATION, TRUSTSTORE_FILE_NAME);

        assertThatThrownBy(() -> SSLContextHelper.builder().withOneWayAuthentication(trustStorePath, EMPTY))
                .isInstanceOf(RuntimeException.class)
                .hasMessage(GENERIC_TRUSTSTORE_VALIDATION_EXCEPTION_MESSAGE);

        Files.delete(trustStorePath);
    }

    @Test
    public void throwExceptionWhenCreateSSLContextForOneWayAuthenticationWithEmptyTrustStoreType() throws IOException {
        Path trustStorePath = copyKeystoreToHomeDirectory(KEYSTORE_LOCATION, TRUSTSTORE_FILE_NAME);

        assertThatThrownBy(() -> SSLContextHelper.builder().withOneWayAuthentication(trustStorePath, TRUSTSTORE_PASSWORD, EMPTY))
                .isInstanceOf(RuntimeException.class)
                .hasMessage(GENERIC_TRUSTSTORE_VALIDATION_EXCEPTION_MESSAGE);

        Files.delete(trustStorePath);
    }

    @Test
    public void throwExceptionWhenCreateSSLContextForOneWayAuthenticationWithNullAsTrustStore() {
        assertThatThrownBy(() -> SSLContextHelper.builder().withOneWayAuthentication((KeyStore) null, TRUSTSTORE_PASSWORD))
                .isInstanceOf(RuntimeException.class)
                .hasMessage(GENERIC_TRUSTSTORE_VALIDATION_EXCEPTION_MESSAGE);
    }

    @Test
    public void throwExceptionWhenCreateSSLContextForOneWayAuthenticationWithEmptyTrustStorePasswordWhileUsingKeyStoreObject() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore trustStore = KeystoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);

        assertThatThrownBy(() -> SSLContextHelper.builder().withOneWayAuthentication(trustStore, EMPTY))
                .isInstanceOf(RuntimeException.class)
                .hasMessage(GENERIC_TRUSTSTORE_VALIDATION_EXCEPTION_MESSAGE);
    }

    @Test
    public void createSSLContextHelperWithHostnameVerifier() {
        String trustStorePath = "keystores-for-unit-tests/truststore.jks";
        String trustStorePassword = "secret";

        SSLContextHelper sslContextHelper = SSLContextHelper.builder()
                                                            .withOneWayAuthentication(trustStorePath, trustStorePassword)
                                                            .withHostnameVerifierEnabled(true)
                                                            .build();

        assertThat(sslContextHelper.getHostnameVerifier()).isInstanceOf(DefaultHostnameVerifier.class);
    }

    @Test
    public void createSSLContextHelperWithoutHostnameVerifier() {
        String trustStorePath = "keystores-for-unit-tests/truststore.jks";
        String trustStorePassword = "secret";

        SSLContextHelper sslContextHelper = SSLContextHelper.builder()
                                                            .withOneWayAuthentication(trustStorePath, trustStorePassword)
                                                            .withHostnameVerifierEnabled(false)
                                                            .build();

        assertThat(sslContextHelper.getHostnameVerifier()).isInstanceOf(NoopHostnameVerifier.class);
    }

    @Test
    public void createSSLContextWithTlsProtocolVersionOneDotOne() {
        String trustStorePath = "keystores-for-unit-tests/truststore.jks";
        String trustStorePassword = "secret";

        SSLContextHelper sslContextHelper = SSLContextHelper.builder()
                                                            .withOneWayAuthentication(trustStorePath, trustStorePassword)
                                                            .withProtocol("TLSv1.1")
                                                            .build();

        assertThat(sslContextHelper.getSslContext()).isNotNull();
        assertThat(sslContextHelper.getSslContext().getProtocol()).isEqualTo("TLSv1.1");
    }


    @Test
    public void throwExceptionWhenKeyStoreFileIsNotFound() {
        String trustStorePath = "keystores-for-unit-tests/not-existing-truststore.jks";
        String trustStorePassword = "secret";

        assertThatThrownBy(() -> SSLContextHelper.builder().withOneWayAuthentication(trustStorePath, trustStorePassword))
                .isInstanceOf(RuntimeException.class)
                .hasMessage("Could not find the keystore file");
    }

    @Test
    public void throwExceptionOneWayAuthenticationIsEnabledWhileTrustStorePathIsNotProvided() {
        String trustStorePath = EMPTY;
        String trustStorePassword = "secret";

        assertThatThrownBy(() -> SSLContextHelper.builder().withOneWayAuthentication(trustStorePath, trustStorePassword))
                .isInstanceOf(RuntimeException.class)
                .hasMessage(GENERIC_TRUSTSTORE_VALIDATION_EXCEPTION_MESSAGE);
    }

    @Test
    public void throwExceptionOneWayAuthenticationIsEnabledWhileTrustStorePasswordIsNotProvided() {
        String trustStorePath = "keystores-for-unit-tests/truststore.jks";
        String trustStorePassword = EMPTY;

        assertThatThrownBy(() -> SSLContextHelper.builder().withOneWayAuthentication(trustStorePath, trustStorePassword))
                .isInstanceOf(RuntimeException.class)
                .hasMessage(GENERIC_TRUSTSTORE_VALIDATION_EXCEPTION_MESSAGE);
    }

    @Test
    public void throwExceptionTwoWayAuthenticationEnabledWhileKeyStorePathIsNotProvided() {
        String identityPath = EMPTY;
        String identityPassword = "secret";
        String trustStorePath = "keystores-for-unit-tests/truststore.jks";
        String trustStorePassword = "secret";

        assertThatThrownBy(() -> SSLContextHelper.builder().withTwoWayAuthentication(identityPath, identityPassword, trustStorePath, trustStorePassword))
                .isInstanceOf(RuntimeException.class)
                .hasMessage(GENERIC_IDENTITY_AND_TRUSTSTORE_VALIDATION_EXCEPTION_MESSAGE);
    }

    @Test
    public void throwExceptionTwoWayAuthenticationEnabledWhileKeyStorePasswordIsNotProvided() {
        String identityPath = "keystores-for-unit-tests/identity.jks";
        String identityPassword = EMPTY;
        String trustStorePath = "keystores-for-unit-tests/truststore.jks";
        String trustStorePassword = "secret";

        assertThatThrownBy(() -> SSLContextHelper.builder().withTwoWayAuthentication(identityPath, identityPassword, trustStorePath, trustStorePassword))
                .isInstanceOf(RuntimeException.class)
                .hasMessage(GENERIC_IDENTITY_AND_TRUSTSTORE_VALIDATION_EXCEPTION_MESSAGE);
    }

    @Test
    public void throwExceptionTwoWayAuthenticationEnabledWhileTrustStorePathIsNotProvided() {
        String identityPath = "keystores-for-unit-tests/identity.jks";
        String identityPassword = "secret";
        String trustStorePath = EMPTY;
        String trustStorePassword = "secret";

        assertThatThrownBy(() -> SSLContextHelper.builder().withTwoWayAuthentication(identityPath, identityPassword, trustStorePath, trustStorePassword))
                .isInstanceOf(RuntimeException.class)
                .hasMessage(GENERIC_IDENTITY_AND_TRUSTSTORE_VALIDATION_EXCEPTION_MESSAGE);
    }

    @Test
    public void throwExceptionTwoWayAuthenticationEnabledWhileTrustStorePasswordIsNotProvided() {
        String identityPath = "keystores-for-unit-tests/identity.jks";
        String identityPassword = "secret";
        String trustStorePath = "keystores-for-unit-tests/truststore.jks";
        String trustStorePassword = EMPTY;

        assertThatThrownBy(() -> SSLContextHelper.builder().withTwoWayAuthentication(identityPath, identityPassword, trustStorePath, trustStorePassword))
                .isInstanceOf(RuntimeException.class)
                .hasMessage(GENERIC_IDENTITY_AND_TRUSTSTORE_VALIDATION_EXCEPTION_MESSAGE);
    }

    private Path copyKeystoreToHomeDirectory(String path, String fileName) throws IOException {
        try(InputStream keystoreInputStream = Thread.currentThread().getContextClassLoader().getResourceAsStream(path + fileName)) {
            Path destination = Paths.get(TEMPORALLY_KEYSTORE_LOCATION, fileName);
            Files.copy(keystoreInputStream, destination, REPLACE_EXISTING);
            return destination;
        }
    }

}
