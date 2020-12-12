package nl.altindag.ssl.util;

import nl.altindag.ssl.exception.GenericSecurityException;
import nl.altindag.ssl.model.KeyStoreHolder;
import nl.altindag.ssl.trustmanager.UnsafeX509ExtendedTrustManager;
import nl.altindag.ssl.trustmanager.X509TrustManagerWrapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CertificateException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;

@ExtendWith(MockitoExtension.class)
class TrustManagerUtilsShould {

    private static final String TRUSTSTORE_FILE_NAME = "truststore.jks";
    private static final char[] TRUSTSTORE_PASSWORD = new char[] {'s', 'e', 'c', 'r', 'e', 't'};
    private static final String KEYSTORE_LOCATION = "keystores-for-unit-tests/";

    @Test
    void combineTrustManagers() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore trustStoreOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        KeyStore trustStoreTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + "truststore-containing-github.jks", TRUSTSTORE_PASSWORD);
        X509ExtendedTrustManager trustManager = TrustManagerUtils
                .combine(TrustManagerUtils.createTrustManager(trustStoreOne), TrustManagerUtils.createTrustManager(trustStoreTwo));

        assertThat(trustStoreOne.size()).isEqualTo(1);
        assertThat(trustStoreTwo.size()).isEqualTo(1);
        assertThat(trustManager.getAcceptedIssuers()).hasSize(2);
    }

    @Test
    void combineTrustManagersWithTrustStoreHolders() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore trustStoreOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        KeyStore trustStoreTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + "truststore-containing-github.jks", TRUSTSTORE_PASSWORD);

        KeyStoreHolder trustStoreHolderOne = new KeyStoreHolder(trustStoreOne, TRUSTSTORE_PASSWORD);
        KeyStoreHolder trustStoreHolderTwo = new KeyStoreHolder(trustStoreTwo, TRUSTSTORE_PASSWORD);

        X509ExtendedTrustManager trustManager = TrustManagerUtils
                .combine(TrustManagerUtils.createTrustManager(trustStoreHolderOne, trustStoreHolderTwo));

        assertThat(trustStoreOne.size()).isEqualTo(1);
        assertThat(trustStoreTwo.size()).isEqualTo(1);
        assertThat(trustManager.getAcceptedIssuers()).hasSize(2);
    }

    @Test
    void combineTrustManagersWithKeyStores() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore trustStoreOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        KeyStore trustStoreTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + "truststore-containing-github.jks", TRUSTSTORE_PASSWORD);

        X509ExtendedTrustManager trustManager = TrustManagerUtils
                .combine(TrustManagerUtils.createTrustManager(trustStoreOne, trustStoreTwo));

        assertThat(trustStoreOne.size()).isEqualTo(1);
        assertThat(trustStoreTwo.size()).isEqualTo(1);
        assertThat(trustManager.getAcceptedIssuers()).hasSize(2);
    }

    @Test
    void combineTrustManagersWhileFilteringDuplicateCertificates() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        X509ExtendedTrustManager trustManager = TrustManagerUtils
                .combine(TrustManagerUtils.createTrustManager(trustStore), TrustManagerUtils.createTrustManager(trustStore));

        assertThat(trustStore.size()).isEqualTo(1);
        assertThat(trustManager.getAcceptedIssuers()).hasSize(1);
    }

    @Test
    void wrapIfNeeded() {
        X509TrustManager trustManager = mock(X509TrustManager.class);
        X509ExtendedTrustManager extendedTrustManager = TrustManagerUtils.wrapIfNeeded(trustManager);

        assertThat(extendedTrustManager).isInstanceOf(X509TrustManagerWrapper.class);
    }

    @Test
    void doNotWrapWhenInstanceIsX509ExtendedTrustManager() {
        X509ExtendedTrustManager trustManager = mock(X509ExtendedTrustManager.class);
        X509ExtendedTrustManager extendedTrustManager = TrustManagerUtils.wrapIfNeeded(trustManager);

        assertThat(extendedTrustManager)
                .isEqualTo(trustManager)
                .isNotInstanceOf(X509TrustManagerWrapper.class);
    }

    @Test
    void createTrustManagerWithCustomSecurityProviderBasedOnTheName() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);

        X509ExtendedTrustManager trustManager = TrustManagerUtils.createTrustManager(trustStore, TrustManagerFactory.getDefaultAlgorithm(), "SunJSSE");

        assertThat(trustManager).isNotNull();
    }

    @Test
    void createTrustManagerWithCustomSecurityProvider() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        Provider sunJSSE = Security.getProvider("SunJSSE");

        X509ExtendedTrustManager trustManager = TrustManagerUtils.createTrustManager(trustStore, TrustManagerFactory.getDefaultAlgorithm(), sunJSSE);

        assertThat(trustManager).isNotNull();
    }

    @Test
    void createTrustManagerWithJdkTrustedCertificatesWhenProvidingNullAsTrustStore() {
        X509ExtendedTrustManager trustManager = TrustManagerUtils.createTrustManager((KeyStore) null);

        assertThat(trustManager).isNotNull();
        assertThat(trustManager.getAcceptedIssuers()).hasSizeGreaterThan(10);
    }

    @Test
    void createTrustManagerWithJdkTrustedCertificatesWhenCallingCreateTrustManagerWithJdkTrustedCertificates() {
        X509ExtendedTrustManager trustManager = TrustManagerUtils.createTrustManagerWithJdkTrustedCertificates();

        assertThat(trustManager).isNotNull();
        assertThat((trustManager).getAcceptedIssuers()).hasSizeGreaterThan(10);
    }

    @Test
    void createTrustManagerWithSystemTrustedCertificate() {
        X509ExtendedTrustManager trustManager = TrustManagerUtils.createTrustManagerWithSystemTrustedCertificates();

        assertThat(trustManager).isNotNull();

        String operatingSystem = System.getProperty("os.name").toLowerCase();
        if (operatingSystem.contains("mac") || operatingSystem.contains("windows")) {
            assertThat((trustManager).getAcceptedIssuers()).hasSizeGreaterThan(0);
        }
    }

    @Test
    void createTrustManagerWithSystemTrustedCertificateWrapsCheckedExceptionIntoGenericSecurityException() {
        try (MockedStatic<KeyStoreUtils> keyStoreUtilsMock = mockStatic(KeyStoreUtils.class)) {
            keyStoreUtilsMock.when(KeyStoreUtils::loadSystemKeyStores).thenThrow(new KeyStoreException("KABOOOM!"));

            assertThatThrownBy(TrustManagerUtils::createTrustManagerWithSystemTrustedCertificates)
                    .hasMessageContaining("KABOOOM!")
                    .isInstanceOf(GenericSecurityException.class);
        }
    }

    @Test
    void createTrustManagerWhenProvidingACustomTrustStore() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        X509ExtendedTrustManager trustManager = TrustManagerUtils.createTrustManager(trustStore);

        assertThat(trustManager).isNotNull();
        assertThat((trustManager).getAcceptedIssuers()).hasSize(1);
    }

    @Test
    void createUnsafeTrustManager() {
        X509ExtendedTrustManager trustManager = TrustManagerUtils.createUnsafeTrustManager();

        assertThat(trustManager)
                .isNotNull()
                .isInstanceOf(UnsafeX509ExtendedTrustManager.class)
                .isEqualTo(TrustManagerUtils.createUnsafeTrustManager());
    }

    @Test
    void throwExceptionWhenInvalidTrustManagerAlgorithmIsProvided() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);

        assertThatThrownBy(() -> TrustManagerUtils.createTrustManager(trustStore, "ABCD"))
                .isInstanceOf(GenericSecurityException.class)
                .hasMessage("java.security.NoSuchAlgorithmException: ABCD TrustManagerFactory not available");
    }

    @Test
    void throwExceptionWhenInvalidSecurityProviderNameIsProvided() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        String trustManagerFactoryAlgorithm = TrustManagerFactory.getDefaultAlgorithm();

        assertThatThrownBy(() -> TrustManagerUtils.createTrustManager(trustStore, trustManagerFactoryAlgorithm, "test"))
                .isInstanceOf(GenericSecurityException.class)
                .hasMessage("java.security.NoSuchProviderException: no such provider: test");
    }

    @Test
    void throwExceptionWhenInvalidSecurityProviderNameIsProvidedForTheTrustManagerFactoryAlgorithm() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        String trustManagerFactoryAlgorithm = TrustManagerFactory.getDefaultAlgorithm();

        assertThatThrownBy(() -> TrustManagerUtils.createTrustManager(trustStore, trustManagerFactoryAlgorithm, "SUN"))
                .isInstanceOf(GenericSecurityException.class)
                .hasMessage("java.security.NoSuchAlgorithmException: no such algorithm: PKIX for provider SUN");
    }

    @Test
    void throwExceptionWhenInvalidSecurityProviderIsProvidedForTheTrustManagerFactoryAlgorithm() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        String trustManagerFactoryAlgorithm = TrustManagerFactory.getDefaultAlgorithm();
        Provider sunSecurityProvider = Security.getProvider("SUN");

        assertThatThrownBy(() -> TrustManagerUtils.createTrustManager(trustStore, trustManagerFactoryAlgorithm, sunSecurityProvider))
                .isInstanceOf(GenericSecurityException.class)
                .hasMessage("java.security.NoSuchAlgorithmException: no such algorithm: PKIX for provider SUN");
    }

    @Test
    void throwGenericSecurityExceptionWhenTrustManagerFactoryCanNotInitializeWithTheProvidedTrustStore() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        TrustManagerFactory trustManagerFactory = mock(TrustManagerFactory.class);

        doThrow(new KeyStoreException("KABOOOM!")).when(trustManagerFactory).init(any(KeyStore.class));


        assertThatThrownBy(() -> TrustManagerUtils.createTrustManager(trustStore, trustManagerFactory))
                .isInstanceOf(GenericSecurityException.class)
                .hasMessage("java.security.KeyStoreException: KABOOOM!");
    }

}
