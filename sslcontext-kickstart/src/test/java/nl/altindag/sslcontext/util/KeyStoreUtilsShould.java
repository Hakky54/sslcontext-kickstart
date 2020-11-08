package nl.altindag.sslcontext.util;

import nl.altindag.sslcontext.SSLFactory;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.net.ssl.X509ExtendedTrustManager;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;

import static java.nio.file.StandardCopyOption.REPLACE_EXISTING;
import static nl.altindag.sslcontext.TestConstants.IDENTITY_FILE_NAME;
import static nl.altindag.sslcontext.TestConstants.KEYSTORE_LOCATION;
import static nl.altindag.sslcontext.TestConstants.TRUSTSTORE_FILE_NAME;
import static nl.altindag.sslcontext.TestConstants.TRUSTSTORE_PASSWORD;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;

@ExtendWith(MockitoExtension.class)
class KeyStoreUtilsShould {

    private static final String JCEKS_KEYSTORE_FILE_NAME = "identity.jceks";
    private static final String PKCS12_KEYSTORE_FILE_NAME = "identity.p12";
    private static final String NON_EXISTING_KEYSTORE_FILE_NAME = "black-hole.jks";

    private static final char[] KEYSTORE_PASSWORD = new char[] {'s', 'e', 'c', 'r', 'e', 't'};
    private static final String TEMPORALLY_KEYSTORE_LOCATION = System.getProperty("user.home");
    private static final String ORIGINAL_OS_NAME = System.getProperty("os.name");

    @Test
    void loadKeyStoreFromClasspath() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore keyStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, KEYSTORE_PASSWORD);
        assertThat(keyStore).isNotNull();
    }

    @Test
    void loadJCEKSKeyStoreFromClasspath() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore keyStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + JCEKS_KEYSTORE_FILE_NAME, KEYSTORE_PASSWORD, "JCEKS");
        assertThat(keyStore).isNotNull();
    }

    @Test
    void loadPKCS12KeyStoreFromClasspath() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore keyStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + PKCS12_KEYSTORE_FILE_NAME, KEYSTORE_PASSWORD, "PKCS12");
        assertThat(keyStore).isNotNull();
    }

    @Test
    void loadKeyStoreWithPathFromDirectory() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        Path keystorePath = copyKeystoreToHomeDirectory(KEYSTORE_LOCATION, IDENTITY_FILE_NAME);

        KeyStore keyStore = KeyStoreUtils.loadKeyStore(keystorePath, KEYSTORE_PASSWORD);
        assertThat(keyStore).isNotNull();

        Files.delete(keystorePath);
    }

    @Test
    void loadSystemKeyStore() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        List<KeyStore> keyStores = KeyStoreUtils.loadSystemKeyStores();

        String operatingSystem = System.getProperty("os.name").toLowerCase();
        if (operatingSystem.contains("mac") || operatingSystem.contains("windows")) {
            assertThat(keyStores).isNotEmpty();
        }
    }

    @Test
    void loadWindowsSystemKeyStore() throws Exception {
        System.setProperty("os.name", "windows");
        KeyStore windowsRootKeyStore = mock(KeyStore.class);
        KeyStore windowsMyKeyStore = mock(KeyStore.class);

        try (MockedStatic<KeyStoreUtils> keyStoreUtilsMock = mockStatic(KeyStoreUtils.class, invocation -> {
            Method method = invocation.getMethod();
            if ("loadSystemKeyStores".equals(method.getName()) && method.getParameterCount() == 0) {
                return invocation.callRealMethod();
            } else {
                return invocation.getMock();
            }
        })) {
            keyStoreUtilsMock.when(() -> KeyStoreUtils.loadSystemKeyStore("Windows-ROOT")).thenReturn(windowsRootKeyStore);
            keyStoreUtilsMock.when(() -> KeyStoreUtils.loadSystemKeyStore("Windows-MY")).thenReturn(windowsMyKeyStore);

            List<KeyStore> keyStores = KeyStoreUtils.loadSystemKeyStores();
            assertThat(keyStores).containsExactlyInAnyOrder(windowsRootKeyStore, windowsMyKeyStore);
        }

        resetOsName();
    }

    @Test
    void loadMacSystemKeyStore() throws Exception {
        System.setProperty("os.name", "mac");
        KeyStore macKeyStore = mock(KeyStore.class);

        try (MockedStatic<KeyStoreUtils> keyStoreUtilsMock = mockStatic(KeyStoreUtils.class, invocation -> {
            Method method = invocation.getMethod();
            if ("loadSystemKeyStores".equals(method.getName()) && method.getParameterCount() == 0) {
                return invocation.callRealMethod();
            } else {
                return invocation.getMock();
            }
        })) {
            keyStoreUtilsMock.when(() -> KeyStoreUtils.loadSystemKeyStore("KeychainStore")).thenReturn(macKeyStore);

            List<KeyStore> keyStores = KeyStoreUtils.loadSystemKeyStores();
            assertThat(keyStores).containsExactly(macKeyStore);
        }

        resetOsName();
    }

    @Test
    void createTrustStoreFromX509CertificatesAsList() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        SSLFactory sslFactory = SSLFactory.builder()
                .withTrustMaterial(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD)
                .withDefaultTrustMaterial()
                .build();

        List<X509Certificate> trustedCertificates = sslFactory.getTrustedCertificates();
        KeyStore trustStore = KeyStoreUtils.createTrustStore(trustedCertificates);

        assertThat(trustedCertificates.size()).isNotZero();
        assertThat(trustStore.size()).isNotZero();
        assertThat(trustStore.size()).isEqualTo(trustedCertificates.size());
    }

    @Test
    void createTrustStoreFromX509CertificatesAsArray() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        SSLFactory sslFactory = SSLFactory.builder()
                .withTrustMaterial(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD)
                .withDefaultTrustMaterial()
                .build();

        X509Certificate[] trustedCertificates = sslFactory.getTrustedCertificates().toArray(new X509Certificate[0]);
        KeyStore trustStore = KeyStoreUtils.createTrustStore(trustedCertificates);

        assertThat(trustedCertificates.length).isNotZero();
        assertThat(trustStore.size()).isNotZero();
        assertThat(trustStore.size()).isEqualTo(trustedCertificates.length);
    }

    @Test
    void createTrustStoreFromMultipleTrustManagers() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        X509ExtendedTrustManager jdkTrustManager = TrustManagerUtils.createTrustManagerWithJdkTrustedCertificates();
        X509ExtendedTrustManager customTrustManager = TrustManagerUtils.createTrustManager(KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD));

        KeyStore trustStore = KeyStoreUtils.createTrustStore(jdkTrustManager, customTrustManager);

        assertThat(jdkTrustManager.getAcceptedIssuers().length).isNotZero();
        assertThat(customTrustManager.getAcceptedIssuers().length).isNotZero();
        assertThat(trustStore.size()).isNotZero();
        assertThat(trustStore.size()).isEqualTo(jdkTrustManager.getAcceptedIssuers().length + customTrustManager.getAcceptedIssuers().length);
    }

    @Test
    void throwExceptionWhenLoadingNonExistingKeystore() {
        Assertions.assertThatThrownBy(() -> KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + NON_EXISTING_KEYSTORE_FILE_NAME, KEYSTORE_PASSWORD))
                  .isInstanceOf(IOException.class)
                  .hasMessage("Could not find the keystore file");
    }

    private Path copyKeystoreToHomeDirectory(String path, String fileName) throws IOException {
        try(InputStream keystoreInputStream = Thread.currentThread().getContextClassLoader().getResourceAsStream(path + fileName)) {
            Path destination = Paths.get(TEMPORALLY_KEYSTORE_LOCATION, fileName);
            Files.copy(keystoreInputStream, destination, REPLACE_EXISTING);
            return destination;
        }
    }

    private void resetOsName() {
        System.setProperty("os.name", ORIGINAL_OS_NAME);
    }

}
