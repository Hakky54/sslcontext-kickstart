/*
 * Copyright 2019-2021 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package nl.altindag.ssl.util;

import nl.altindag.ssl.SSLFactory;
import nl.altindag.ssl.exception.GenericKeyStoreException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.net.ssl.X509ExtendedTrustManager;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.List;

import static nl.altindag.ssl.TestConstants.IDENTITY_FILE_NAME;
import static nl.altindag.ssl.TestConstants.KEYSTORE_LOCATION;
import static nl.altindag.ssl.TestConstants.TRUSTSTORE_FILE_NAME;
import static nl.altindag.ssl.TestConstants.TRUSTSTORE_PASSWORD;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.spy;

/**
 * @author Hakan Altindag
 */
@ExtendWith(MockitoExtension.class)
class KeyStoreUtilsShould {

    private static final String JCEKS_KEYSTORE_FILE_NAME = "identity.jceks";
    private static final String PKCS12_KEYSTORE_FILE_NAME = "identity.p12";
    private static final String NON_EXISTING_KEYSTORE_FILE_NAME = "black-hole.jks";

    private static final char[] KEYSTORE_PASSWORD = new char[] {'s', 'e', 'c', 'r', 'e', 't'};
    private static final String ORIGINAL_OS_NAME = System.getProperty("os.name");
    private static final String TEST_RESOURCES_LOCATION = "src/test/resources/";

    @Test
    void loadKeyStoreFromClasspath() {
        KeyStore keyStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, KEYSTORE_PASSWORD);
        assertThat(keyStore).isNotNull();
    }

    @Test
    void loadJCEKSKeyStoreFromClasspath() {
        KeyStore keyStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + JCEKS_KEYSTORE_FILE_NAME, KEYSTORE_PASSWORD, "JCEKS");
        assertThat(keyStore).isNotNull();
    }

    @Test
    void loadPKCS12KeyStoreFromClasspath() {
        KeyStore keyStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + PKCS12_KEYSTORE_FILE_NAME, KEYSTORE_PASSWORD, "PKCS12");
        assertThat(keyStore).isNotNull();
    }

    @Test
    void loadKeyStoreWithPathFromDirectory() {
        KeyStore keyStore = KeyStoreUtils.loadKeyStore(Paths.get(TEST_RESOURCES_LOCATION + KEYSTORE_LOCATION + IDENTITY_FILE_NAME).toAbsolutePath(), KEYSTORE_PASSWORD);
        assertThat(keyStore).isNotNull();
    }

    @Test
    void loadKeyStoreAsInputStream() throws IOException {
        KeyStore keyStore;
        try(InputStream inputStream = getResource(KEYSTORE_LOCATION + IDENTITY_FILE_NAME)) {
            keyStore = KeyStoreUtils.loadKeyStore(inputStream, "secret".toCharArray());
        }

        assertThat(keyStore).isNotNull();
    }

    @Test
    void loadSystemKeyStore() {
        List<KeyStore> keyStores = KeyStoreUtils.loadSystemKeyStores();

        String operatingSystem = System.getProperty("os.name").toLowerCase();
        if (operatingSystem.contains("mac") || operatingSystem.contains("windows")) {
            assertThat(keyStores).isNotEmpty();
        }
    }

    @Test
    void loadWindowsSystemKeyStore() {
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
            keyStoreUtilsMock.when(() -> KeyStoreUtils.createKeyStore("Windows-ROOT", null)).thenReturn(windowsRootKeyStore);
            keyStoreUtilsMock.when(() -> KeyStoreUtils.createKeyStore("Windows-MY", null)).thenReturn(windowsMyKeyStore);

            List<KeyStore> keyStores = KeyStoreUtils.loadSystemKeyStores();
            assertThat(keyStores).containsExactlyInAnyOrder(windowsRootKeyStore, windowsMyKeyStore);
        }

        resetOsName();
    }

    @Test
    void loadMacSystemKeyStore() {
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
            keyStoreUtilsMock.when(() -> KeyStoreUtils.createKeyStore("KeychainStore", null)).thenReturn(macKeyStore);

            List<KeyStore> keyStores = KeyStoreUtils.loadSystemKeyStores();
            assertThat(keyStores).containsExactly(macKeyStore);
        }

        resetOsName();
    }

    @Test
    void createTrustStoreFromX509CertificatesAsList() throws KeyStoreException {
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
    void createTrustStoreFromX509CertificatesAsArray() throws KeyStoreException {
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
    void createTrustStoreFromMultipleTrustManagers() throws KeyStoreException {
        X509ExtendedTrustManager jdkTrustManager = TrustManagerUtils.createTrustManagerWithJdkTrustedCertificates();
        X509ExtendedTrustManager customTrustManager = TrustManagerUtils.createTrustManager(KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD));

        KeyStore trustStore = KeyStoreUtils.createTrustStore(jdkTrustManager, customTrustManager);

        assertThat(jdkTrustManager.getAcceptedIssuers().length).isNotZero();
        assertThat(customTrustManager.getAcceptedIssuers().length).isNotZero();
        assertThat(trustStore.size()).isNotZero();
        assertThat(trustStore.size()).isEqualTo(jdkTrustManager.getAcceptedIssuers().length + customTrustManager.getAcceptedIssuers().length);
    }

    @Test
    void throwExceptionWhenLoadingNonExistingKeystoreType() {
        assertThatThrownBy(() -> KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, KEYSTORE_PASSWORD, "unknown"))
                .isInstanceOf(GenericKeyStoreException.class)
                .hasMessageContaining("unknown not found");
    }

    @Test
    void throwExceptionWhenLoadingNonExistingKeystore() {
        assertThatThrownBy(() -> KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + NON_EXISTING_KEYSTORE_FILE_NAME, KEYSTORE_PASSWORD))
                  .isInstanceOf(GenericKeyStoreException.class)
                  .hasMessageContaining("KeyStore is not present for the giving input");
    }

    @Test
    void throwGenericKeyStoreExceptionWhenFailingToCloseStreamProperly() throws IOException {
        String keystoreType = KeyStore.getDefaultType();
        Path keystorePath = Paths.get(TEST_RESOURCES_LOCATION + KEYSTORE_LOCATION + IDENTITY_FILE_NAME).toAbsolutePath();
        InputStream inputStream = spy(Files.newInputStream(keystorePath, StandardOpenOption.READ));

        try (MockedStatic<Files> filesMockedStatic = mockStatic(Files.class, invocation -> {
            Method method = invocation.getMethod();
            if ("newInputStream".equals(method.getName())) {
                return invocation.getMock();
            } else {
                return invocation.callRealMethod();
            }
        })) {

            doThrow(new IOException("Could not close the stream")).when(inputStream).close();

            filesMockedStatic.when(() -> Files.newInputStream(any(Path.class), any(OpenOption.class))).thenReturn(inputStream);

            assertThatThrownBy(() -> KeyStoreUtils.loadKeyStore(keystorePath, KEYSTORE_PASSWORD, keystoreType))
                    .isInstanceOf(GenericKeyStoreException.class)
                    .hasMessageContaining("Could not close the stream");
        }
    }

    @Test
    void throwExceptionWhenCreateKeyStoreForUnknownType() {
        assertThatThrownBy(() -> KeyStoreUtils.createKeyStore("unknown", KEYSTORE_PASSWORD))
                .isInstanceOf(GenericKeyStoreException.class)
                .hasMessageContaining("unknown not found");
    }

    @Test
    void throwGenericKeyStoreWhenSetCertificateEntryThrowsKeyStoreException() throws KeyStoreException {
        SSLFactory sslFactory = SSLFactory.builder()
                .withTrustMaterial(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD)
                .withDefaultTrustMaterial()
                .build();

        X509Certificate[] trustedCertificates = sslFactory.getTrustedCertificates().toArray(new X509Certificate[0]);

        KeyStore keyStore = mock(KeyStore.class);
        doThrow(new KeyStoreException("lazy")).when(keyStore).setCertificateEntry(anyString(), any(Certificate.class));

        try (MockedStatic<KeyStoreUtils> keyStoreUtilsMock = mockStatic(KeyStoreUtils.class, invocation -> {
            Method method = invocation.getMethod();
            if ("createKeyStore".equals(method.getName()) && method.getParameterCount() == 0) {
                return invocation.getMock();
            } else {
                return invocation.callRealMethod();
            }
        })) {
            keyStoreUtilsMock.when(KeyStoreUtils::createKeyStore).thenReturn(keyStore);

            assertThatThrownBy(() -> KeyStoreUtils.createTrustStore(trustedCertificates))
                    .isInstanceOf(GenericKeyStoreException.class)
                    .hasMessageContaining("lazy");
        }
    }

    private void resetOsName() {
        System.setProperty("os.name", ORIGINAL_OS_NAME);
    }

    private InputStream getResource(String path) {
        return this.getClass().getClassLoader().getResourceAsStream(path);
    }

}
