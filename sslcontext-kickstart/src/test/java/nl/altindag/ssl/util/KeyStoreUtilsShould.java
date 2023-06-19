/*
 * Copyright 2019 Thunderberry.
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

import nl.altindag.log.LogCaptor;
import nl.altindag.ssl.IOTestUtils;
import nl.altindag.ssl.SSLFactory;
import nl.altindag.ssl.TestConstants;
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
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import static nl.altindag.ssl.TestConstants.IDENTITY_FILE_NAME;
import static nl.altindag.ssl.TestConstants.IDENTITY_PASSWORD;
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
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.when;

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
        try(InputStream inputStream = IOTestUtils.getResourceAsStream(KEYSTORE_LOCATION + IDENTITY_FILE_NAME)) {
            keyStore = KeyStoreUtils.loadKeyStore(inputStream, "secret".toCharArray());
        }

        assertThat(keyStore).isNotNull();
    }

    @Test
    void loadSystemKeyStore() {
        List<KeyStore> keyStores = KeyStoreUtils.loadSystemKeyStores();

        String operatingSystem = System.getProperty("os.name").toLowerCase();
        if (operatingSystem.contains("mac") || operatingSystem.contains("windows") || operatingSystem.contains("linux")) {
            assertThat(keyStores).isNotEmpty();
        }
    }

    @Test
    void loadSystemKeyStoreNotLogIfDebugIsDisabled() {
        LogCaptor logCaptor = LogCaptor.forClass(KeyStoreUtils.class);
        logCaptor.setLogLevelToInfo();

        List<KeyStore> keyStores = KeyStoreUtils.loadSystemKeyStores();

        String operatingSystem = System.getProperty("os.name").toLowerCase();
        if (operatingSystem.contains("mac") || operatingSystem.contains("windows") || operatingSystem.contains("linux")) {
            assertThat(keyStores).isNotEmpty();
        }

        assertThat(logCaptor.getDebugLogs()).isEmpty();
    }

    @Test
    void loadWindowsSystemKeyStore() {
        LogCaptor logCaptor = LogCaptor.forClass(KeyStoreUtils.class);
        logCaptor.setLogLevelToDebug();

        System.setProperty("os.name", "windows");
        KeyStore windowsRootKeyStore = mock(KeyStore.class);
        KeyStore windowsMyKeyStore = mock(KeyStore.class);
        KeyStore windowsMyCurrentUserKeyStore = mock(KeyStore.class);
        KeyStore windowsMyLocalmachineKeyStore = mock(KeyStore.class);
        KeyStore windowsRootCurrentUserKeyStore = mock(KeyStore.class);
        KeyStore windowsRootLocalmachineKeyStore = mock(KeyStore.class);

        try (MockedStatic<KeyStoreUtils> keyStoreUtilsMock = mockStatic(KeyStoreUtils.class, invocation -> {
            Method method = invocation.getMethod();
            if ("loadSystemKeyStores".equals(method.getName()) && method.getParameterCount() == 0) {
                return invocation.callRealMethod();
            } else if ("createKeyStoreIfAvailable".equals(method.getName()) && method.getParameterCount() == 2 && "Windows-ROOT".equals(invocation.getArgument(0))) {
                return Optional.of(windowsRootKeyStore);
            } else if ("createKeyStoreIfAvailable".equals(method.getName()) && method.getParameterCount() == 2 && "Windows-MY".equals(invocation.getArgument(0))) {
                return Optional.of(windowsMyKeyStore);
            } else if ("createKeyStoreIfAvailable".equals(method.getName()) && method.getParameterCount() == 2 && "Windows-MY-CURRENTUSER".equals(invocation.getArgument(0))) {
                return Optional.of(windowsMyCurrentUserKeyStore);
            } else if ("createKeyStoreIfAvailable".equals(method.getName()) && method.getParameterCount() == 2 && "Windows-MY-LOCALMACHINE".equals(invocation.getArgument(0))) {
                return Optional.of(windowsMyLocalmachineKeyStore);
            } else if ("createKeyStoreIfAvailable".equals(method.getName()) && method.getParameterCount() == 2 && "Windows-ROOT-LOCALMACHINE".equals(invocation.getArgument(0))) {
                return Optional.of(windowsRootLocalmachineKeyStore);
            } else if ("createKeyStoreIfAvailable".equals(method.getName()) && method.getParameterCount() == 2 && "Windows-ROOT-CURRENTUSER".equals(invocation.getArgument(0))) {
                return Optional.of(windowsRootCurrentUserKeyStore);
            } else if ("countAmountOfTrustMaterial".equals(method.getName())) {
                return 2;
            } else {
                return invocation.getMock();
            }
        })) {
            List<KeyStore> keyStores = KeyStoreUtils.loadSystemKeyStores();
            assertThat(keyStores).containsExactlyInAnyOrder(windowsRootKeyStore, windowsMyKeyStore, windowsMyCurrentUserKeyStore, windowsMyLocalmachineKeyStore, windowsRootCurrentUserKeyStore, windowsRootLocalmachineKeyStore);
            assertThat(logCaptor.getDebugLogs()).contains("Loaded [12] system trusted certificates");
        } finally {
            resetOsName();
        }
    }

    @Test
    void loadAndroidSystemKeyStoreWithAndroidSystemProperty() {
        System.setProperty("os.name", "Linux");

        HashMap<String, String> androidProperties = new HashMap<>();
        androidProperties.put("java.vendor", "The Android Project");
        androidProperties.put("java.vm.vendor", "The Android Project");
        androidProperties.put("java.runtime.name", "Android Runtime");

        androidProperties.forEach((key, value) -> {
            System.setProperty(key, value);

            KeyStore androidCAStore = mock(KeyStore.class);

            try (MockedStatic<KeyStoreUtils> keyStoreUtilsMock = mockStatic(KeyStoreUtils.class, invocation -> {
                Method method = invocation.getMethod();
                if ("loadSystemKeyStores".equals(method.getName()) && method.getParameterCount() == 0) {
                    return invocation.callRealMethod();
                } else if ("createKeyStoreIfAvailable".equals(method.getName()) && method.getParameterCount() == 2 && "AndroidCAStore".equals(invocation.getArgument(0))) {
                    return Optional.of(androidCAStore);
                } else if ("countAmountOfTrustMaterial".equals(method.getName())) {
                    return 2;
                } else {
                    return invocation.getMock();
                }
            })) {
                List<KeyStore> keyStores = KeyStoreUtils.loadSystemKeyStores();
                assertThat(keyStores).containsExactly(androidCAStore);
            } finally {
                System.clearProperty(key);
            }
        });

        resetOsName();
    }

    @Test
    void notLoadAndroidSystemKeyStoreWhenAdditionalAndroidPropertiesAreMissing() {
        System.setProperty("os.name", "Linux");
        System.clearProperty("java.vendor");
        System.clearProperty("java.vm.vendor");
        System.clearProperty("java.runtime.name");

        KeyStore androidCAStore = mock(KeyStore.class);

        try (MockedStatic<LinuxCertificateUtils> linuxCertificateUtilsMockedStatic = mockStatic(LinuxCertificateUtils.class);
             MockedStatic<KeyStoreUtils> keyStoreUtilsMock = mockStatic(KeyStoreUtils.class, invocation -> {
            Method method = invocation.getMethod();
            if ("loadSystemKeyStores".equals(method.getName()) && method.getParameterCount() == 0) {
                return invocation.callRealMethod();
            } else if ("createKeyStoreIfAvailable".equals(method.getName()) && method.getParameterCount() == 2 && "AndroidCAStore".equals(invocation.getArgument(0))) {
                return Optional.of(androidCAStore);
            } else if ("createTrustStore".equals(method.getName()) && method.getParameterCount() == 1) {
                return mock(KeyStore.class);
            } else if ("countAmountOfTrustMaterial".equals(method.getName())) {
                return 2;
            } else {
                return invocation.getMock();
            }
        })) {
            KeyStoreUtils.loadSystemKeyStores();
            keyStoreUtilsMock.verify(() -> KeyStoreUtils.createKeyStore("AndroidCAStore", null), times(0));
        } finally {
            resetOsName();
        }
    }

    @Test
    void loadMacSystemKeyStore() {
        System.setProperty("os.name", "mac");
        KeyStore keychainStore = mock(KeyStore.class);
        KeyStore systemTrustStore = mock(KeyStore.class);

        try (MockedStatic<MacCertificateUtils> macCertificateUtilsMockedStatic = mockStatic(MacCertificateUtils.class);
             MockedStatic<KeyStoreUtils> keyStoreUtilsMockedStatic = mockStatic(KeyStoreUtils.class, invocation -> {
            Method method = invocation.getMethod();
            if ("loadSystemKeyStores".equals(method.getName()) && method.getParameterCount() == 0) {
                return invocation.callRealMethod();
            } else if ("createKeyStoreIfAvailable".equals(method.getName()) && method.getParameterCount() == 2 && "KeychainStore".equals(invocation.getArgument(0))) {
                return Optional.of(keychainStore);
            } else if ("createTrustStore".equals(method.getName()) && method.getParameterCount() == 1 && method.getParameters()[0].getType().equals(List.class)) {
                return systemTrustStore;
            } else if ("countAmountOfTrustMaterial".equals(method.getName())) {
                return 2;
            } else {
                return invocation.callRealMethod();
            }
        })) {
            List<KeyStore> keyStores = KeyStoreUtils.loadSystemKeyStores();
            assertThat(keyStores).containsExactly(keychainStore, systemTrustStore);
            macCertificateUtilsMockedStatic.verify(MacCertificateUtils::getCertificates, times(1));
        }

        resetOsName();
    }

    @Test
    void loadLinuxSystemKeyStoreReturns() {
        System.setProperty("os.name", "linux");

        KeyStore systemTrustStore = mock(KeyStore.class);

        try (MockedStatic<LinuxCertificateUtils> linuxCertificateUtilsMockedStatic = mockStatic(LinuxCertificateUtils.class);
             MockedStatic<KeyStoreUtils> keyStoreUtilsMockedStatic = mockStatic(KeyStoreUtils.class, invocation -> {
                 Method method = invocation.getMethod();
                 if ("loadSystemKeyStores".equals(method.getName()) && method.getParameterCount() == 0) {
                     return invocation.callRealMethod();
                 } else if ("createTrustStore".equals(method.getName()) && method.getParameterCount() == 1 && method.getParameters()[0].getType().equals(List.class)) {
                     return systemTrustStore;
                 } else if ("countAmountOfTrustMaterial".equals(method.getName())) {
                     return 2;
                 } else {
                     return invocation.getMock();
                 }
             })) {
            List<KeyStore> keyStores = KeyStoreUtils.loadSystemKeyStores();
            assertThat(keyStores).containsExactly(systemTrustStore);
            linuxCertificateUtilsMockedStatic.verify(LinuxCertificateUtils::getCertificates, times(1));
        }

        resetOsName();
    }

    @Test
    void notLoadSystemKeyStoreForUnknownOs() {
        System.setProperty("os.name", "Banana OS");
        LogCaptor logCaptor = LogCaptor.forClass(KeyStoreUtils.class);

        List<KeyStore> keyStores = KeyStoreUtils.loadSystemKeyStores();

        assertThat(keyStores).isEmpty();
        assertThat(logCaptor.getWarnLogs()).contains("No system KeyStores available for [banana os]");

        logCaptor.close();
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
    void countAmountOfTrustMaterial() {
        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);

        int amountOfTrustMaterial = KeyStoreUtils.countAmountOfTrustMaterial(trustStore);
        assertThat(amountOfTrustMaterial).isEqualTo(1);
    }

    @Test
    void containsTrustMaterial() {
        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);

        boolean containsTrustMaterial = KeyStoreUtils.containsTrustMaterial(trustStore);
        assertThat(containsTrustMaterial).isTrue();
    }

    @Test
    void doesNotContainsTrustMaterial() {
        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);

        boolean containsTrustMaterial = KeyStoreUtils.containsTrustMaterial(trustStore);
        assertThat(containsTrustMaterial).isFalse();
    }

    @Test
    void countAmountOfIdentityMaterial() {
        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);

        int amountOfIdentityMaterial = KeyStoreUtils.countAmountOfIdentityMaterial(trustStore);
        assertThat(amountOfIdentityMaterial).isEqualTo(1);
    }

    @Test
    void containsIdentityMaterial() {
        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);

        boolean containsIdentityMaterial = KeyStoreUtils.containsIdentityMaterial(trustStore);
        assertThat(containsIdentityMaterial).isTrue();
    }

    @Test
    void containsIdentityMaterialReturnsTrueWithFirstMatchEvenThoughKeyStoreContainsMoreIdentityMaterial() {
        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + "identity-with-multiple-keys.jks", IDENTITY_PASSWORD);

        boolean containsIdentityMaterial = KeyStoreUtils.containsIdentityMaterial(trustStore);
        assertThat(containsIdentityMaterial).isTrue();
    }

    @Test
    void doesNotContainsIdentityMaterial() {
        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);

        boolean containsIdentityMaterial = KeyStoreUtils.containsIdentityMaterial(trustStore);
        assertThat(containsIdentityMaterial).isFalse();
    }

    @Test
    void createIdentityStoreWithPrivateKeyAndCertificateChainAsListAndAlias() throws NoSuchAlgorithmException, KeyStoreException, UnrecoverableKeyException {
        KeyStore identity = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);
        PrivateKey privateKey = (PrivateKey) identity.getKey("dummy-client", IDENTITY_PASSWORD);
        Certificate[] certificateChain = identity.getCertificateChain("dummy-client");

        KeyStore identityStore = KeyStoreUtils.createIdentityStore(privateKey, IDENTITY_PASSWORD, "dummy-client", Arrays.asList(certificateChain));

        assertThat(identityStore).isNotNull();
        assertThat(identityStore.size()).isEqualTo(1);
        assertThat(identityStore.isKeyEntry("dummy-client")).isTrue();
    }

    @Test
    void createIdentityStoreWithPrivateKeyAndCertificateChainAsList() throws NoSuchAlgorithmException, KeyStoreException, UnrecoverableKeyException {
        KeyStore identity = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);
        PrivateKey privateKey = (PrivateKey) identity.getKey("dummy-client", IDENTITY_PASSWORD);
        Certificate[] certificateChain = identity.getCertificateChain("dummy-client");

        KeyStore identityStore = KeyStoreUtils.createIdentityStore(privateKey, IDENTITY_PASSWORD, Arrays.asList(certificateChain));

        assertThat(identityStore).isNotNull();
        assertThat(identityStore.size()).isEqualTo(1);
        assertThat(identityStore.isKeyEntry("cn=prof-oak_ou=oak-pokémon-research-lab_o=oak-pokémon-research-lab_c=pallet-town")).isTrue();
    }

    @Test
    void createTrustStoreHavingUniqueAliasesForCertificatesWhileHavingSameDistinguishName() throws KeyStoreException {
        List<X509Certificate> trustedCertificates = SSLFactory.builder()
                .withTrustMaterial(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD)
                .withDefaultTrustMaterial()
                .build()
                .getTrustedCertificates();

        KeyStore trustStore = KeyStoreUtils.createTrustStore(
                Stream.concat(trustedCertificates.stream(), trustedCertificates.stream()).collect(Collectors.toList())
        );

        assertThat(trustStore.size()).isEqualTo(trustedCertificates.size() * 2);
    }

    @Test
    void limitTheAmountOfDuplicateAliasesTo1002WhenHavingExactMatchingAliases() throws KeyStoreException {
        X509Certificate trustedCertificate = SSLFactory.builder()
                .withTrustMaterial(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD)
                .withDefaultTrustMaterial()
                .build()
                .getTrustedCertificates()
                .stream()
                .findFirst()
                .orElseThrow(() -> new RuntimeException("At least one certificate should be present"));

        List<X509Certificate> trustedCertificates = IntStream.range(0, 1100)
                .mapToObj(index -> trustedCertificate)
                .collect(Collectors.toList());

        KeyStore trustStore = KeyStoreUtils.createTrustStore(trustedCertificates);

        assertThat(trustStore.size()).isEqualTo(1002);
    }

    @Test
    void writeKeystoreToFilesystem() throws IOException, KeyStoreException {
        KeyStore baseTruststore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        Path truststorePath = Paths.get(TestConstants.HOME_DIRECTORY).resolve(Paths.get("truststore.jks"));
        KeyStoreUtils.write(truststorePath, baseTruststore, TRUSTSTORE_PASSWORD);

        assertThat(Files.exists(truststorePath)).isTrue();
        KeyStore truststore = KeyStoreUtils.loadKeyStore(truststorePath, TRUSTSTORE_PASSWORD);
        assertThat(truststore.size())
                .isGreaterThan(0)
                .isEqualTo(baseTruststore.size());

        Enumeration<String> aliases = truststore.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            assertThat(truststore.isCertificateEntry(alias)).isTrue();
            assertThat(truststore.getCertificate(alias)).isEqualTo(baseTruststore.getCertificate(alias));
        }

        Files.delete(truststorePath);
    }

    @Test
    void getCertificates() {
        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);

        List<Certificate> certificates = KeyStoreUtils.getCertificates(trustStore);
        assertThat(certificates).hasSize(1);
    }

    @Test
    void getAliasToCertificate() {
        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);

        Map<String, Certificate> aliasToCertificate = KeyStoreUtils.getAliasToCertificate(trustStore);
        assertThat(aliasToCertificate.values()).hasSize(1);
        assertThat(aliasToCertificate)
                .hasSize(1)
                .containsKey("google");
    }

    @Test
    void getAliasToCertificateFiltersOutKeyMaterial() throws KeyStoreException {
        KeyStore keyStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, KEYSTORE_PASSWORD);

        assertThat(keyStore.size()).isGreaterThan(0);

        Map<String, Certificate> aliasToCertificate = KeyStoreUtils.getAliasToCertificate(keyStore);
        assertThat(aliasToCertificate).isEmpty();
    }

    @Test
    void createKeyStoreIfAvailableReturnsEmptyForNonExistingKeyStoreType() {
        Optional<KeyStore> bananaKeyStore = KeyStoreUtils.createKeyStoreIfAvailable("Banana", null);
        assertThat(bananaKeyStore).isEmpty();
    }

    @Test
    void createKeyStoreIfAvailableReturnsFilledKeyStore() {
        LogCaptor logCaptor = LogCaptor.forClass(KeyStoreUtils.class);

        KeyStore bananaKeyStore = mock(KeyStore.class);

        try (MockedStatic<KeyStoreUtils> keyStoreUtilsMock = mockStatic(KeyStoreUtils.class, invocation -> {
            Method method = invocation.getMethod();
            if ("createKeyStore".equals(method.getName()) && method.getParameterCount() == 2 && "Banana".equals(invocation.getArgument(0))) {
                return bananaKeyStore;
            } else if ("countAmountOfTrustMaterial".equals(method.getName())) {
                return 2;
            } else {
                return invocation.callRealMethod();
            }
        })) {
            Optional<KeyStore> keyStore = KeyStoreUtils.createKeyStoreIfAvailable("Banana", null);
            assertThat(keyStore).isPresent();
            assertThat(logCaptor.getDebugLogs()).contains("Successfully loaded KeyStore of the type [Banana] having [2] entries");
        }
    }

    @Test
    void createKeyStoreIfAvailableReturnsFilledKeyStoreWithoutLoggingIfDebugIsDisabled() {
        LogCaptor logCaptor = LogCaptor.forClass(KeyStoreUtils.class);
        logCaptor.setLogLevelToInfo();

        KeyStore bananaKeyStore = mock(KeyStore.class);

        try (MockedStatic<KeyStoreUtils> keyStoreUtilsMock = mockStatic(KeyStoreUtils.class, invocation -> {
            Method method = invocation.getMethod();
            if ("createKeyStore".equals(method.getName()) && method.getParameterCount() == 2 && "Banana".equals(invocation.getArgument(0))) {
                return bananaKeyStore;
            } else if ("countAmountOfTrustMaterial".equals(method.getName())) {
                return 2;
            } else {
                return invocation.callRealMethod();
            }
        })) {
            Optional<KeyStore> keyStore = KeyStoreUtils.createKeyStoreIfAvailable("Banana", null);
            assertThat(keyStore).isPresent();
            assertThat(logCaptor.getDebugLogs()).isEmpty();
        }
    }

    @Test
    void throwsIllegalArgumentExceptionWhenTrustStoreIsCreatedWithEmptyListOfCertificates() {
        List<Certificate> certificates = Collections.emptyList();
        assertThatThrownBy(() -> KeyStoreUtils.createTrustStore(certificates))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Could not create TrustStore because certificate is absent");
    }

    @Test
    void throwsIllegalArgumentExceptionWhenTrustStoreIsCreatedWithNullAsCertificates() {
        assertThatThrownBy(() -> KeyStoreUtils.createTrustStore((List<? extends Certificate>) null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Could not create TrustStore because certificate is absent");
    }

    @Test
    void throwsIllegalArgumentExceptionWhenTrustStoreIsCreatedTrustManagerWhichDoesNotContainAnyTrustedCertificates() {
        X509ExtendedTrustManager trustManager = TrustManagerUtils.createUnsafeTrustManager();
        assertThatThrownBy(() -> KeyStoreUtils.createTrustStore(trustManager))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Could not create TrustStore because the provided TrustManager does not contain any trusted certificates");
    }

    @Test
    void throwsGenericKeyStoreExceptionWhenKeyStoreMethodThrowsAKeyStoreException() throws KeyStoreException {
        KeyStore trustStore = mock(KeyStore.class);
        when(trustStore.aliases()).thenThrow(new KeyStoreException("KABOOM!"));

        assertThatThrownBy(() -> KeyStoreUtils.containsIdentityMaterial(trustStore))
                .isInstanceOf(GenericKeyStoreException.class);
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
                  .hasMessageContaining("Failed to load the keystore from the classpath for the given path: [keystore/black-hole.jks]");
    }

    @Test
    void throwExceptionWhenLoadingNonExistingKeystoreTypeWhenUsingPath() throws IOException {
        Path trustStorePath = IOTestUtils.copyFileToHomeDirectory(KEYSTORE_LOCATION, TRUSTSTORE_FILE_NAME);

        assertThatThrownBy(() -> KeyStoreUtils.loadKeyStore(trustStorePath, KEYSTORE_PASSWORD, "unknown"))
                .isInstanceOf(GenericKeyStoreException.class)
                .hasMessageContaining("unknown not found");

        Files.delete(trustStorePath);
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
                return keyStore;
            } else {
                return invocation.callRealMethod();
            }
        })) {
            assertThatThrownBy(() -> KeyStoreUtils.createTrustStore(trustedCertificates))
                    .isInstanceOf(GenericKeyStoreException.class)
                    .hasMessageContaining("lazy");
        }
    }

    @Test
    void throwGenericKeyStoreWhenIsCertificateEntryThrowsKeyStoreExceptionForMethodGetAliasToCertificate() throws KeyStoreException {
        KeyStore keyStore = mock(KeyStore.class);
        doThrow(new KeyStoreException("lazy")).when(keyStore).isCertificateEntry(anyString());

        try (MockedStatic<KeyStoreUtils> keyStoreUtilsMock = mockStatic(KeyStoreUtils.class, invocation -> {
            Method method = invocation.getMethod();
            if ("getAliases".equals(method.getName()) && method.getParameterCount() == 1) {
                return List.of("hello");
            } else {
                return invocation.callRealMethod();
            }
        })) {
            assertThatThrownBy(() -> KeyStoreUtils.getAliasToCertificate(keyStore))
                    .isInstanceOf(GenericKeyStoreException.class)
                    .hasMessageContaining("lazy");
        }
    }

    private void resetOsName() {
        System.setProperty("os.name", ORIGINAL_OS_NAME);
    }

}
