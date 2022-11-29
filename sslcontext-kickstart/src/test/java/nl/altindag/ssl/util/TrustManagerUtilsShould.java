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
import nl.altindag.ssl.exception.GenericSecurityException;
import nl.altindag.ssl.exception.GenericTrustManagerException;
import nl.altindag.ssl.trustmanager.CompositeX509ExtendedTrustManager;
import nl.altindag.ssl.trustmanager.DummyX509ExtendedTrustManager;
import nl.altindag.ssl.trustmanager.RootTrustManagerFactorySpi;
import nl.altindag.ssl.trustmanager.UnsafeX509ExtendedTrustManager;
import nl.altindag.ssl.trustmanager.X509TrustManagerWrapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.MockedStatic;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.net.ssl.CertPathTrustManagerParameters;
import javax.net.ssl.ManagerFactoryParameters;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509TrustManager;
import java.lang.reflect.Method;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CertPathBuilder;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXRevocationChecker;
import java.security.cert.X509CertSelector;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.EnumSet;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.groups.Tuple.tuple;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.times;

/**
 * @author Hakan Altindag
 */
@ExtendWith(MockitoExtension.class)
class TrustManagerUtilsShould {

    private static final String TRUSTSTORE_FILE_NAME = "truststore.jks";
    private static final char[] TRUSTSTORE_PASSWORD = new char[] {'s', 'e', 'c', 'r', 'e', 't'};
    private static final String KEYSTORE_LOCATION = "keystore/";
    private static final String ORIGINAL_OS_NAME = System.getProperty("os.name");

    @Test
    void combineTrustManagers() throws KeyStoreException {
        KeyStore trustStoreOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        KeyStore trustStoreTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + "truststore-containing-github.jks", TRUSTSTORE_PASSWORD);
        X509ExtendedTrustManager trustManager = TrustManagerUtils
                .combine(TrustManagerUtils.createTrustManager(trustStoreOne), TrustManagerUtils.createTrustManager(trustStoreTwo));

        assertThat(trustStoreOne.size()).isEqualTo(1);
        assertThat(trustStoreTwo.size()).isEqualTo(1);
        assertThat(trustManager.getAcceptedIssuers()).hasSize(2);
    }

    @Test
    void unwrapCombinedTrustManagersAndRecombineIntoSingleBaseTrustManager() throws KeyStoreException {
        KeyStore trustStoreOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        KeyStore trustStoreTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + "truststore-containing-github.jks", TRUSTSTORE_PASSWORD);

        X509ExtendedTrustManager trustManagerOne = TrustManagerUtils.createTrustManager(trustStoreOne);
        X509ExtendedTrustManager trustManagerTwo = TrustManagerUtils.createTrustManager(trustStoreTwo);

        X509ExtendedTrustManager combinedTrustManager = TrustManagerUtils.combine(trustManagerOne, trustManagerTwo);
        X509ExtendedTrustManager combinedCombinedTrustManager = TrustManagerUtils.combine(combinedTrustManager, trustManagerOne, trustManagerTwo);

        assertThat(trustStoreOne.size()).isEqualTo(1);
        assertThat(trustStoreTwo.size()).isEqualTo(1);
        assertThat(combinedTrustManager.getAcceptedIssuers()).hasSize(2);
        assertThat(combinedCombinedTrustManager.getAcceptedIssuers()).hasSize(2);

        assertThat(combinedTrustManager).isInstanceOf(CompositeX509ExtendedTrustManager.class);
        assertThat(combinedCombinedTrustManager).isInstanceOf(CompositeX509ExtendedTrustManager.class);
        assertThat(((CompositeX509ExtendedTrustManager) combinedTrustManager).getTrustManagers().size()).isEqualTo(2);
        assertThat(((CompositeX509ExtendedTrustManager) combinedCombinedTrustManager).getTrustManagers().size()).isEqualTo(4);
    }

    @Test
    void combineTrustManagersWithKeyStores() throws KeyStoreException {
        KeyStore trustStoreOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        KeyStore trustStoreTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + "truststore-containing-github.jks", TRUSTSTORE_PASSWORD);

        X509ExtendedTrustManager trustManager = TrustManagerUtils
                .combine(TrustManagerUtils.createTrustManager(trustStoreOne, trustStoreTwo));

        assertThat(trustStoreOne.size()).isEqualTo(1);
        assertThat(trustStoreTwo.size()).isEqualTo(1);
        assertThat(trustManager.getAcceptedIssuers()).hasSize(2);
    }

    @Test
    void combineTrustManagersWhileFilteringDuplicateCertificates() throws KeyStoreException {
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
    void createTrustManagerWithCustomSecurityProviderBasedOnTheName() {
        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);

        X509ExtendedTrustManager trustManager = TrustManagerUtils.createTrustManager(trustStore, TrustManagerFactory.getDefaultAlgorithm(), "SunJSSE");

        assertThat(trustManager).isNotNull();
    }

    @Test
    void createTrustManagerWithCustomSecurityProvider() {
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
        String operatingSystem = System.getProperty("os.name").toLowerCase();
        try (MockedStatic<KeyStoreUtils> mockedStatic = mockStatic(KeyStoreUtils.class, invocation -> {
            Method method = invocation.getMethod();
            if ("createKeyStore".equals(method.getName())
                    && method.getParameterCount() == 2
                    && operatingSystem.contains("mac")) {
                return KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
            } else {
                return invocation.callRealMethod();
            }
        })) {
            Optional<X509ExtendedTrustManager> trustManager = TrustManagerUtils.createTrustManagerWithSystemTrustedCertificates();
            if (operatingSystem.contains("mac") || operatingSystem.contains("windows")) {
                assertThat(trustManager).isPresent();
                assertThat((trustManager).get().getAcceptedIssuers()).hasSizeGreaterThan(0);
            }

            if (operatingSystem.contains("linux")) {
                assertThat(trustManager).isNotPresent();
            }
        }
    }

    @Test
    void createTrustManagerWhenProvidingACustomTrustStore() {
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
    void createTrustManagerFromMultipleTrustManagers() {
        KeyStore trustStoreOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        KeyStore trustStoreTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + "truststore-containing-github.jks", TRUSTSTORE_PASSWORD);

        X509ExtendedTrustManager trustManagerOne = TrustManagerUtils.createTrustManager(trustStoreOne);
        X509ExtendedTrustManager trustManagerTwo = TrustManagerUtils.createTrustManager(trustStoreTwo);

        X509ExtendedTrustManager trustManager = TrustManagerUtils.trustManagerBuilder()
                .withTrustManager(trustManagerOne)
                .withTrustManager(trustManagerTwo)
                .build();

        assertThat(trustManager).isNotNull();
    }

    @Test
    void createTrustManagerFromMultipleTrustManagersUsingVarArgs() {
        KeyStore trustStoreOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        KeyStore trustStoreTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + "truststore-containing-github.jks", TRUSTSTORE_PASSWORD);

        X509ExtendedTrustManager trustManagerOne = TrustManagerUtils.createTrustManager(trustStoreOne);
        X509ExtendedTrustManager trustManagerTwo = TrustManagerUtils.createTrustManager(trustStoreTwo);

        X509ExtendedTrustManager trustManager = TrustManagerUtils.trustManagerBuilder()
                .withTrustManagers(trustManagerOne, trustManagerTwo)
                .build();

        assertThat(trustManager).isNotNull();
    }

    @Test
    void createTrustManagerFromMultipleTrustManagersUsingList() {
        KeyStore trustStoreOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        KeyStore trustStoreTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + "truststore-containing-github.jks", TRUSTSTORE_PASSWORD);

        X509ExtendedTrustManager trustManagerOne = TrustManagerUtils.createTrustManager(trustStoreOne);
        X509ExtendedTrustManager trustManagerTwo = TrustManagerUtils.createTrustManager(trustStoreTwo);

        X509ExtendedTrustManager trustManager = TrustManagerUtils.trustManagerBuilder()
                .withTrustManagers(Arrays.asList(trustManagerOne, trustManagerTwo))
                .build();

        assertThat(trustManager).isNotNull();
    }

    @Test
    void createTrustManagerFromMultipleTrustStoresUsingVarArgs() {
        KeyStore trustStoreOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        KeyStore trustStoreTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + "truststore-containing-github.jks", TRUSTSTORE_PASSWORD);

        X509ExtendedTrustManager trustManager = TrustManagerUtils.trustManagerBuilder()
                .withTrustStores(trustStoreOne, trustStoreTwo)
                .build();

        assertThat(trustManager).isNotNull();
    }

    @Test
    void createTrustManagerFromMultipleTrustStoresUsingList() {
        KeyStore trustStoreOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        KeyStore trustStoreTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + "truststore-containing-github.jks", TRUSTSTORE_PASSWORD);

        X509ExtendedTrustManager trustManager = TrustManagerUtils.trustManagerBuilder()
                .withTrustStores(Arrays.asList(trustStoreOne, trustStoreTwo))
                .build();

        assertThat(trustManager).isNotNull();
    }

    @Test
    void createTrustManagerFromMultipleTrustStores() {
        KeyStore trustStoreOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        KeyStore trustStoreTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + "truststore-containing-github.jks", TRUSTSTORE_PASSWORD);

        X509ExtendedTrustManager trustManager = TrustManagerUtils.trustManagerBuilder()
                .withTrustStore(trustStoreOne)
                .withTrustStore(trustStoreTwo)
                .build();

        assertThat(trustManager).isNotNull();
    }

    @Test
    void loadLinuxSystemKeyStoreReturnsOptionalOfEmpty() {
        System.setProperty("os.name", "linux");

        Optional<X509ExtendedTrustManager> trustManager = TrustManagerUtils.createTrustManagerWithSystemTrustedCertificates();
        assertThat(trustManager).isNotPresent();

        resetOsName();
    }

    @Test
    void createTrustManagerFromMultipleTrustStoresWithTrustManagerFactoryAlgorithm() {
        KeyStore trustStoreOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        KeyStore trustStoreTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + "truststore-containing-github.jks", TRUSTSTORE_PASSWORD);

        X509ExtendedTrustManager trustManager = TrustManagerUtils.trustManagerBuilder()
                .withTrustStore(trustStoreOne, TrustManagerFactory.getDefaultAlgorithm())
                .withTrustStore(trustStoreTwo, TrustManagerFactory.getDefaultAlgorithm())
                .build();

        assertThat(trustManager).isNotNull();
    }

    @Test
    void createTrustManagerFromManagerParameters() throws NoSuchAlgorithmException, KeyStoreException, InvalidAlgorithmParameterException {
        KeyStore trustStoreOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        KeyStore trustStoreTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + "truststore-containing-github.jks", TRUSTSTORE_PASSWORD);

        CertPathTrustManagerParameters certPathTrustManagerParametersOne = createTrustManagerParameters(trustStoreOne);
        CertPathTrustManagerParameters certPathTrustManagerParametersTwo = createTrustManagerParameters(trustStoreTwo);

        X509ExtendedTrustManager trustManager = TrustManagerUtils.createTrustManager(certPathTrustManagerParametersOne, certPathTrustManagerParametersTwo);

        assertThat(trustManager).isNotNull();
    }

    @Test
    void createTrustManagerFromManagerParametersWithTrustManagerFactoryAlgorithm() throws NoSuchAlgorithmException, KeyStoreException, InvalidAlgorithmParameterException {
        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        CertPathTrustManagerParameters certPathTrustManagerParameters = createTrustManagerParameters(trustStore);

        X509ExtendedTrustManager trustManager = TrustManagerUtils.createTrustManager(certPathTrustManagerParameters, TrustManagerFactory.getDefaultAlgorithm());

        assertThat(trustManager).isNotNull();
    }

    @Test
    void createTrustManagerFromManagerParametersWithSecurityProviderName() throws NoSuchAlgorithmException, KeyStoreException, InvalidAlgorithmParameterException {
        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        CertPathTrustManagerParameters certPathTrustManagerParameters = createTrustManagerParameters(trustStore);

        X509ExtendedTrustManager trustManager = TrustManagerUtils.createTrustManager(certPathTrustManagerParameters, TrustManagerFactory.getDefaultAlgorithm(), "SunJSSE");

        assertThat(trustManager).isNotNull();
    }

    @Test
    void createTrustManagerFromManagerParametersWithSecurityProvider() throws NoSuchAlgorithmException, KeyStoreException, InvalidAlgorithmParameterException {
        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        CertPathTrustManagerParameters certPathTrustManagerParameters = createTrustManagerParameters(trustStore);

        X509ExtendedTrustManager trustManager = TrustManagerUtils.createTrustManager(certPathTrustManagerParameters, TrustManagerFactory.getDefaultAlgorithm(), Security.getProvider("SunJSSE"));

        assertThat(trustManager).isNotNull();
    }

    @Test
    void createOnlyUnsafeTrustManagerWhileProvidingMultipleTrustManagers() {
        LogCaptor logCaptor = LogCaptor.forRoot();

        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);

        X509ExtendedTrustManager trustManager = TrustManagerUtils.combine(
                TrustManagerUtils.createTrustManager(trustStore),
                TrustManagerUtils.createUnsafeTrustManager()
        );

        assertThat(trustManager).isInstanceOf(UnsafeX509ExtendedTrustManager.class);

        assertThat(logCaptor.getDebugLogs()).contains("Unsafe TrustManager is being used therefore other trust managers will not be included for constructing the base trust manager");
    }

    @Test
    void doNotLogAnythingWhenUnsafeTrustManagerIsBeingUsedWithoutAdditionalTrustManagers() {
        LogCaptor logCaptor = LogCaptor.forRoot();

        X509ExtendedTrustManager trustManager = TrustManagerUtils.combine(
                TrustManagerUtils.createUnsafeTrustManager()
        );

        assertThat(trustManager).isInstanceOf(UnsafeX509ExtendedTrustManager.class);

        assertThat(logCaptor.getLogs()).isEmpty();
    }

    @Test
    void notIncludeTrustManagerWhichDoesNotContainTrustedCertificates() {
        KeyStore trustStoreOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        KeyStore trustStoreTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + "truststore-containing-github.jks", TRUSTSTORE_PASSWORD);
        KeyStore emptyTrustStore = KeyStoreUtils.createKeyStore();

        X509ExtendedTrustManager trustManager = TrustManagerUtils.createTrustManager(trustStoreOne, trustStoreTwo, emptyTrustStore);

        assertThat(trustManager).isInstanceOf(CompositeX509ExtendedTrustManager.class);

        CompositeX509ExtendedTrustManager compositeX509ExtendedTrustManager = (CompositeX509ExtendedTrustManager) trustManager;
        assertThat(compositeX509ExtendedTrustManager.getTrustManagers()).hasSize(2);
    }

    @Test
    void ignoreOtherTrustMaterialIfDummyTrustManagerIsPresent() {
        LogCaptor logCaptor = LogCaptor.forRoot();

        KeyStore trustStoreOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        KeyStore trustStoreTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + "truststore-containing-github.jks", TRUSTSTORE_PASSWORD);

        X509ExtendedTrustManager trustManager = TrustManagerUtils.trustManagerBuilder()
                .withTrustStore(trustStoreOne)
                .withTrustStore(trustStoreTwo)
                .withTrustManager(TrustManagerUtils.createDummyTrustManager())
                .build();

        assertThat(trustManager).isInstanceOf(DummyX509ExtendedTrustManager.class);
        assertThat(logCaptor.getDebugLogs()).contains("Dummy TrustManager is being used therefore other trust managers will not be included for constructing the base trust manager");
    }

    @Test
    void doNotLogAnythingWhenDummyTrustManagerIsBeingUsedWithoutAdditionalTrustManagers() {
        LogCaptor logCaptor = LogCaptor.forRoot();

        X509ExtendedTrustManager trustManager = TrustManagerUtils.combine(
                TrustManagerUtils.createDummyTrustManager()
        );

        assertThat(trustManager).isInstanceOf(DummyX509ExtendedTrustManager.class);

        assertThat(logCaptor.getLogs()).isEmpty();
    }

    @Test
    void notCombineIfOnlyOneTrustManagerContainsTrustedCertificates() {
        X509ExtendedTrustManager emptyTrustManager = TrustManagerUtils.createTrustManager(KeyStoreUtils.createKeyStore());
        X509ExtendedTrustManager filledTrustManager = TrustManagerUtils.createTrustManager(KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD));

        X509ExtendedTrustManager trustManager = TrustManagerUtils.combine(emptyTrustManager, filledTrustManager);

        assertThat(trustManager).isNotInstanceOf(CompositeX509ExtendedTrustManager.class);
    }

    @Test
    void setDefault() {
        try (MockedStatic<RootTrustManagerFactorySpi> rootTrustManagerFactorySpiMock = mockStatic(RootTrustManagerFactorySpi.class, InvocationOnMock::callRealMethod)) {

            X509ExtendedTrustManager trustManager = TrustManagerUtils.createDummyTrustManager();
            TrustManagerUtils.setDefault(trustManager);

            rootTrustManagerFactorySpiMock.verify(() -> RootTrustManagerFactorySpi.setTrustManager(trustManager), times(1));

            Provider[] providers = Security.getProviders();
            assertThat(providers).isNotEmpty();
            assertThat(providers[0].getName()).isEqualTo("Fenix");

            List<Provider.Service> services = new ArrayList<>(providers[0].getServices());
            assertThat(services).hasSize(2);

            assertThat(services).extracting(Provider.Service::getType, Provider.Service::getAlgorithm)
                    .containsExactlyInAnyOrder(
                            tuple("TrustManagerFactory", "SunX509"),
                            tuple("TrustManagerFactory", "PKIX")
                    );
        }

        Security.removeProvider("Fenix");
    }

    private CertPathTrustManagerParameters createTrustManagerParameters(KeyStore trustStore) throws NoSuchAlgorithmException, KeyStoreException, InvalidAlgorithmParameterException {
        CertPathBuilder certPathBuilder = CertPathBuilder.getInstance("PKIX");
        PKIXRevocationChecker revocationChecker = (PKIXRevocationChecker) certPathBuilder.getRevocationChecker();
        revocationChecker.setOptions(EnumSet.of(PKIXRevocationChecker.Option.NO_FALLBACK));
        PKIXBuilderParameters pkixParams = new PKIXBuilderParameters(trustStore, new X509CertSelector());
        pkixParams.addCertPathChecker(revocationChecker);
        return new CertPathTrustManagerParameters(pkixParams);
    }

    @Test
    void throwExceptionWhenMultipleTrustManagersCombinedDontHaveTrustedCertificates() {
        X509ExtendedTrustManager trustManagerOne = TrustManagerUtils.createTrustManager(KeyStoreUtils.createKeyStore());
        X509ExtendedTrustManager trustManagerTwo = TrustManagerUtils.createTrustManager(KeyStoreUtils.createKeyStore());

        assertThatThrownBy(() -> TrustManagerUtils.combine(trustManagerOne, trustManagerTwo))
                .hasMessageContaining("The provided trust material does not contain any trusted certificate.");
    }

    @Test
    void throwExceptionWhenInvalidTrustManagerAlgorithmIsProvided() {
        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);

        assertThatThrownBy(() -> TrustManagerUtils.createTrustManager(trustStore, "ABCD"))
                .isInstanceOf(GenericTrustManagerException.class)
                .hasMessage("java.security.NoSuchAlgorithmException: ABCD TrustManagerFactory not available");
    }

    @Test
    void throwExceptionWhenInvalidSecurityProviderNameIsProvided() {
        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        String trustManagerFactoryAlgorithm = TrustManagerFactory.getDefaultAlgorithm();

        assertThatThrownBy(() -> TrustManagerUtils.createTrustManager(trustStore, trustManagerFactoryAlgorithm, "test"))
                .isInstanceOf(GenericTrustManagerException.class)
                .hasMessage("java.security.NoSuchProviderException: no such provider: test");
    }

    @Test
    void throwExceptionWhenInvalidSecurityProviderNameIsProvidedForTheTrustManagerFactoryAlgorithm() {
        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        String trustManagerFactoryAlgorithm = TrustManagerFactory.getDefaultAlgorithm();

        assertThatThrownBy(() -> TrustManagerUtils.createTrustManager(trustStore, trustManagerFactoryAlgorithm, "SUN"))
                .isInstanceOf(GenericTrustManagerException.class)
                .hasMessage("java.security.NoSuchAlgorithmException: no such algorithm: PKIX for provider SUN");
    }

    @Test
    void throwExceptionWhenInvalidSecurityProviderIsProvidedForTheTrustManagerFactoryAlgorithm() {
        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        String trustManagerFactoryAlgorithm = TrustManagerFactory.getDefaultAlgorithm();
        Provider sunSecurityProvider = Security.getProvider("SUN");

        assertThatThrownBy(() -> TrustManagerUtils.createTrustManager(trustStore, trustManagerFactoryAlgorithm, sunSecurityProvider))
                .isInstanceOf(GenericTrustManagerException.class)
                .hasMessage("java.security.NoSuchAlgorithmException: no such algorithm: PKIX for provider SUN");
    }

    @Test
    void throwExceptionWhenInvalidTrustManagerAlgorithmIsProvidedWhenUsingManagerFactoryParameters() {
        assertThatThrownBy(() -> TrustManagerUtils.createTrustManager(mock(ManagerFactoryParameters.class), "ABCD"))
                .isInstanceOf(GenericTrustManagerException.class)
                .hasMessage("java.security.NoSuchAlgorithmException: ABCD TrustManagerFactory not available");
    }

    @Test
    void throwExceptionWhenInvalidSecurityProviderIsProvidedForTheTrustManagerFactoryAlgorithmWhenUsingManagerFactoryParameters() {
        String trustManagerFactoryAlgorithm = TrustManagerFactory.getDefaultAlgorithm();
        Provider sunSecurityProvider = Security.getProvider("SUN");

        assertThatThrownBy(() -> TrustManagerUtils.createTrustManager(mock(ManagerFactoryParameters.class), trustManagerFactoryAlgorithm, sunSecurityProvider))
                .isInstanceOf(GenericTrustManagerException.class)
                .hasMessage("java.security.NoSuchAlgorithmException: no such algorithm: PKIX for provider SUN");
    }

    @Test
    void throwExceptionWhenInvalidSecurityProviderNameIsProvidedForTheTrustManagerFactoryAlgorithmWhenUsingManagerFactoryParameters() {
        String trustManagerFactoryAlgorithm = TrustManagerFactory.getDefaultAlgorithm();

        assertThatThrownBy(() -> TrustManagerUtils.createTrustManager(mock(ManagerFactoryParameters.class), trustManagerFactoryAlgorithm, "SUN"))
                .isInstanceOf(GenericTrustManagerException.class)
                .hasMessage("java.security.NoSuchAlgorithmException: no such algorithm: PKIX for provider SUN");
    }

    @Test
    void throwExceptionWhenSomethingUnexpectedHappensWhileInitializingTrustManagerWithManagerFactoryParameters() throws InvalidAlgorithmParameterException {
        TrustManagerFactory trustManagerFactory = mock(TrustManagerFactory.class);
        doThrow(new InvalidAlgorithmParameterException("KABOOM!!"))
                .when(trustManagerFactory).init(any(ManagerFactoryParameters.class));

        assertThatThrownBy(() -> TrustManagerUtils.createTrustManager(mock(ManagerFactoryParameters.class), trustManagerFactory))
                .isInstanceOf(GenericTrustManagerException.class)
                .hasMessageContaining("KABOOM!!");
    }

    @Test
    void throwGenericSecurityExceptionWhenTrustManagerFactoryCanNotInitializeWithTheProvidedTrustStore() throws KeyStoreException {
        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        TrustManagerFactory trustManagerFactory = mock(TrustManagerFactory.class);

        doThrow(new KeyStoreException("KABOOOM!")).when(trustManagerFactory).init(any(KeyStore.class));

        assertThatThrownBy(() -> TrustManagerUtils.createTrustManager(trustStore, trustManagerFactory))
                .isInstanceOf(GenericSecurityException.class)
                .hasMessage("java.security.KeyStoreException: KABOOOM!");
    }

    @Test
    void throwGenericTrustManagerExceptionWhenProvidingEmptyListOfTrustManagersWhenCombining() {
        List<X509TrustManager> trustManagers = Collections.emptyList();
        assertThatThrownBy(() -> TrustManagerUtils.combine(trustManagers))
                .isInstanceOf(GenericTrustManagerException.class)
                .hasMessage("Input does not contain TrustManager");
    }

    @Test
    void throwExceptionWhenUnsupportedTrustManagerIsProvidedWhenSwappingTrustManager() {
        KeyStore trustStoreOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        KeyStore trustStoreTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + "truststore-containing-github.jks", TRUSTSTORE_PASSWORD);

        X509ExtendedTrustManager trustManagerOne = TrustManagerUtils.createTrustManager(trustStoreOne);
        X509ExtendedTrustManager trustManagerTwo = TrustManagerUtils.createTrustManager(trustStoreTwo);

        assertThatThrownBy(() -> TrustManagerUtils.swapTrustManager(trustManagerOne, trustManagerTwo))
                .isInstanceOf(GenericTrustManagerException.class)
                .hasMessage("The baseTrustManager is from the instance of [sun.security.ssl.X509TrustManagerImpl] " +
                        "and should be an instance of [nl.altindag.ssl.trustmanager.HotSwappableX509ExtendedTrustManager].");
    }

    @Test
    void throwExceptionWhenUnsupportedTrustManagerIsProvidedWhenSwappingTrustManagerWithANewTrustManager() {
        KeyStore trustStoreOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        KeyStore trustStoreTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + "truststore-containing-github.jks", TRUSTSTORE_PASSWORD);

        X509ExtendedTrustManager baseTrustManager = TrustManagerUtils.createSwappableTrustManager(TrustManagerUtils.createTrustManager(trustStoreOne));
        X509ExtendedTrustManager newTrustManager = TrustManagerUtils.createSwappableTrustManager(TrustManagerUtils.createTrustManager(trustStoreTwo));

        assertThatThrownBy(() -> TrustManagerUtils.swapTrustManager(baseTrustManager, newTrustManager))
                .isInstanceOf(GenericTrustManagerException.class)
                .hasMessage("The newTrustManager should not be an instance of [nl.altindag.ssl.trustmanager.HotSwappableX509ExtendedTrustManager]");
    }

    private void resetOsName() {
        System.setProperty("os.name", ORIGINAL_OS_NAME);
    }

}
