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

import nl.altindag.ssl.SSLFactory;
import nl.altindag.ssl.keymanager.RootKeyManagerFactorySpi;
import nl.altindag.ssl.trustmanager.RootTrustManagerFactorySpi;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.invocation.InvocationOnMock;

import java.security.Provider;
import java.security.Provider.Service;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.groups.Tuple.tuple;
import static org.mockito.Mockito.*;

class SSLFactoryUtilsShould {

    @Test
    void notReloadWhenBaseTrustManagerIsAbsent() {
        try (MockedStatic<TrustManagerUtils> mock = mockStatic(TrustManagerUtils.class, InvocationOnMock::callRealMethod)) {
            SSLFactory baseSslFactory = SSLFactory.builder()
                    .withDummyIdentityMaterial()
                    .withSwappableIdentityMaterial()
                    .build();

            SSLFactory updatedSslFactory = SSLFactory.builder()
                    .withDummyTrustMaterial()
                    .build();

            SSLFactoryUtils.reload(baseSslFactory, updatedSslFactory);

            mock.verify(() -> TrustManagerUtils.swapTrustManager(any(), any()), times(0));
        }
    }

    @Test
    void notReloadWhenBaseKeyManagerIsAbsent() {
        try (MockedStatic<KeyManagerUtils> mock = mockStatic(KeyManagerUtils.class, InvocationOnMock::callRealMethod)) {
            SSLFactory baseSslFactory = SSLFactory.builder()
                    .withDummyTrustMaterial()
                    .withSwappableTrustMaterial()
                    .build();

            SSLFactory updatedSslFactory = SSLFactory.builder()
                    .withDummyIdentityMaterial()
                    .build();

            SSLFactoryUtils.reload(baseSslFactory, updatedSslFactory);

            mock.verify(() -> KeyManagerUtils.swapKeyManager(any(), any()), times(0));
        }
    }

    @Test
    void notReloadWhenUpdatedTrustManagerIsAbsent() {
        try (MockedStatic<TrustManagerUtils> mock = mockStatic(TrustManagerUtils.class, InvocationOnMock::callRealMethod)) {
            SSLFactory baseSslFactory = SSLFactory.builder()
                    .withDummyTrustMaterial()
                    .withSwappableTrustMaterial()
                    .build();

            SSLFactory updatedSslFactory = SSLFactory.builder()
                    .withDummyIdentityMaterial()
                    .build();

            SSLFactoryUtils.reload(baseSslFactory, updatedSslFactory);

            mock.verify(() -> TrustManagerUtils.swapTrustManager(any(), any()), times(0));
        }
    }

    @Test
    void notReloadWhenUpdatedKeyManagerIsAbsent() {
        try (MockedStatic<KeyManagerUtils> mock = mockStatic(KeyManagerUtils.class, InvocationOnMock::callRealMethod)) {
            SSLFactory baseSslFactory = SSLFactory.builder()
                    .withDummyIdentityMaterial()
                    .withSwappableIdentityMaterial()
                    .build();

            SSLFactory updatedSslFactory = SSLFactory.builder()
                    .withDummyTrustMaterial()
                    .build();

            SSLFactoryUtils.reload(baseSslFactory, updatedSslFactory);

            mock.verify(() -> KeyManagerUtils.swapKeyManager(any(), any()), times(0));
        }
    }

    @Test
    void reloadTrustManager() {
        try (MockedStatic<TrustManagerUtils> mock = mockStatic(TrustManagerUtils.class, InvocationOnMock::callRealMethod)) {
            SSLFactory baseSslFactory = SSLFactory.builder()
                    .withDummyTrustMaterial()
                    .withSwappableTrustMaterial()
                    .build();

            SSLFactory updatedSslFactory = SSLFactory.builder()
                    .withDummyTrustMaterial()
                    .build();

            SSLFactoryUtils.reload(baseSslFactory, updatedSslFactory);

            mock.verify(() -> TrustManagerUtils.swapTrustManager(any(), any()), times(1));
        }
    }

    @Test
    void reloadKeyManager() {
        try (MockedStatic<KeyManagerUtils> mock = mockStatic(KeyManagerUtils.class, InvocationOnMock::callRealMethod)) {
            SSLFactory baseSslFactory = SSLFactory.builder()
                    .withDummyIdentityMaterial()
                    .withSwappableIdentityMaterial()
                    .build();

            SSLFactory updatedSslFactory = SSLFactory.builder()
                    .withDummyIdentityMaterial()
                    .build();

            SSLFactoryUtils.reload(baseSslFactory, updatedSslFactory);

            mock.verify(() -> KeyManagerUtils.swapKeyManager(any(), any()), times(1));
        }
    }

    @Test
    void configureAsDefault() {
        SSLFactory sslFactory = SSLFactory.builder()
                .withDummyIdentityMaterial()
                .withDummyTrustMaterial()
                .build();

        assertThat(sslFactory.getKeyManager()).isPresent();
        assertThat(sslFactory.getTrustManager()).isPresent();

        try (MockedStatic<RootKeyManagerFactorySpi> rootKeyManagerFactorySpiMock = mockStatic(RootKeyManagerFactorySpi.class, InvocationOnMock::callRealMethod);
             MockedStatic<RootTrustManagerFactorySpi> rootTrustManagerFactorySpiMock = mockStatic(RootTrustManagerFactorySpi.class, InvocationOnMock::callRealMethod)) {

            SSLFactoryUtils.configureAsDefault(sslFactory);

            rootKeyManagerFactorySpiMock.verify(() -> RootKeyManagerFactorySpi.setKeyManager(sslFactory.getKeyManager().get()), times(1));
            rootTrustManagerFactorySpiMock.verify(() -> RootTrustManagerFactorySpi.setTrustManager(sslFactory.getTrustManager().get()), times(1));


            Provider[] providers = Security.getProviders();
            assertThat(providers).isNotEmpty();
            assertThat(providers[0].getName()).isEqualTo("Fenix");

            List<Service> services = new ArrayList<>(providers[0].getServices());
            assertThat(services).hasSize(2);

            assertThat(services).extracting(Service::getType, Service::getAlgorithm)
                    .containsExactlyInAnyOrder(
                            tuple("KeyManagerFactory", "PKIX"),
                            tuple("TrustManagerFactory", "PKIX")
                    );
        }

        Security.removeProvider("Fenix");
    }

}