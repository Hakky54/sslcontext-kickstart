/*
 * Copyright 2019-2022 the original author or authors.
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
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.invocation.InvocationOnMock;

import static org.mockito.Mockito.any;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.times;

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

}