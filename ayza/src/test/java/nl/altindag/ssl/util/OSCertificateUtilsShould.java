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
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;

import java.io.IOException;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;

/**
 * @author Hakan Altindag
 */
class OSCertificateUtilsShould {

    private final OSCertificateUtils oscertificateUtils = new OSCertificateUtils() {
        @Override
        List<KeyStore> getTrustStores() {
            return Collections.emptyList();
        }
    };

    @Test
    void loadCertificateIgnoresInvalidFiles() throws IOException {
        Path path = IOTestUtils.copyFileToHomeDirectory("pem/", "invalid.pem");
        List<Certificate> certificates = oscertificateUtils.loadCertificate(path);
        assertThat(certificates).isEmpty();
        Files.delete(path);
    }

    @Test
    void loadCertificateReadsValidFiles() throws IOException {
        Path path = IOTestUtils.copyFileToHomeDirectory("pem/", "badssl-certificate.pem");
        List<Certificate> certificates = oscertificateUtils.loadCertificate(path);
        assertThat(certificates).isNotEmpty();
        Files.delete(path);
    }

    @Test
    void createKeyStoreIfAvailableReturnsEmptyForNonExistingKeyStoreType() {
        OSCertificateUtils osCertificateUtils = new OSCertificateUtils() {
            @Override
            List<KeyStore> getTrustStores() {
                return Collections.emptyList();
            }
        };

        Optional<KeyStore> bananaKeyStore = osCertificateUtils.createKeyStoreIfAvailable("Banana", null);
        assertThat(bananaKeyStore).isEmpty();
    }

    @Test
    void createKeyStoreIfAvailableReturnsFilledKeyStore() {
        LogCaptor logCaptor = LogCaptor.forClass(OSCertificateUtils.class);

        KeyStore bananaKeyStore = mock(KeyStore.class);

        try (MockedStatic<KeyStoreUtils> mockedStatic = mockStatic(KeyStoreUtils.class, invocation -> {
            Method method = invocation.getMethod();
            if ("createKeyStore".equals(method.getName()) && method.getParameterCount() == 2 && "Banana".equals(invocation.getArgument(0))) {
                return bananaKeyStore;
            } else if ("countAmountOfTrustMaterial".equals(method.getName())) {
                return 2;
            } else {
                return invocation.callRealMethod();
            }
        })) {
            OSCertificateUtils osCertificateUtils = new OSCertificateUtils() {
                @Override
                List<KeyStore> getTrustStores() {
                    return Collections.emptyList();
                }
            };

            Optional<KeyStore> keyStore = osCertificateUtils.createKeyStoreIfAvailable("Banana", null);
            assertThat(keyStore).isPresent();
            assertThat(logCaptor.getDebugLogs()).contains("Successfully loaded KeyStore of the type [Banana] having [2] entries");
        }
    }

    @Test
    void createKeyStoreIfAvailableReturnsFilledKeyStoreWithoutLoggingIfDebugIsDisabled() {
        LogCaptor logCaptor = LogCaptor.forClass(OSCertificateUtils.class);
        logCaptor.setLogLevelToInfo();

        KeyStore bananaKeyStore = mock(KeyStore.class);

        try (MockedStatic<KeyStoreUtils> mockedStatic = mockStatic(KeyStoreUtils.class, invocation -> {
            Method method = invocation.getMethod();
            if ("createKeyStore".equals(method.getName()) && method.getParameterCount() == 2 && "Banana".equals(invocation.getArgument(0))) {
                return bananaKeyStore;
            } else if ("countAmountOfTrustMaterial".equals(method.getName())) {
                return 2;
            } else {
                return invocation.callRealMethod();
            }
        })) {
            OSCertificateUtils osCertificateUtils = new OSCertificateUtils() {
                @Override
                List<KeyStore> getTrustStores() {
                    return Collections.emptyList();
                }
            };

            Optional<KeyStore> keyStore = osCertificateUtils.createKeyStoreIfAvailable("Banana", null);
            assertThat(keyStore).isPresent();
            assertThat(logCaptor.getDebugLogs()).isEmpty();
        }
    }

}
