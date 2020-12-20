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

package nl.altindag.ssl.trustmanager;

import nl.altindag.log.LogCaptor;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.net.ssl.ManagerFactoryParameters;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedTrustManager;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.Provider;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * @author Hakan Altindag
 */
@ExtendWith(MockitoExtension.class)
class TrustManagerFactoryWrapperShould {

    private final LogCaptor logCaptor = LogCaptor.forClass(TrustManagerFactoryWrapper.class);

    @Test
    void createInstanceFromTrustManager() {
        X509ExtendedTrustManager trustManager = mock(X509ExtendedTrustManager.class);
        TrustManagerFactoryWrapper trustManagerFactory = new TrustManagerFactoryWrapper(trustManager);

        assertThat(trustManagerFactory)
                .isNotNull()
                .isInstanceOf(TrustManagerFactory.class);

        assertThat(trustManagerFactory.getAlgorithm()).isEqualTo("no-algorithm");
        assertThat(trustManagerFactory.getTrustManagers()).containsExactly(trustManager);

        Provider provider = trustManagerFactory.getProvider();
        assertThat(provider.getName()).isEmpty();
        assertThat(provider.getInfo()).isEmpty();
        assertThat(provider.getVersion()).isEqualTo(1.0);
    }

    @Test
    void ignoreProvidedKeyStore() throws KeyStoreException {
        X509ExtendedTrustManager trustManager = mock(X509ExtendedTrustManager.class);
        TrustManagerFactoryWrapper trustManagerFactory = new TrustManagerFactoryWrapper(trustManager);

        trustManagerFactory.init((KeyStore) null);
        assertThat(logCaptor.getInfoLogs()).contains("Ignoring provided KeyStore");
    }
    @Test
    void ignoreProvidedManagerFactoryParameters() throws InvalidAlgorithmParameterException {
        X509ExtendedTrustManager trustManager = mock(X509ExtendedTrustManager.class);
        TrustManagerFactoryWrapper trustManagerFactory = new TrustManagerFactoryWrapper(trustManager);

        trustManagerFactory.init((ManagerFactoryParameters) null);
        assertThat(logCaptor.getInfoLogs()).contains("Ignoring provided ManagerFactoryParameters");
    }

}
