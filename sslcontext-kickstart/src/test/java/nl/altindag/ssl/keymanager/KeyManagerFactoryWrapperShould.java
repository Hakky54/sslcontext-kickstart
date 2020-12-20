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

package nl.altindag.ssl.keymanager;

import nl.altindag.log.LogCaptor;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.X509ExtendedKeyManager;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.UnrecoverableKeyException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * @author Hakan Altindag
 */
@ExtendWith(MockitoExtension.class)
class KeyManagerFactoryWrapperShould {

    private final LogCaptor logCaptor = LogCaptor.forClass(KeyManagerFactoryWrapper.class);

    @Test
    void createInstanceFromKeyManager() {
        X509ExtendedKeyManager keyManager = mock(X509ExtendedKeyManager.class);
        KeyManagerFactoryWrapper keyManagerFactory = new KeyManagerFactoryWrapper(keyManager);

        assertThat(keyManagerFactory)
                .isNotNull()
                .isInstanceOf(KeyManagerFactory.class);

        assertThat(keyManagerFactory.getAlgorithm()).isEqualTo("no-algorithm");
        assertThat(keyManagerFactory.getKeyManagers()).containsExactly(keyManager);

        Provider provider = keyManagerFactory.getProvider();
        assertThat(provider.getName()).isEmpty();
        assertThat(provider.getInfo()).isEmpty();
        assertThat(provider.getVersion()).isEqualTo(1.0);
    }

    @Test
    void ignoreProvidedKeyStore() throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException {
        X509ExtendedKeyManager keyManager = mock(X509ExtendedKeyManager.class);
        KeyManagerFactoryWrapper keyManagerFactory = new KeyManagerFactoryWrapper(keyManager);

        keyManagerFactory.init(null, null);
        assertThat(logCaptor.getInfoLogs()).contains("Ignoring provided KeyStore");
    }
    @Test
    void ignoreProvidedManagerFactoryParameters() throws InvalidAlgorithmParameterException {
        X509ExtendedKeyManager keyManager = mock(X509ExtendedKeyManager.class);
        KeyManagerFactoryWrapper keyManagerFactory = new KeyManagerFactoryWrapper(keyManager);

        keyManagerFactory.init(null);
        assertThat(logCaptor.getInfoLogs()).contains("Ignoring provided ManagerFactoryParameters");
    }

}
