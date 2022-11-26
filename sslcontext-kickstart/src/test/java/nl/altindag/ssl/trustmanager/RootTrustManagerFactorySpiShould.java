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
package nl.altindag.ssl.trustmanager;

import nl.altindag.log.LogCaptor;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.net.ssl.ManagerFactoryParameters;
import java.security.KeyStore;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * @author Hakan Altindag
 */
class RootTrustManagerFactorySpiShould {

    private static LogCaptor logCaptor;

    @BeforeAll
    static void setupLogCaptor() {
        logCaptor = LogCaptor.forClass(RootTrustManagerFactorySpi.class);
    }

    @AfterEach
    void clearCapturedLogs() {
        logCaptor.clearLogs();
    }

    @AfterAll
    static void closeLogCaptor() {
        logCaptor.close();
    }

    @Test
    void ignoreProvidedKeyStore() {
        RootTrustManagerFactorySpi trustManagerFactorySpi = new RootTrustManagerFactorySpi();

        trustManagerFactorySpi.engineInit((KeyStore) null);
        assertThat(logCaptor.getDebugLogs()).contains("Ignoring provided KeyStore");
    }

    @Test
    void ignoreProvidedManagerFactoryParameters() {
        RootTrustManagerFactorySpi trustManagerFactorySpi = new RootTrustManagerFactorySpi();

        trustManagerFactorySpi.engineInit((ManagerFactoryParameters) null);
        assertThat(logCaptor.getDebugLogs()).contains("Ignoring provided ManagerFactoryParameters");
    }

    @Test
    void trustManagerCanNotBeNull() {
        assertThatThrownBy(() -> RootTrustManagerFactorySpi.setTrustManager(null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("No valid TrustManager has been provided. TrustManager must be present, but was absent.");
    }

}
