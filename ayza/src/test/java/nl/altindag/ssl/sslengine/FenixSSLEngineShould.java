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
package nl.altindag.ssl.sslengine;

import nl.altindag.log.LogCaptor;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

class FenixSSLEngineShould {

    private SSLEngine sslEngine;
    private SSLEngine wrapperSslEngine;
    private SSLParameters sslParameters;
    private static LogCaptor logCaptor;

    @BeforeAll
    static void setupLogCaptor() {
        logCaptor = LogCaptor.forClass(FenixSSLEngine.class);
    }

    @AfterAll
    static void closeLogCaptor() {
        logCaptor.close();
    }

    @BeforeEach
    void setup() {
        sslParameters = new SSLParameters();
        sslEngine = mock(SSLEngine.class);
        wrapperSslEngine = new FenixSSLEngine(sslEngine, sslParameters);
    }

    @AfterEach
    void clearLogs() {
        logCaptor.clearLogs();
    }

    @Test
    void setSSLParameters() {
        wrapperSslEngine.setSSLParameters(null);
        assertThat(logCaptor.getDebugLogs()).containsExactly("Ignoring provided ssl parameters");
    }

    @Test
    void setEnabledCipherSuites() {
        wrapperSslEngine.setEnabledCipherSuites(null);
        assertThat(logCaptor.getDebugLogs()).containsExactly("Ignoring provided ciphers");
    }

    @Test
    void setEnabledProtocols() {
        wrapperSslEngine.setEnabledProtocols(null);
        assertThat(logCaptor.getDebugLogs()).containsExactly("Ignoring provided protocols");
    }

    @Test
    void setNeedClientAuth() {
        wrapperSslEngine.setNeedClientAuth(true);
        assertThat(logCaptor.getDebugLogs()).containsExactly("Ignoring provided indicator for need client auth");
    }

    @Test
    void setWantClientAuth() {
        wrapperSslEngine.setWantClientAuth(true);
        assertThat(logCaptor.getDebugLogs()).containsExactly("Ignoring provided indicator for want client auth");
    }

    @Test
    void getEnabledCipherSuites() {
        wrapperSslEngine.getEnabledCipherSuites();

        verify(sslEngine, times(1)).setSSLParameters(sslParameters);
        verify(sslEngine, times(1)).getEnabledCipherSuites();
    }

    @Test
    void getEnabledProtocols() {
        wrapperSslEngine.getEnabledProtocols();

        verify(sslEngine, times(1)).setSSLParameters(sslParameters);
        verify(sslEngine, times(1)).getEnabledProtocols();
    }

    @Test
    void getNeedClientAuth() {
        wrapperSslEngine.getNeedClientAuth();

        verify(sslEngine, times(1)).setSSLParameters(sslParameters);
        verify(sslEngine, times(1)).getNeedClientAuth();
    }

    @Test
    void getWantClientAuth() {
        wrapperSslEngine.getWantClientAuth();

        verify(sslEngine, times(1)).setSSLParameters(sslParameters);
        verify(sslEngine, times(1)).getWantClientAuth();
    }

    @Test
    void getSSLParameters() {
        wrapperSslEngine.getSSLParameters();

        verify(sslEngine, times(1)).setSSLParameters(sslParameters);
        verify(sslEngine, times(1)).getSSLParameters();
    }

}
