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
package nl.altindag.ssl.socket;

import nl.altindag.log.LogCaptor;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocket;
import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@SuppressWarnings("ResultOfMethodCallIgnored")
class FenixSSLServerSocketShould {

    private SSLServerSocket socket;
    private SSLServerSocket wrapperSocket;
    private SSLParameters sslParameters;
    private static LogCaptor logCaptor;

    @BeforeAll
    static void setupLogCaptor() {
        logCaptor = LogCaptor.forClass(FenixSSLServerSocket.class);
    }

    @AfterAll
    static void closeLogCaptor() {
        logCaptor.close();
    }

    @BeforeEach
    void setup() throws IOException {
        socket = mock(SSLServerSocket.class);
        sslParameters = new SSLParameters();
        wrapperSocket = new FenixSSLServerSocket(socket, sslParameters);
    }

    @AfterEach
    void clearLogs() {
        logCaptor.clearLogs();
    }

    @Test
    void setSSLParameters() {
        wrapperSocket.setSSLParameters(null);
        assertThat(logCaptor.getDebugLogs()).containsExactly("Ignoring provided ssl parameters");
    }

    @Test
    void setEnabledCipherSuites() {
        wrapperSocket.setEnabledCipherSuites(null);
        assertThat(logCaptor.getDebugLogs()).containsExactly("Ignoring provided ciphers");
    }

    @Test
    void setEnabledProtocols() {
        wrapperSocket.setEnabledProtocols(null);
        assertThat(logCaptor.getDebugLogs()).containsExactly("Ignoring provided protocols");
    }

    @Test
    void setNeedClientAuth() {
        wrapperSocket.setNeedClientAuth(true);
        assertThat(logCaptor.getDebugLogs()).containsExactly("Ignoring provided indicator for need client auth");
    }

    @Test
    void setWantClientAuth() {
        wrapperSocket.setWantClientAuth(true);
        assertThat(logCaptor.getDebugLogs()).containsExactly("Ignoring provided indicator for want client auth");
    }

    @Test
    void getEnabledCipherSuites() {
        wrapperSocket.getEnabledCipherSuites();

        verify(socket, times(1)).setSSLParameters(sslParameters);
        verify(socket, times(1)).getEnabledCipherSuites();
    }

    @Test
    void getEnabledProtocols() {
        wrapperSocket.getEnabledProtocols();

        verify(socket, times(1)).setSSLParameters(sslParameters);
        verify(socket, times(1)).getEnabledProtocols();
    }

    @Test
    void getNeedClientAuth() {
        wrapperSocket.getNeedClientAuth();

        verify(socket, times(1)).setSSLParameters(sslParameters);
        verify(socket, times(1)).getNeedClientAuth();
    }

    @Test
    void getWantClientAuth() {
        wrapperSocket.getWantClientAuth();

        verify(socket, times(1)).setSSLParameters(sslParameters);
        verify(socket, times(1)).getWantClientAuth();
    }

    @Test
    void getSSLParameters() {
        wrapperSocket.getSSLParameters();

        verify(socket, times(1)).setSSLParameters(sslParameters);
        verify(socket, times(1)).getSSLParameters();
    }

}
