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
package nl.altindag.ssl.model;

import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSocket;

import java.net.Inet4Address;
import java.net.InetAddress;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * @author Hakan Altindag
 */
class TrustManagerParametersShould {

    @Test
    void getHostnameFromSslEngineIfAvailable() {
        SSLEngine sslEngine = mock(SSLEngine.class);
        when(sslEngine.getPeerHost()).thenReturn("localhost");

        TrustManagerParameters trustManagerParameters = new TrustManagerParameters(null, null, null, sslEngine);
        assertThat(trustManagerParameters.getHostname()).hasValue("localhost");
    }

    @Test
    void getHostnameFromSocketIfAvailable() {
        SSLSocket socket = mock(SSLSocket.class);
        InetAddress inetAddress = mock(Inet4Address.class);

        when(inetAddress.getHostName()).thenReturn("localhost");
        when(socket.getInetAddress()).thenReturn(inetAddress);

        TrustManagerParameters trustManagerParameters = new TrustManagerParameters(null, null, socket, null);
        assertThat(trustManagerParameters.getHostname()).hasValue("localhost");
    }

    @Test
    void getHostnameIsAbsentWhenNoSSLEngineAndSocketIsPresent() {
        TrustManagerParameters trustManagerParameters = new TrustManagerParameters(null, null, null, null);
        assertThat(trustManagerParameters.getHostname()).isEmpty();
    }

    @Test
    void getPortFromSslEngineIfAvailable() {
        SSLEngine sslEngine = mock(SSLEngine.class);
        when(sslEngine.getPeerPort()).thenReturn(8443);

        TrustManagerParameters trustManagerParameters = new TrustManagerParameters(null, null, null, sslEngine);
        assertThat(trustManagerParameters.getPort()).hasValue(8443);
    }

    @Test
    void getPortFromSocketIfAvailable() {
        SSLSocket socket = mock(SSLSocket.class);
        when(socket.getPort()).thenReturn(8443);

        TrustManagerParameters trustManagerParameters = new TrustManagerParameters(null, null, socket, null);
        assertThat(trustManagerParameters.getPort()).hasValue(8443);
    }

    @Test
    void getPortIsAbsentWhenNoSSLEngineAndSocketIsPresent() {
        TrustManagerParameters trustManagerParameters = new TrustManagerParameters(null, null, null, null);
        assertThat(trustManagerParameters.getPort()).isEmpty();
    }

}
