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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocket;
import java.io.IOException;
import java.net.SocketAddress;
import java.net.SocketException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SuppressWarnings("ResultOfMethodCallIgnored")
class DelegatingSSLServerSocketShould {

    private SSLServerSocket socket;
    private SSLServerSocket wrapperSocket;

    @BeforeEach
    void setup() throws IOException {
        socket = mock(SSLServerSocket.class);
        wrapperSocket = new DelegatingSSLServerSocket(socket);
    }

    @Test
    void getEnabledCipherSuites() {
        wrapperSocket.getEnabledCipherSuites();
        verify(socket, times(1)).getEnabledCipherSuites();
    }

    @Test
    void setEnabledCipherSuites() {
        String[] ciphers = {"some-cipher"};
        wrapperSocket.setEnabledCipherSuites(ciphers);
        verify(socket, times(1)).setEnabledCipherSuites(ciphers);
    }

    @Test
    void getSupportedCipherSuites() {
        wrapperSocket.getSupportedCipherSuites();
        verify(socket, times(1)).getSupportedCipherSuites();
    }

    @Test
    void getSupportedProtocols() {
        wrapperSocket.getSupportedProtocols();
        verify(socket, times(1)).getSupportedProtocols();
    }

    @Test
    void getEnabledProtocols() {
        wrapperSocket.getEnabledProtocols();
        verify(socket, times(1)).getEnabledProtocols();
    }

    @Test
    void setEnabledProtocols() {
        String[] protocols = {"some-protocols"};
        wrapperSocket.setEnabledProtocols(protocols);
        verify(socket, times(1)).setEnabledProtocols(protocols);
    }

    @Test
    void setNeedClientAuth() {
        wrapperSocket.setNeedClientAuth(true);
        verify(socket, times(1)).setNeedClientAuth(true);
    }

    @Test
    void getNeedClientAuth() {
        wrapperSocket.getNeedClientAuth();
        verify(socket, times(1)).getNeedClientAuth();
    }

    @Test
    void setWantClientAuth() {
        wrapperSocket.setWantClientAuth(true);
        verify(socket, times(1)).setWantClientAuth(true);
    }

    @Test
    void getWantClientAuth() {
        wrapperSocket.getWantClientAuth();
        verify(socket, times(1)).getWantClientAuth();
    }

    @Test
    void setUseClientMode() {
        wrapperSocket.setUseClientMode(true);
        verify(socket, times(1)).setUseClientMode(true);
    }

    @Test
    void getUseClientMode() {
        wrapperSocket.getUseClientMode();
        verify(socket, times(1)).getUseClientMode();
    }

    @Test
    void setEnableSessionCreation() {
        wrapperSocket.setEnableSessionCreation(true);
        verify(socket, times(1)).setEnableSessionCreation(true);
    }

    @Test
    void getEnableSessionCreation() {
        wrapperSocket.getEnableSessionCreation();
        verify(socket, times(1)).getEnableSessionCreation();
    }

    @Test
    void getSSLParameters() {
        wrapperSocket.getSSLParameters();
        verify(socket, times(1)).getSSLParameters();
    }

    @Test
    void setSSLParameters() {
        SSLParameters sslParameters = mock(SSLParameters.class);
        wrapperSocket.setSSLParameters(sslParameters);
        verify(socket, times(1)).setSSLParameters(sslParameters);
    }

    @Test
    void bind() throws IOException {
        SocketAddress socketAddress = mock(SocketAddress.class);
        wrapperSocket.bind(socketAddress);
        verify(socket, times(1)).bind(socketAddress);
    }

    @Test
    void bindWithBacklog() throws IOException {
        SocketAddress socketAddress = mock(SocketAddress.class);
        wrapperSocket.bind(socketAddress, 1);
        verify(socket, times(1)).bind(socketAddress, 1);
    }

    @Test
    void getInetAddress() {
        wrapperSocket.getInetAddress();
        verify(socket, times(1)).getInetAddress();
    }

    @Test
    void getLocalPort() {
        wrapperSocket.getLocalPort();
        verify(socket, times(1)).getLocalPort();
    }

    @Test
    void getLocalSocketAddress() {
        wrapperSocket.getLocalSocketAddress();
        verify(socket, times(1)).getLocalSocketAddress();
    }

    @Test
    void accept() throws IOException {
        wrapperSocket.accept();
        verify(socket, times(1)).accept();
    }

    @Test
    void close() throws IOException {
        wrapperSocket.close();
        verify(socket, times(1)).close();
    }

    @Test
    void getChannel() {
        wrapperSocket.getChannel();
        verify(socket, times(1)).getChannel();
    }

    @Test
    void isBound() {
        wrapperSocket.isBound();
        verify(socket, times(1)).isBound();
    }

    @Test
    void isClosed() {
        wrapperSocket.isClosed();
        verify(socket, times(1)).isClosed();
    }

    @Test
    void setSoTimeout() throws SocketException {
        wrapperSocket.setSoTimeout(100);
        verify(socket, times(1)).setSoTimeout(100);
    }

    @Test
    void getSoTimeout() throws IOException {
        wrapperSocket.getSoTimeout();
        verify(socket, times(1)).getSoTimeout();
    }

    @Test
    void setReuseAddress() throws SocketException {
        wrapperSocket.setReuseAddress(true);
        verify(socket, times(1)).setReuseAddress(true);
    }

    @Test
    void getReuseAddress() throws SocketException {
        wrapperSocket.getReuseAddress();
        verify(socket, times(1)).getReuseAddress();
    }

    @Test
    void callDelegateToString() {
        when(socket.toString()).thenReturn("hello");
        String result = wrapperSocket.toString();

        assertThat(result).isEqualTo("hello");
    }

    @Test
    void setReceiveBufferSize() throws SocketException {
        wrapperSocket.setReceiveBufferSize(1000);
        verify(socket, times(1)).setReceiveBufferSize(1000);
    }

    @Test
    void getReceiveBufferSize() throws SocketException {
        wrapperSocket.getReceiveBufferSize();
        verify(socket, times(1)).getReceiveBufferSize();
    }

    @Test
    void setPerformancePreferences() throws SocketException {
        wrapperSocket.setPerformancePreferences(1000, 1000, 1000);
        verify(socket, times(1)).setPerformancePreferences(1000, 1000, 1000);
    }

}
