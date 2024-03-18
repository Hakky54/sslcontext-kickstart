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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;
import java.nio.ByteBuffer;
import java.util.List;
import java.util.function.BiFunction;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

@SuppressWarnings("ResultOfMethodCallIgnored")
class DelegatingSSLEngineShould {

    private SSLEngine sslEngine;
    private SSLEngine wrapperSslEngine;

    @BeforeEach
    void setup() {
        sslEngine = mock(SSLEngine.class);
        wrapperSslEngine = new DelegatingSSLEngine(sslEngine);
    }

    @Test
    void wrapWithSrcsOffsetLengthDst() throws SSLException {
        ByteBuffer[] srcs = new ByteBuffer[] {};
        ByteBuffer dst = ByteBuffer.allocate(1);

        wrapperSslEngine.wrap(srcs, 1, 2, dst);
        verify(sslEngine, times(1)).wrap(srcs, 1, 2, dst);
    }

    @Test
    void wrapWithSrcDst() throws SSLException {
        ByteBuffer src = ByteBuffer.allocate(1);
        ByteBuffer dst = ByteBuffer.allocate(1);

        wrapperSslEngine.wrap(src, dst);
        verify(sslEngine, times(1)).wrap(src, dst);
    }

    @Test
    void wrapWithSrcsDst() throws SSLException {
        ByteBuffer[] srcs = new ByteBuffer[] {};
        ByteBuffer dst = ByteBuffer.allocate(1);

        wrapperSslEngine.wrap(srcs, dst);
        verify(sslEngine, times(1)).wrap(srcs, dst);
    }

    @Test
    void unwrapWithSrcOffsetLengthDst() throws SSLException {
        ByteBuffer[] dsts = new ByteBuffer[] {};
        ByteBuffer src = ByteBuffer.allocate(1);

        wrapperSslEngine.unwrap(src, dsts, 1, 2);
        verify(sslEngine, times(1)).unwrap(src, dsts, 1, 2);
    }

    @Test
    void unwrapWithSrcDst() throws SSLException {
        ByteBuffer dst = ByteBuffer.allocate(1);
        ByteBuffer src = ByteBuffer.allocate(1);

        wrapperSslEngine.unwrap(src, dst);
        verify(sslEngine, times(1)).unwrap(src, dst);
    }

    @Test
    void unwrapWithSrcDsts() throws SSLException {
        ByteBuffer[] dsts = new ByteBuffer[] {};
        ByteBuffer src = ByteBuffer.allocate(1);

        wrapperSslEngine.unwrap(src, dsts);
        verify(sslEngine, times(1)).unwrap(src, dsts);
    }

    @Test
    void getDelegatedTask() {
        wrapperSslEngine.getDelegatedTask();
        verify(sslEngine, times(1)).getDelegatedTask();
    }

    @Test
    void closeInbound() throws SSLException {
        wrapperSslEngine.closeInbound();
        verify(sslEngine, times(1)).closeInbound();
    }

    @Test
    void isInboundDone() {
        wrapperSslEngine.isInboundDone();
        verify(sslEngine, times(1)).isInboundDone();
    }

    @Test
    void closeOutbound() {
        wrapperSslEngine.closeOutbound();
        verify(sslEngine, times(1)).closeOutbound();
    }

    @Test
    void isOutboundDone() {
        wrapperSslEngine.isOutboundDone();
        verify(sslEngine, times(1)).isOutboundDone();
    }

    @Test
    void getSupportedCipherSuites() {
        wrapperSslEngine.getSupportedCipherSuites();
        verify(sslEngine, times(1)).getSupportedCipherSuites();
    }

    @Test
    void getEnabledCipherSuites() {
        wrapperSslEngine.getEnabledCipherSuites();
        verify(sslEngine, times(1)).getEnabledCipherSuites();
    }

    @Test
    void setEnabledCipherSuites() {
        String[] ciphers = {"some-cipher"};
        wrapperSslEngine.setEnabledCipherSuites(ciphers);
        verify(sslEngine, times(1)).setEnabledCipherSuites(ciphers);
    }

    @Test
    void getSupportedProtocols() {
        wrapperSslEngine.getSupportedProtocols();
        verify(sslEngine, times(1)).getSupportedProtocols();
    }

    @Test
    void getEnabledProtocols() {
        wrapperSslEngine.getEnabledProtocols();
        verify(sslEngine, times(1)).getEnabledProtocols();
    }

    @Test
    void setEnabledProtocols() {
        String[] protocols = {"some-protocols"};
        wrapperSslEngine.setEnabledProtocols(protocols);
        verify(sslEngine, times(1)).setEnabledProtocols(protocols);
    }

    @Test
    void getSession() {
        wrapperSslEngine.getSession();
        verify(sslEngine, times(1)).getSession();
    }

    @Test
    void beginHandshake() throws SSLException {
        wrapperSslEngine.beginHandshake();
        verify(sslEngine, times(1)).beginHandshake();
    }

    @Test
    void getHandshakeStatus() {
        wrapperSslEngine.getHandshakeStatus();
        verify(sslEngine, times(1)).getHandshakeStatus();
    }

    @Test
    void getHandshakeSession() {
        wrapperSslEngine.getHandshakeSession();
        verify(sslEngine, times(1)).getHandshakeSession();
    }

    @Test
    void getHandshakeApplicationProtocol() {
        wrapperSslEngine.getHandshakeApplicationProtocol();
        verify(sslEngine, times(1)).getHandshakeApplicationProtocol();
    }

    @Test
    void setHandshakeApplicationProtocolSelector() {
        BiFunction<SSLEngine, List<String>, String> selector = (s, l) -> "";
        wrapperSslEngine.setHandshakeApplicationProtocolSelector(selector);
        verify(sslEngine, times(1)).setHandshakeApplicationProtocolSelector(selector);
    }

    @Test
    void getHandshakeApplicationProtocolSelector() {
        wrapperSslEngine.getHandshakeApplicationProtocolSelector();
        verify(sslEngine, times(1)).getHandshakeApplicationProtocolSelector();
    }

    @Test
    void setUseClientMode() {
        wrapperSslEngine.setUseClientMode(true);
        verify(sslEngine, times(1)).setUseClientMode(true);
    }

    @Test
    void getUseClientMode() {
        wrapperSslEngine.getUseClientMode();
        verify(sslEngine, times(1)).getUseClientMode();
    }

    @Test
    void setNeedClientAuth() {
        wrapperSslEngine.setNeedClientAuth(true);
        verify(sslEngine, times(1)).setNeedClientAuth(true);
    }

    @Test
    void getNeedClientAuth() {
        wrapperSslEngine.getNeedClientAuth();
        verify(sslEngine, times(1)).getNeedClientAuth();
    }

    @Test
    void setWantClientAuth() {
        wrapperSslEngine.setWantClientAuth(true);
        verify(sslEngine, times(1)).setWantClientAuth(true);
    }

    @Test
    void getWantClientAuth() {
        wrapperSslEngine.getWantClientAuth();
        verify(sslEngine, times(1)).getWantClientAuth();
    }

    @Test
    void setEnableSessionCreation() {
        wrapperSslEngine.setEnableSessionCreation(true);
        verify(sslEngine, times(1)).setEnableSessionCreation(true);
    }

    @Test
    void getEnableSessionCreation() {
        wrapperSslEngine.getEnableSessionCreation();
        verify(sslEngine, times(1)).getEnableSessionCreation();
    }

    @Test
    void getPeerHost() {
        wrapperSslEngine.getPeerHost();
        verify(sslEngine, times(1)).getPeerHost();
    }

    @Test
    void getPeerPort() {
        wrapperSslEngine.getPeerPort();
        verify(sslEngine, times(1)).getPeerPort();
    }

    @Test
    void getSSLParameters() {
        wrapperSslEngine.getSSLParameters();
        verify(sslEngine, times(1)).getSSLParameters();
    }

    @Test
    void setSSLParameters() {
        SSLParameters sslParameters = mock(SSLParameters.class);
        wrapperSslEngine.setSSLParameters(sslParameters);
        verify(sslEngine, times(1)).setSSLParameters(sslParameters);
    }

    @Test
    void getApplicationProtocol() {
        wrapperSslEngine.getApplicationProtocol();
        verify(sslEngine, times(1)).getApplicationProtocol();
    }

}
