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

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import java.nio.ByteBuffer;
import java.util.List;
import java.util.function.BiFunction;

/**
 * @author Hakan Altindag
 */
class DelegatingSSLEngine extends SSLEngine {

    final SSLEngine sslEngine;

    public DelegatingSSLEngine(SSLEngine sslEngine) {
        this.sslEngine = sslEngine;
    }

    @Override
    public SSLEngineResult wrap(ByteBuffer[] srcs, int offset, int length, ByteBuffer dst) throws SSLException {
        return sslEngine.wrap(srcs, offset, length, dst);
    }

    @Override
    public SSLEngineResult wrap(ByteBuffer src, ByteBuffer dst) throws SSLException {
        return sslEngine.wrap(src, dst);
    }

    @Override
    public SSLEngineResult wrap(ByteBuffer[] srcs, ByteBuffer dst) throws SSLException {
        return sslEngine.wrap(srcs, dst);
    }

    @Override
    public SSLEngineResult unwrap(ByteBuffer src, ByteBuffer[] dsts, int offset, int length) throws SSLException {
        return sslEngine.unwrap(src, dsts, offset, length);
    }

    @Override
    public SSLEngineResult unwrap(ByteBuffer src, ByteBuffer dst) throws SSLException {
        return sslEngine.unwrap(src, dst);
    }

    @Override
    public SSLEngineResult unwrap(ByteBuffer src, ByteBuffer[] dsts) throws SSLException {
        return sslEngine.unwrap(src, dsts);
    }

    @Override
    public Runnable getDelegatedTask() {
        return sslEngine.getDelegatedTask();
    }

    @Override
    public void closeInbound() throws SSLException {
        sslEngine.closeInbound();
    }

    @Override
    public boolean isInboundDone() {
        return sslEngine.isInboundDone();
    }

    @Override
    public void closeOutbound() {
        sslEngine.closeOutbound();
    }

    @Override
    public boolean isOutboundDone() {
        return sslEngine.isOutboundDone();
    }

    @Override
    public String[] getSupportedCipherSuites() {
        return sslEngine.getSupportedCipherSuites();
    }

    @Override
    public String[] getEnabledCipherSuites() {
        return sslEngine.getEnabledCipherSuites();
    }

    @Override
    public void setEnabledCipherSuites(String[] suites) {
        sslEngine.setEnabledCipherSuites(suites);
    }

    @Override
    public String[] getSupportedProtocols() {
        return sslEngine.getSupportedProtocols();
    }

    @Override
    public String[] getEnabledProtocols() {
        return sslEngine.getEnabledProtocols();
    }

    @Override
    public void setEnabledProtocols(String[] protocols) {
        sslEngine.setEnabledProtocols(protocols);
    }

    @Override
    public SSLSession getSession() {
        return sslEngine.getSession();
    }

    @Override
    public void beginHandshake() throws SSLException {
        sslEngine.beginHandshake();
    }

    @Override
    public SSLEngineResult.HandshakeStatus getHandshakeStatus() {
        return sslEngine.getHandshakeStatus();
    }

    @Override
    public SSLSession getHandshakeSession() {
        return sslEngine.getHandshakeSession();
    }

    @Override
    public String getHandshakeApplicationProtocol() {
        return sslEngine.getHandshakeApplicationProtocol();
    }

    @Override
    public void setHandshakeApplicationProtocolSelector(BiFunction<SSLEngine, List<String>, String> selector) {
        sslEngine.setHandshakeApplicationProtocolSelector(selector);
    }

    @Override
    public BiFunction<SSLEngine, List<String>, String> getHandshakeApplicationProtocolSelector() {
        return sslEngine.getHandshakeApplicationProtocolSelector();
    }

    @Override
    public void setUseClientMode(boolean mode) {
        sslEngine.setUseClientMode(mode);
    }

    @Override
    public boolean getUseClientMode() {
        return sslEngine.getUseClientMode();
    }

    @Override
    public void setNeedClientAuth(boolean need) {
        sslEngine.setNeedClientAuth(need);
    }

    @Override
    public boolean getNeedClientAuth() {
        return sslEngine.getNeedClientAuth();
    }

    @Override
    public void setWantClientAuth(boolean want) {
        sslEngine.setWantClientAuth(want);
    }

    @Override
    public boolean getWantClientAuth() {
        return sslEngine.getWantClientAuth();
    }

    @Override
    public void setEnableSessionCreation(boolean flag) {
        sslEngine.setEnableSessionCreation(flag);
    }

    @Override
    public boolean getEnableSessionCreation() {
        return sslEngine.getEnableSessionCreation();
    }

    @Override
    public String getPeerHost() {
        return sslEngine.getPeerHost();
    }

    @Override
    public int getPeerPort() {
        return sslEngine.getPeerPort();
    }

    @Override
    public SSLParameters getSSLParameters() {
        return sslEngine.getSSLParameters();
    }

    @Override
    public void setSSLParameters(SSLParameters params) {
        sslEngine.setSSLParameters(params);
    }

    @Override
    public String getApplicationProtocol() {
        return sslEngine.getApplicationProtocol();
    }

}
