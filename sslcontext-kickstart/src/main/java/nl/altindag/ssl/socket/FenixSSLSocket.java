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

import nl.altindag.ssl.util.internal.Callable;

import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;

/**
 * <strong>NOTE:</strong>
 * Please don't use this class directly as it is part of the internal API. Class name and methods can be changed any time.
 *
 * @author Hakan Altindag
 */
class FenixSSLSocket extends DelegatingSSLSocket {

    private final SSLParameters sslParameters;

    public FenixSSLSocket(SSLSocket socket, SSLParameters sslParameters) {
        super(socket);
        this.sslParameters = sslParameters;
    }

    @Override
    public void setSSLParameters(SSLParameters params) {

    }

    @Override
    public void setEnabledCipherSuites(String[] suites) {

    }

    @Override
    public void setEnabledProtocols(String[] protocols) {

    }

    @Override
    public void setNeedClientAuth(boolean need) {

    }

    @Override
    public void setWantClientAuth(boolean want) {

    }

    @Override
    public String[] getEnabledCipherSuites() {
        return updateAndGet(super::getEnabledCipherSuites);
    }

    @Override
    public boolean getNeedClientAuth() {
        return updateAndGet(super::getNeedClientAuth);
    }

    @Override
    public String[] getEnabledProtocols() {
        return updateAndGet(super::getEnabledProtocols);
    }

    @Override
    public boolean getWantClientAuth() {
        return updateAndGet(super::getWantClientAuth);
    }

    @Override
    public SSLParameters getSSLParameters() {
        return updateAndGet(super::getSSLParameters);
    }

    private <T> T updateAndGet(Callable<T> callable) {
        socket.setSSLParameters(sslParameters);
        return callable.call();
    }

}
