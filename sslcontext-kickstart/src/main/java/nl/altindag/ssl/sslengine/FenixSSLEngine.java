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
import javax.net.ssl.SSLParameters;

/**
 * <strong>NOTE:</strong>
 * Please don't use this class directly as it is part of the internal API. Class name and methods can be changed any time.
 *
 * @author Hakan Altindag
 */
public class FenixSSLEngine extends DelegatingSSLEngine {

    private final SSLParameters sslParameters;

    public FenixSSLEngine(SSLEngine sslEngine, SSLParameters sslParameters) {
        super(sslEngine);
        this.sslParameters = sslParameters;
    }

    @Override
    public void setSSLParameters(SSLParameters params) {
        // ignore
    }

    @Override
    public void setEnabledCipherSuites(String[] suites) {
        // ignore
    }

    @Override
    public void setEnabledProtocols(String[] protocols) {
        // ignore
    }

    @Override
    public String[] getEnabledCipherSuites() {
        return updateAndGet(super::getEnabledCipherSuites);
    }

    @Override
    public String[] getEnabledProtocols() {
        return updateAndGet(super::getEnabledProtocols);
    }

    @Override
    public boolean getNeedClientAuth() {
        return updateAndGet(super::getNeedClientAuth);
    }

    @Override
    public boolean getWantClientAuth() {
        return updateAndGet(super::getWantClientAuth);
    }

    @Override
    public SSLParameters getSSLParameters() {
        return updateAndGet(super::getSSLParameters);
    }

    private <T> T updateAndGet(SSLEngineCallable<T> callable) {
        sslEngine.setSSLParameters(sslParameters);
        return callable.call();
    }

}
