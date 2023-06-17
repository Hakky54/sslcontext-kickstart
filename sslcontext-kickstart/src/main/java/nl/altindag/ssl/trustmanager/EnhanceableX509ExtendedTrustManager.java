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

import nl.altindag.ssl.model.TrustManagerParameters;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedTrustManager;
import java.net.Socket;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Optional;
import java.util.function.Predicate;

/**
 * <strong>NOTE:</strong>
 * Please don't use this class directly as it is part of the internal API. Class name and methods can be changed any time.
 *
 * @author Hakan Altindag
 */
public final class EnhanceableX509ExtendedTrustManager extends DelegatingX509ExtendedTrustManager {

    private final Predicate<TrustManagerParameters> trustManagerParametersValidator;

    public EnhanceableX509ExtendedTrustManager(
            X509ExtendedTrustManager trustManager,
            Predicate<TrustManagerParameters> trustManagerParametersValidator) {

        super(trustManager);
        this.trustManagerParametersValidator = Optional.ofNullable(trustManagerParametersValidator)
                .orElse(trustManagerParameters -> false);
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        checkTrusted(trustManager -> trustManager.checkClientTrusted(chain, authType), chain, authType, null, null);
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
        checkTrusted(trustManager -> trustManager.checkClientTrusted(chain, authType, socket), chain, authType, socket, null);
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine sslEngine) throws CertificateException {
        checkTrusted(trustManager -> trustManager.checkClientTrusted(chain, authType, sslEngine), chain, authType, null, sslEngine);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        checkTrusted(trustManager -> trustManager.checkServerTrusted(chain, authType), chain, authType, null, null);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
        checkTrusted(trustManager -> trustManager.checkServerTrusted(chain, authType, socket), chain, authType, socket, null);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine sslEngine) throws CertificateException {
        checkTrusted(trustManager -> trustManager.checkServerTrusted(chain, authType, sslEngine), chain, authType, null, sslEngine);
    }

    private void checkTrusted(TrustManagerConsumer trustManagerConsumer, X509Certificate[] chain, String authType, Socket socket, SSLEngine sslEngine) throws CertificateException {
        TrustManagerParameters trustManagerParameters = new TrustManagerParameters(chain, authType, socket, sslEngine);
        if (trustManagerParametersValidator.test(trustManagerParameters)) {
            return;
        }

        trustManagerConsumer.checkTrusted(trustManager);
    }

}
