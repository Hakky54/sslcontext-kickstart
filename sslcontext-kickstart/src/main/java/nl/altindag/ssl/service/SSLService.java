/*
 * Copyright 2019-2021 the original author or authors.
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

package nl.altindag.ssl.service;

import nl.altindag.ssl.model.SSLMaterial;
import nl.altindag.ssl.util.KeyManagerUtils;
import nl.altindag.ssl.util.SSLParametersUtils;
import nl.altindag.ssl.util.SocketUtils;
import nl.altindag.ssl.util.TrustManagerUtils;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509ExtendedTrustManager;

import java.net.URI;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import static java.util.Objects.nonNull;
import static java.util.stream.Collectors.toList;
import static java.util.stream.Collectors.toMap;

/**
 * <p>
 * <strong>NOTE:</strong>
 * Please don't use this class directly as it is part of the internal API. Class name and methods can be changed any time.
 * </p>
 *
 * @author Hakan Altindag
 */
public final class SSLService {

    private final SSLMaterial sslMaterial;

    public SSLService(SSLMaterial sslMaterial) {
        this.sslMaterial = sslMaterial;
    }

    public SSLSocketFactory createSslSocketFactory() {
        return SocketUtils.createSslSocketFactory(
                sslMaterial.getSslContext().getSocketFactory(),
                getSslParameters()
        );
    }

    public SSLServerSocketFactory createSslServerSocketFactory() {
        return SocketUtils.createSslServerSocketFactory(
                sslMaterial.getSslContext().getServerSocketFactory(),
                getSslParameters()
        );
    }

    public SSLEngine createSslEngine(String peerHost, Integer peerPort) {
        SSLEngine sslEngine;
        if (nonNull(peerHost) && nonNull(peerPort)) {
            sslEngine = sslMaterial.getSslContext().createSSLEngine(peerHost, peerPort);
        } else {
            sslEngine = sslMaterial.getSslContext().createSSLEngine();
        }

        sslEngine.setSSLParameters(getSslParameters());
        return sslEngine;
    }

    public Optional<X509ExtendedKeyManager> getKeyManager() {
        return Optional.ofNullable(sslMaterial.getIdentityMaterial().getKeyManager());
    }

    public Optional<KeyManagerFactory> createKeyManagerFactory() {
        return this.getKeyManager().map(KeyManagerUtils::createKeyManagerFactory);
    }

    public Optional<X509ExtendedTrustManager> getTrustManager() {
        return Optional.ofNullable(sslMaterial.getTrustMaterial().getTrustManager());
    }

    public Optional<TrustManagerFactory> createTrustManagerFactory() {
        return this.getTrustManager().map(TrustManagerUtils::createTrustManagerFactory);
    }

    public List<X509Certificate> getTrustedCertificates() {
        return this.getTrustManager()
                .map(X509ExtendedTrustManager::getAcceptedIssuers)
                .flatMap(x509Certificates -> Optional.of(Arrays.asList(x509Certificates)))
                .map(Collections::unmodifiableList)
                .orElse(Collections.emptyList());
    }

    public Map<String, List<String>> getClientIdentityRoute() {
        return sslMaterial.getIdentityMaterial()
                .getPreferredClientAliasToHost()
                .entrySet().stream()
                .collect(toMap(
                        Map.Entry::getKey,
                        hosts -> hosts.getValue().stream()
                                .map(URI::toString)
                                .collect(Collectors.collectingAndThen(toList(), Collections::unmodifiableList)))
                );
    }

    public SSLParameters getSslParameters() {
        return SSLParametersUtils.copy(sslMaterial.getSslParameters());
    }

    public SSLMaterial getSslMaterial() {
        return sslMaterial;
    }

}
