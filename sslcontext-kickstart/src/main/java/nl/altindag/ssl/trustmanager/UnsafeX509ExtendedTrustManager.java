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

package nl.altindag.ssl.trustmanager;

import nl.altindag.log.Logger;
import nl.altindag.log.LoggerFactory;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedTrustManager;
import java.net.Socket;
import java.security.Principal;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.stream.Collectors;

/**
 * An insecure {@link UnsafeX509ExtendedTrustManager TrustManager} that trusts all X.509 certificates without any verification.
 * <p>
 * <strong>NOTE:</strong>
 * Never use this {@link UnsafeX509ExtendedTrustManager} in production.
 * It is purely for testing purposes, and thus it is very insecure.
 * </p>
 * <br>
 * Suppressed warning: java:S4830 - "Server certificates should be verified during SSL/TLS connections"
 *                                  This TrustManager doesn't validate certificates and should not be used at production.
 *                                  It is just meant to be used for testing purposes and it is designed not to verify server certificates.
 *
 * <p>
 * <br>
 * <strong>NOTE:</strong>
 * Please don't use this class directly as it is part of the internal API. Class name and methods can be changed any time.
 * Instead use the {@link nl.altindag.ssl.util.TrustManagerUtils TrustManagerUtils} which provides the same functionality
 * while it has a stable API because it is part of the public API.
 * </p>
 *
 * @author Hakan Altindag
 */
@SuppressWarnings("java:S4830")
public final class UnsafeX509ExtendedTrustManager extends X509ExtendedTrustManager {

    private static final Logger LOGGER = LoggerFactory.getLogger(UnsafeX509ExtendedTrustManager.class);

    private static final X509ExtendedTrustManager INSTANCE = new UnsafeX509ExtendedTrustManager();

    private static final String SERVER = "server";
    private static final String CLIENT = "client";
    private static final String CERTIFICATE_LOG_MESSAGE = "Accepting the following {} certificates without validating: {}";
    private static final X509Certificate[] EMPTY_CERTIFICATES = new X509Certificate[0];

    private UnsafeX509ExtendedTrustManager() {}

    public static X509ExtendedTrustManager getInstance() {
        return INSTANCE;
    }

    @Override
    public void checkClientTrusted(X509Certificate[] certificates, String authType) {
        logCertificate(certificates, CLIENT);
    }

    @Override
    public void checkClientTrusted(X509Certificate[] certificates, String authType, Socket socket) {
        logCertificate(certificates, CLIENT);
    }

    @Override
    public void checkClientTrusted(X509Certificate[] certificates, String authType, SSLEngine sslEngine) {
        logCertificate(certificates, CLIENT);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] certificates, String authType) {
        logCertificate(certificates, SERVER);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] certificates, String authType, Socket socket) {
        logCertificate(certificates, SERVER);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] certificates, String authType, SSLEngine sslEngine) {
        logCertificate(certificates, SERVER);
    }

    private static void logCertificate(X509Certificate[] certificates, String serverOrClient) {
        String principals = extractPrincipals(certificates);
        LOGGER.warn(CERTIFICATE_LOG_MESSAGE, serverOrClient, principals);
    }

    private static String extractPrincipals(X509Certificate[] certificates) {
        return Arrays.stream(certificates)
                .map(X509Certificate::getSubjectX500Principal)
                .map(Principal::toString)
                .map(principal -> String.format("{%s}", principal))
                .collect(Collectors.joining(",", "[", "]"));
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return EMPTY_CERTIFICATES;
    }

}
