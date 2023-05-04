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

import nl.altindag.ssl.util.HostUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedTrustManager;
import java.net.Socket;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Map;
import java.util.Optional;

/**
 * <strong>NOTE:</strong>
 * Please don't use this class directly as it is part of the internal API. Class name and methods can be changed any time.
 *
 * @author Hakan Altindag
 */
public final class LoggingX509ExtendedTrustManager extends DelegatingX509ExtendedTrustManager {

    private static final Logger LOGGER = LoggerFactory.getLogger(LoggingX509ExtendedTrustManager.class);
    private static final String LOG_MESSAGE_TEMPLATE = "Validating the certificate chain of the %s%s with authentication type %s%s. See below for the full chain of the %s:\n%s";

    public LoggingX509ExtendedTrustManager(X509ExtendedTrustManager trustManager) {
        super(trustManager);
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        logCertificate(CounterParty.CLIENT, chain, authType, null, null);
        super.checkClientTrusted(chain, authType);
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
        logCertificate(CounterParty.CLIENT, chain, authType, socket, null);
        super.checkClientTrusted(chain, authType, socket);
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine sslEngine) throws CertificateException {
        logCertificate(CounterParty.CLIENT, chain, authType, null, sslEngine);
        super.checkClientTrusted(chain, authType, sslEngine);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        logCertificate(CounterParty.SERVER, chain, authType, null, null);
        super.checkServerTrusted(chain, authType);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
        logCertificate(CounterParty.SERVER, chain, authType, socket, null);
        super.checkServerTrusted(chain, authType, socket);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine sslEngine) throws CertificateException {
        logCertificate(CounterParty.SERVER, chain, authType, null, sslEngine);
        super.checkServerTrusted(chain, authType, sslEngine);
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        X509Certificate[] acceptedIssuers = trustManager.getAcceptedIssuers();
        return Arrays.copyOf(acceptedIssuers, acceptedIssuers.length);
    }

    private static void logCertificate(CounterParty counterParty, X509Certificate[] chain, String authType, Socket socket, SSLEngine sslEngine) {
        String certificateChain = Arrays.toString(chain);

        Optional<String> classNameLogMessage = getClassnameOfEitherOrOther(socket, sslEngine)
                .map(className -> ", while also using the " + className + "");
        Optional<String> hostAndPortLogMessage = getHostAndPortOfEitherOrOther(socket, sslEngine)
                .map(hostAndPort -> "[" + hostAndPort + "]");

        String logMessage = String.format(LOG_MESSAGE_TEMPLATE, counterParty, hostAndPortLogMessage.orElse(""), authType, classNameLogMessage.orElse(""), counterParty, certificateChain);
        LOGGER.info(logMessage);
    }

    private static Optional<String> getClassnameOfEitherOrOther(Socket socket, SSLEngine sslEngine) {
        if (socket != null) {
            return Optional.of(Socket.class.getSimpleName());
        }

        if (sslEngine != null) {
            return Optional.of(SSLEngine.class.getSimpleName());
        }

        return Optional.empty();
    }

    private static Optional<String> getHostAndPortOfEitherOrOther(Socket socket, SSLEngine sslEngine) {
        Map.Entry<String, Integer> hostToPort = null;
        if (socket != null) {
            hostToPort = HostUtils.extractHostAndPort(socket);
        }

        if (sslEngine != null) {
            hostToPort = HostUtils.extractHostAndPort(sslEngine);
        }

        if (hostToPort != null) {
            return Optional.of(String.join(":", hostToPort.getKey(), hostToPort.getValue().toString()));
        }

        return Optional.empty();
    }

    private enum CounterParty {
        SERVER, CLIENT;

        @Override
        public String toString() {
            return this.name().toLowerCase();
        }
    }

}
