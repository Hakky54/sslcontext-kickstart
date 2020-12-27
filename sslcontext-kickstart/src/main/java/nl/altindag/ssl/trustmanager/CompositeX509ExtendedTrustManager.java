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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedTrustManager;
import java.net.Socket;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * {@link CompositeX509ExtendedTrustManager} is a wrapper for a collection of TrustManagers.
 * It has the ability to validate a certificate chain against multiple TrustManagers.
 * If any one of the composed managers trusts a certificate chain, then it is trusted by the composite manager.
 * The TrustManager can be build from one or more of any combination provided within the {@link nl.altindag.ssl.util.TrustManagerUtils.TrustManagerBuilder TrustManagerUtils.TrustManagerBuilder}.
 * <br><br>
 * This includes:
 * <pre>
 *     - Any amount of custom TrustManagers
 *     - Any amount of custom TrustStores
 * </pre>
 *
 * <p>
 * <strong>NOTE:</strong>
 * Please don't use this class directly as it is part of the internal API. Class name and methods can be changed any time.
 * Instead use the {@link nl.altindag.ssl.util.TrustManagerUtils TrustManagerUtils} which provides the same functionality
 * while it has a stable API because it is part of the public API.
 * </p>
 *
 * @see <a href="http://stackoverflow.com/questions/1793979/registering-multiple-keystores-in-jvm">
 *     http://stackoverflow.com/questions/1793979/registering-multiple-keystores-in-jvm
 *     </a>
 * @see <a href="http://codyaray.com/2013/04/java-ssl-with-multiple-keystores">
 *     http://codyaray.com/2013/04/java-ssl-with-multiple-keystores
 *     </a>
 *
 * @author Cody Ray
 * @author Hakan Altindag
 */
public final class CompositeX509ExtendedTrustManager extends X509ExtendedTrustManager {

    private static final Logger LOGGER = LoggerFactory.getLogger(CompositeX509ExtendedTrustManager.class);
    private static final String CERTIFICATE_EXCEPTION_MESSAGE = "None of the TrustManagers trust this certificate chain";
    private static final String CLIENT_CERTIFICATE_LOG_MESSAGE = "Received the following client certificate: [{}]";
    private static final String SERVER_CERTIFICATE_LOG_MESSAGE = "Received the following server certificate: [{}]";

    private final List<? extends X509ExtendedTrustManager> trustManagers;
    private final X509Certificate[] acceptedIssuers;

    public CompositeX509ExtendedTrustManager(List<? extends X509ExtendedTrustManager> trustManagers) {
        this.trustManagers = Collections.unmodifiableList(trustManagers);
        acceptedIssuers = trustManagers.stream()
                .map(X509ExtendedTrustManager::getAcceptedIssuers)
                .flatMap(Arrays::stream)
                .distinct()
                .toArray(X509Certificate[]::new);
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug(CLIENT_CERTIFICATE_LOG_MESSAGE, chain[0].getSubjectDN());
        }

        List<CertificateException> certificateExceptions = new ArrayList<>();
        for (X509ExtendedTrustManager trustManager : trustManagers) {
            try {
                trustManager.checkClientTrusted(chain, authType);
                return;
            } catch (CertificateException e) {
                certificateExceptions.add(e);
            }
        }

        CertificateException certificateException = new CertificateException(CERTIFICATE_EXCEPTION_MESSAGE);
        certificateExceptions.forEach(certificateException::addSuppressed);

        throw certificateException;
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug(CLIENT_CERTIFICATE_LOG_MESSAGE, chain[0].getSubjectDN());
        }

        List<CertificateException> certificateExceptions = new ArrayList<>();
        for (X509ExtendedTrustManager trustManager : trustManagers) {
            try {
                trustManager.checkClientTrusted(chain, authType, socket);
                return;
            } catch (CertificateException e) {
                certificateExceptions.add(e);
            }
        }

        CertificateException certificateException = new CertificateException(CERTIFICATE_EXCEPTION_MESSAGE);
        certificateExceptions.forEach(certificateException::addSuppressed);

        throw certificateException;
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine sslEngine) throws CertificateException {
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug(CLIENT_CERTIFICATE_LOG_MESSAGE, chain[0].getSubjectDN());
        }

        List<CertificateException> certificateExceptions = new ArrayList<>();
        for (X509ExtendedTrustManager trustManager : trustManagers) {
            try {
                trustManager.checkClientTrusted(chain, authType, sslEngine);
                return;
            } catch (CertificateException e) {
                certificateExceptions.add(e);
            }
        }

        CertificateException certificateException = new CertificateException(CERTIFICATE_EXCEPTION_MESSAGE);
        certificateExceptions.forEach(certificateException::addSuppressed);

        throw certificateException;
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug(SERVER_CERTIFICATE_LOG_MESSAGE, chain[0].getSubjectDN());
        }

        List<CertificateException> certificateExceptions = new ArrayList<>();
        for (X509ExtendedTrustManager trustManager : trustManagers) {
            try {
                trustManager.checkServerTrusted(chain, authType);
                return;
            } catch (CertificateException e) {
                certificateExceptions.add(e);
            }
        }

        CertificateException certificateException = new CertificateException(CERTIFICATE_EXCEPTION_MESSAGE);
        certificateExceptions.forEach(certificateException::addSuppressed);

        throw certificateException;
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug(SERVER_CERTIFICATE_LOG_MESSAGE, chain[0].getSubjectDN());
        }

        List<CertificateException> certificateExceptions = new ArrayList<>();
        for (X509ExtendedTrustManager trustManager : trustManagers) {
            try {
                trustManager.checkServerTrusted(chain, authType, socket);
                return;
            } catch (CertificateException e) {
                certificateExceptions.add(e);
            }
        }

        CertificateException certificateException = new CertificateException(CERTIFICATE_EXCEPTION_MESSAGE);
        certificateExceptions.forEach(certificateException::addSuppressed);

        throw certificateException;
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine sslEngine) throws CertificateException {
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug(SERVER_CERTIFICATE_LOG_MESSAGE, chain[0].getSubjectDN());
        }

        List<CertificateException> certificateExceptions = new ArrayList<>();
        for (X509ExtendedTrustManager trustManager : trustManagers) {
            try {
                trustManager.checkServerTrusted(chain, authType, sslEngine);
                return;
            } catch (CertificateException e) {
                certificateExceptions.add(e);
            }
        }

        CertificateException certificateException = new CertificateException(CERTIFICATE_EXCEPTION_MESSAGE);
        certificateExceptions.forEach(certificateException::addSuppressed);

        throw certificateException;
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return acceptedIssuers;
    }

    public int size() {
        return trustManagers.size();
    }

}
