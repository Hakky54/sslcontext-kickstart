/*
 * Copyright 2019-2022 the original author or authors.
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

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedTrustManager;
import java.net.Socket;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * <strong>NOTE:</strong>
 * Please don't use this class directly as it is part of the internal API. Class name and methods can be changed any time.
 *
 * @author Hakan Altindag
 */
public final class DummyX509ExtendedTrustManager extends X509ExtendedTrustManager {

    private static final X509ExtendedTrustManager INSTANCE = new DummyX509ExtendedTrustManager();
    private static final X509Certificate[] EMPTY_CERTIFICATES = new X509Certificate[0];
    private static final String MISSING_IMPLEMENTATION = "No X509ExtendedTrustManager implementation available";

    private DummyX509ExtendedTrustManager() {}

    public static X509ExtendedTrustManager getInstance() {
        return INSTANCE;
    }

    @Override
    public void checkClientTrusted(X509Certificate[] certificates, String authType) throws CertificateException {
        throw new CertificateException(MISSING_IMPLEMENTATION);
    }

    @Override
    public void checkClientTrusted(X509Certificate[] certificates, String authType, Socket socket) throws CertificateException {
        throw new CertificateException(MISSING_IMPLEMENTATION);
    }

    @Override
    public void checkClientTrusted(X509Certificate[] certificates, String authType, SSLEngine sslEngine) throws CertificateException {
        throw new CertificateException(MISSING_IMPLEMENTATION);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] certificates, String authType) throws CertificateException {
        throw new CertificateException(MISSING_IMPLEMENTATION);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] certificates, String authType, Socket socket) throws CertificateException {
        throw new CertificateException(MISSING_IMPLEMENTATION);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] certificates, String authType, SSLEngine sslEngine) throws CertificateException {
        throw new CertificateException(MISSING_IMPLEMENTATION);
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return EMPTY_CERTIFICATES;
    }

}
