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

import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedTrustManager;
import java.net.Socket;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

/**
 * @author Hakan Altindag
 */
@SuppressWarnings("ConstantValue")
class JdkX509ExtendedTrustManagerShould {

    @Test
    void checkClientTrusted() throws CertificateException {
        X509ExtendedTrustManager baseTrustManager = mock(X509ExtendedTrustManager.class);

        X509Certificate[] certificateChain = new X509Certificate[]{mock(X509Certificate.class)};
        String authType = "RSA";

        JdkX509ExtendedTrustManager trustManager = new JdkX509ExtendedTrustManager(baseTrustManager);

        trustManager.checkClientTrusted(certificateChain, authType);

        verify(baseTrustManager, times(1)).checkClientTrusted(certificateChain, authType);
    }

    @Test
    void checkClientTrustedWithSocket() throws CertificateException {
        X509ExtendedTrustManager baseTrustManager = mock(X509ExtendedTrustManager.class);

        X509Certificate[] certificateChain = new X509Certificate[]{mock(X509Certificate.class)};
        String authType = "RSA";
        Socket socket = mock(Socket.class);

        JdkX509ExtendedTrustManager trustManager = new JdkX509ExtendedTrustManager(baseTrustManager);

        trustManager.checkClientTrusted(certificateChain, authType, socket);

        verify(baseTrustManager, times(1)).checkClientTrusted(certificateChain, authType, socket);
    }

    @Test
    void checkClientTrustedWithSSLEngine() throws CertificateException {
        X509ExtendedTrustManager baseTrustManager = mock(X509ExtendedTrustManager.class);

        X509Certificate[] certificateChain = new X509Certificate[]{mock(X509Certificate.class)};
        String authType = "RSA";
        SSLEngine sslEngine = mock(SSLEngine.class);

        JdkX509ExtendedTrustManager trustManager = new JdkX509ExtendedTrustManager(baseTrustManager);

        trustManager.checkClientTrusted(certificateChain, authType, sslEngine);

        verify(baseTrustManager, times(1)).checkClientTrusted(certificateChain, authType, sslEngine);
    }

    @Test
    void checkServerTrusted() throws CertificateException {
        X509ExtendedTrustManager baseTrustManager = mock(X509ExtendedTrustManager.class);

        X509Certificate[] certificateChain = new X509Certificate[]{mock(X509Certificate.class)};
        String authType = "RSA";

        JdkX509ExtendedTrustManager trustManager = new JdkX509ExtendedTrustManager(baseTrustManager);

        trustManager.checkServerTrusted(certificateChain, authType);

        verify(baseTrustManager, times(1)).checkServerTrusted(certificateChain, authType);
    }

    @Test
    void checkServerTrustedWithSocket() throws CertificateException {
        X509ExtendedTrustManager baseTrustManager = mock(X509ExtendedTrustManager.class);

        X509Certificate[] certificateChain = new X509Certificate[]{mock(X509Certificate.class)};
        String authType = "RSA";
        Socket socket = mock(Socket.class);

        JdkX509ExtendedTrustManager trustManager = new JdkX509ExtendedTrustManager(baseTrustManager);

        trustManager.checkServerTrusted(certificateChain, authType, socket);

        verify(baseTrustManager, times(1)).checkServerTrusted(certificateChain, authType, socket);
    }

    @Test
    void checkServerTrustedWithSSLEngine() throws CertificateException {
        X509ExtendedTrustManager baseTrustManager = mock(X509ExtendedTrustManager.class);

        X509Certificate[] certificateChain = new X509Certificate[]{mock(X509Certificate.class)};
        String authType = "RSA";
        SSLEngine sslEngine = mock(SSLEngine.class);

        JdkX509ExtendedTrustManager trustManager = new JdkX509ExtendedTrustManager(baseTrustManager);

        trustManager.checkServerTrusted(certificateChain, authType, sslEngine);

        verify(baseTrustManager, times(1)).checkServerTrusted(certificateChain, authType, sslEngine);
    }


}
