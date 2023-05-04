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

import nl.altindag.log.LogCaptor;
import nl.altindag.ssl.util.KeyStoreUtils;
import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedTrustManager;
import java.net.Socket;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * @author Hakan Altindag
 */
class LoggingX509ExtendedTrustManagerShould {

    private static final String TRUSTSTORE_FILE_NAME = "truststore.jks";
    private static final char[] TRUSTSTORE_PASSWORD = new char[] {'s', 'e', 'c', 'r', 'e', 't'};
    private static final String KEYSTORE_LOCATION = "keystore/";

    @Test
    void checkClientTrusted() throws KeyStoreException, CertificateException {
        LogCaptor logCaptor = LogCaptor.forClass(LoggingX509ExtendedTrustManager.class);

        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        X509Certificate[] trustedCerts = KeyStoreTestUtils.getTrustedX509Certificates(trustStore);

        X509ExtendedTrustManager innerTrustManager = mock(X509ExtendedTrustManager.class);
        doNothing().when(innerTrustManager).checkClientTrusted(any(), any());
        when(innerTrustManager.getAcceptedIssuers()).thenReturn(new X509Certificate[]{});

        X509ExtendedTrustManager trustManager = new LoggingX509ExtendedTrustManager(innerTrustManager);

        assertThat(trustManager.getAcceptedIssuers()).isEmpty();
        assertThat(trustedCerts).hasSize(1);

        assertThatCode(() -> trustManager.checkClientTrusted(trustedCerts, "RSA"))
                .doesNotThrowAnyException();

        verify(innerTrustManager, times(1)).checkClientTrusted(trustedCerts, "RSA");
        verify(innerTrustManager, times(1)).getAcceptedIssuers();

        assertThat(logCaptor.getLogs()).hasSize(1);
    }

    @Test
    void checkClientTrustedWithSslEngine() throws KeyStoreException, CertificateException {
        LogCaptor logCaptor = LogCaptor.forClass(LoggingX509ExtendedTrustManager.class);

        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        X509Certificate[] trustedCerts = KeyStoreTestUtils.getTrustedX509Certificates(trustStore);

        X509ExtendedTrustManager innerTrustManager = mock(X509ExtendedTrustManager.class);
        doNothing().when(innerTrustManager).checkClientTrusted(any(), any(), any(SSLEngine.class));
        when(innerTrustManager.getAcceptedIssuers()).thenReturn(new X509Certificate[]{});

        X509ExtendedTrustManager trustManager = new LoggingX509ExtendedTrustManager(innerTrustManager);

        assertThat(trustManager.getAcceptedIssuers()).isEmpty();
        assertThat(trustedCerts).hasSize(1);

        assertThatCode(() -> trustManager.checkClientTrusted(trustedCerts, "RSA", (SSLEngine) null))
                .doesNotThrowAnyException();

        verify(innerTrustManager, times(1)).checkClientTrusted(trustedCerts, "RSA", (SSLEngine) null);
        verify(innerTrustManager, times(1)).getAcceptedIssuers();

        assertThat(logCaptor.getLogs()).hasSize(1);
    }

    @Test
    void checkClientTrustedWithSocket() throws KeyStoreException, CertificateException {
        LogCaptor logCaptor = LogCaptor.forClass(LoggingX509ExtendedTrustManager.class);

        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        X509Certificate[] trustedCerts = KeyStoreTestUtils.getTrustedX509Certificates(trustStore);

        X509ExtendedTrustManager innerTrustManager = mock(X509ExtendedTrustManager.class);
        doNothing().when(innerTrustManager).checkClientTrusted(any(), any(), any(Socket.class));
        when(innerTrustManager.getAcceptedIssuers()).thenReturn(new X509Certificate[]{});

        X509ExtendedTrustManager trustManager = new LoggingX509ExtendedTrustManager(innerTrustManager);

        assertThat(trustManager.getAcceptedIssuers()).isEmpty();
        assertThat(trustedCerts).hasSize(1);

        assertThatCode(() -> trustManager.checkClientTrusted(trustedCerts, "RSA", (Socket) null))
                .doesNotThrowAnyException();

        verify(innerTrustManager, times(1)).checkClientTrusted(trustedCerts, "RSA", (Socket) null);
        verify(innerTrustManager, times(1)).getAcceptedIssuers();

        assertThat(logCaptor.getLogs()).hasSize(1);
    }

    @Test
    void checkServerTrusted() throws KeyStoreException, CertificateException {
        LogCaptor logCaptor = LogCaptor.forClass(LoggingX509ExtendedTrustManager.class);

        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        X509Certificate[] trustedCerts = KeyStoreTestUtils.getTrustedX509Certificates(trustStore);

        X509ExtendedTrustManager innerTrustManager = mock(X509ExtendedTrustManager.class);
        doNothing().when(innerTrustManager).checkServerTrusted(any(), any());
        when(innerTrustManager.getAcceptedIssuers()).thenReturn(new X509Certificate[]{});

        X509ExtendedTrustManager trustManager = new LoggingX509ExtendedTrustManager(innerTrustManager);

        assertThat(trustManager.getAcceptedIssuers()).isEmpty();
        assertThat(trustedCerts).hasSize(1);

        assertThatCode(() -> trustManager.checkServerTrusted(trustedCerts, "RSA"))
                .doesNotThrowAnyException();

        verify(innerTrustManager, times(1)).checkServerTrusted(trustedCerts, "RSA");
        verify(innerTrustManager, times(1)).getAcceptedIssuers();

        assertThat(logCaptor.getLogs()).hasSize(1);
    }

    @Test
    void checkServerTrustedWithSslEngine() throws KeyStoreException, CertificateException {
        LogCaptor logCaptor = LogCaptor.forClass(LoggingX509ExtendedTrustManager.class);

        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        X509Certificate[] trustedCerts = KeyStoreTestUtils.getTrustedX509Certificates(trustStore);

        X509ExtendedTrustManager innerTrustManager = mock(X509ExtendedTrustManager.class);
        doNothing().when(innerTrustManager).checkServerTrusted(any(), any(), any(SSLEngine.class));
        when(innerTrustManager.getAcceptedIssuers()).thenReturn(new X509Certificate[]{});

        X509ExtendedTrustManager trustManager = new LoggingX509ExtendedTrustManager(innerTrustManager);

        assertThat(trustManager.getAcceptedIssuers()).isEmpty();
        assertThat(trustedCerts).hasSize(1);

        assertThatCode(() -> trustManager.checkServerTrusted(trustedCerts, "RSA", (SSLEngine) null))
                .doesNotThrowAnyException();

        verify(innerTrustManager, times(1)).checkServerTrusted(trustedCerts, "RSA", (SSLEngine) null);
        verify(innerTrustManager, times(1)).getAcceptedIssuers();

        assertThat(logCaptor.getLogs()).hasSize(1);
    }

    @Test
    void checkServerTrustedWitSocket() throws KeyStoreException, CertificateException {
        LogCaptor logCaptor = LogCaptor.forClass(LoggingX509ExtendedTrustManager.class);

        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        X509Certificate[] trustedCerts = KeyStoreTestUtils.getTrustedX509Certificates(trustStore);

        X509ExtendedTrustManager innerTrustManager = mock(X509ExtendedTrustManager.class);
        doNothing().when(innerTrustManager).checkServerTrusted(any(), any(), any(Socket.class));
        when(innerTrustManager.getAcceptedIssuers()).thenReturn(new X509Certificate[]{});

        X509ExtendedTrustManager trustManager = new LoggingX509ExtendedTrustManager(innerTrustManager);

        assertThat(trustManager.getAcceptedIssuers()).isEmpty();
        assertThat(trustedCerts).hasSize(1);

        assertThatCode(() -> trustManager.checkServerTrusted(trustedCerts, "RSA", (Socket) null))
                .doesNotThrowAnyException();

        verify(innerTrustManager, times(1)).checkServerTrusted(trustedCerts, "RSA", (Socket) null);
        verify(innerTrustManager, times(1)).getAcceptedIssuers();

        assertThat(logCaptor.getLogs()).hasSize(1);
    }

}
