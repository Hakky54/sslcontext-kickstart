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
import nl.altindag.ssl.util.HostUtils;
import nl.altindag.ssl.util.KeyStoreUtils;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedTrustManager;
import java.net.Socket;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.AbstractMap;
import java.util.Arrays;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
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
        assertThat(logCaptor.getLogs().get(0))
                .contains("Validating the certificate chain of the client with authentication type RSA. See below for the full chain of the client")
                .contains(Arrays.toString(trustedCerts));
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

        SSLEngine sslEngine = mock(SSLEngine.class);
        try (MockedStatic<HostUtils> mockedStatic = mockStatic(HostUtils.class)) {
            mockedStatic.when(() -> HostUtils.extractHostAndPort(any(SSLEngine.class))).thenReturn(new AbstractMap.SimpleEntry<>("foo", 443));

            assertThatCode(() -> trustManager.checkClientTrusted(trustedCerts, "RSA", sslEngine))
                    .doesNotThrowAnyException();
        }

        verify(innerTrustManager, times(1)).checkClientTrusted(trustedCerts, "RSA", sslEngine);
        verify(innerTrustManager, times(1)).getAcceptedIssuers();

        assertThat(logCaptor.getLogs()).hasSize(1);
        assertThat(logCaptor.getLogs().get(0))
                .contains("Validating the certificate chain of the client[foo:443] with authentication type RSA, while also using the SSLEngine. See below for the full chain of the client")
                .contains(Arrays.toString(trustedCerts));
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

        Socket socket = mock(Socket.class);
        try (MockedStatic<HostUtils> mockedStatic = mockStatic(HostUtils.class)) {
            mockedStatic.when(() -> HostUtils.extractHostAndPort(any(Socket.class))).thenReturn(new AbstractMap.SimpleEntry<>("foo", 443));

            assertThatCode(() -> trustManager.checkClientTrusted(trustedCerts, "RSA", socket))
                    .doesNotThrowAnyException();
        }

        verify(innerTrustManager, times(1)).checkClientTrusted(trustedCerts, "RSA", socket);
        verify(innerTrustManager, times(1)).getAcceptedIssuers();

        assertThat(logCaptor.getLogs()).hasSize(1);
        assertThat(logCaptor.getLogs().get(0))
                .contains("Validating the certificate chain of the client[foo:443] with authentication type RSA, while also using the Socket. See below for the full chain of the client:")
                .contains(Arrays.toString(trustedCerts));
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
        assertThat(logCaptor.getLogs().get(0))
                .contains("Validating the certificate chain of the server with authentication type RSA. See below for the full chain of the server")
                .contains(Arrays.toString(trustedCerts));
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

        SSLEngine sslEngine = mock(SSLEngine.class);
        try (MockedStatic<HostUtils> mockedStatic = mockStatic(HostUtils.class)) {
            mockedStatic.when(() -> HostUtils.extractHostAndPort(any(SSLEngine.class))).thenReturn(new AbstractMap.SimpleEntry<>("foo", 443));

            assertThatCode(() -> trustManager.checkServerTrusted(trustedCerts, "RSA", sslEngine))
                    .doesNotThrowAnyException();
        }

        verify(innerTrustManager, times(1)).checkServerTrusted(trustedCerts, "RSA", sslEngine);
        verify(innerTrustManager, times(1)).getAcceptedIssuers();

        assertThat(logCaptor.getLogs()).hasSize(1);
        assertThat(logCaptor.getLogs().get(0))
                .contains("Validating the certificate chain of the server[foo:443] with authentication type RSA, while also using the SSLEngine. See below for the full chain of the server")
                .contains(Arrays.toString(trustedCerts));
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

        Socket socket = mock(Socket.class);
        try (MockedStatic<HostUtils> mockedStatic = mockStatic(HostUtils.class)) {
            mockedStatic.when(() -> HostUtils.extractHostAndPort(any(Socket.class))).thenReturn(new AbstractMap.SimpleEntry<>("foo", 443));

            assertThatCode(() -> trustManager.checkServerTrusted(trustedCerts, "RSA", socket))
                    .doesNotThrowAnyException();
        }

        verify(innerTrustManager, times(1)).checkServerTrusted(trustedCerts, "RSA", socket);
        verify(innerTrustManager, times(1)).getAcceptedIssuers();

        assertThat(logCaptor.getLogs()).hasSize(1);
        assertThat(logCaptor.getLogs().get(0))
                .contains("Validating the certificate chain of the server[foo:443] with authentication type RSA, while also using the Socket. See below for the full chain of the server:")
                .contains(Arrays.toString(trustedCerts));
    }

    @Test
    void returnReturnClassnameSocketIfItIsPresent() {
        Socket socket = mock(Socket.class);
        Optional<String> classname = LoggingX509ExtendedTrustManager.getClassnameOfEitherOrOther(socket, null);

        assertThat(classname)
                .isPresent()
                .hasValue("Socket");
    }

    @Test
    void returnReturnClassnameSSLEngineIfItIsPresent() {
        SSLEngine sslEngine = mock(SSLEngine.class);
        Optional<String> classname = LoggingX509ExtendedTrustManager.getClassnameOfEitherOrOther(null, sslEngine);

        assertThat(classname)
                .isPresent()
                .hasValue("SSLEngine");
    }

    @Test
    void returnReturnEmptyClassnameIfSocketAndSSLEngineAreNull() {
        Optional<String> classname = LoggingX509ExtendedTrustManager.getClassnameOfEitherOrOther(null, null);

        assertThat(classname).isNotPresent();
    }

    @Test
    void returnHostAndPortIfSocketIsPresent() {
        Socket socket = mock(Socket.class);

        try (MockedStatic<HostUtils> mockedStatic = mockStatic(HostUtils.class)) {
            mockedStatic.when(() -> HostUtils.extractHostAndPort(any(Socket.class))).thenReturn(new AbstractMap.SimpleEntry<>("foo", 443));
            Optional<String> hostAndPort = LoggingX509ExtendedTrustManager.getHostAndPortOfEitherOrOther(socket, null);

            assertThat(hostAndPort)
                    .isPresent()
                    .hasValue("foo:443");
        }
    }

    @Test
    void returnHostAndPortIfSSLEngineIsPresent() {
        SSLEngine sslEngine = mock(SSLEngine.class);

        try (MockedStatic<HostUtils> mockedStatic = mockStatic(HostUtils.class)) {
            mockedStatic.when(() -> HostUtils.extractHostAndPort(any(SSLEngine.class))).thenReturn(new AbstractMap.SimpleEntry<>("foo", 443));
            Optional<String> hostAndPort = LoggingX509ExtendedTrustManager.getHostAndPortOfEitherOrOther(null, sslEngine);

            assertThat(hostAndPort)
                    .isPresent()
                    .hasValue("foo:443");
        }
    }

    @Test
    void returnEmptyHostAndPortIfSocketAndSSLEngineAreNull() {
        Optional<String> hostAndPort = LoggingX509ExtendedTrustManager.getHostAndPortOfEitherOrOther(null, null);
        assertThat(hostAndPort).isNotPresent();
    }

}
