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

import nl.altindag.log.LogCaptor;
import nl.altindag.ssl.util.KeyStoreUtils;
import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedTrustManager;
import java.io.IOException;
import java.net.Socket;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

/**
 * @author Hakan Altindag
 */
class UnsafeX509ExtendedTrustManagerShould {

    private static final String TRUSTSTORE_FILE_NAME = "truststore.jks";
    private static final char[] TRUSTSTORE_PASSWORD = new char[] {'s', 'e', 'c', 'r', 'e', 't'};
    private static final String KEYSTORE_FILE_NAME = "identity.jks";
    private static final char[] KEYSTORE_PASSWORD = new char[] {'s', 'e', 'c', 'r', 'e', 't'};
    private static final String KEYSTORE_LOCATION = "keystores-for-unit-tests/";

    @Test
    void checkClientTrusted() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        LogCaptor logCaptor = LogCaptor.forClass(UnsafeX509ExtendedTrustManager.class);

        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        X509ExtendedTrustManager trustManager = UnsafeX509ExtendedTrustManager.INSTANCE;
        X509Certificate[] trustedCerts = KeyStoreTestUtils.getTrustedX509Certificates(trustStore);

        assertThat(trustManager).isNotNull();
        assertThat(trustManager.getAcceptedIssuers()).isEmpty();
        assertThat(trustedCerts).hasSize(1);

        assertThatCode(() -> trustManager.checkClientTrusted(trustedCerts, "RSA"))
                .doesNotThrowAnyException();

        assertThat(logCaptor.getDebugLogs())
                .hasSize(1)
                .containsExactly("Accepting a client certificate: [CN=*.google.com, O=Google LLC, L=Mountain View, ST=California, C=US]");
    }

    @Test
    void checkClientTrustedWithSslEngine() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        LogCaptor logCaptor = LogCaptor.forClass(UnsafeX509ExtendedTrustManager.class);

        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        X509ExtendedTrustManager trustManager = UnsafeX509ExtendedTrustManager.INSTANCE;
        X509Certificate[] trustedCerts = KeyStoreTestUtils.getTrustedX509Certificates(trustStore);

        assertThat(trustManager).isNotNull();
        assertThat(trustManager.getAcceptedIssuers()).isEmpty();
        assertThat(trustedCerts).hasSize(1);

        assertThatCode(() -> trustManager.checkClientTrusted(trustedCerts, "RSA", (SSLEngine) null))
                .doesNotThrowAnyException();

        assertThat(logCaptor.getDebugLogs())
                .hasSize(1)
                .contains("Accepting a client certificate: [CN=*.google.com, O=Google LLC, L=Mountain View, ST=California, C=US]");
    }

    @Test
    void checkClientTrustedWithSocket() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        LogCaptor logCaptor = LogCaptor.forClass(UnsafeX509ExtendedTrustManager.class);

        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        X509ExtendedTrustManager trustManager = UnsafeX509ExtendedTrustManager.INSTANCE;
        X509Certificate[] trustedCerts = KeyStoreTestUtils.getTrustedX509Certificates(trustStore);

        assertThat(trustManager).isNotNull();
        assertThat(trustManager.getAcceptedIssuers()).isEmpty();
        assertThat(trustedCerts).hasSize(1);

        assertThatCode(() -> trustManager.checkClientTrusted(trustedCerts, "RSA", (Socket) null))
                .doesNotThrowAnyException();

        assertThat(logCaptor.getDebugLogs())
                .hasSize(1)
                .contains("Accepting a client certificate: [CN=*.google.com, O=Google LLC, L=Mountain View, ST=California, C=US]");
    }

    @Test
    void checkServerTrusted() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        LogCaptor logCaptor = LogCaptor.forClass(UnsafeX509ExtendedTrustManager.class);

        X509Certificate[] trustedCerts = KeyStoreTestUtils.getTrustedX509Certificates(KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + KEYSTORE_FILE_NAME, KEYSTORE_PASSWORD));

        X509ExtendedTrustManager trustManager = UnsafeX509ExtendedTrustManager.INSTANCE;

        assertThat(trustedCerts).hasSize(1);
        assertThat(trustManager.getAcceptedIssuers()).isEmpty();

        assertThatCode(() -> trustManager.checkServerTrusted(trustedCerts, "RSA"))
                .doesNotThrowAnyException();

        assertThat(logCaptor.getDebugLogs())
                .hasSize(1)
                .contains("Accepting a server certificate: [CN=Prof Oak, OU=Oak Pokémon Research Lab, O=Oak Pokémon Research Lab, C=Pallet Town]");
    }

    @Test
    void checkServerTrustedWithSslEngine() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        LogCaptor logCaptor = LogCaptor.forClass(UnsafeX509ExtendedTrustManager.class);

        X509Certificate[] trustedCerts = KeyStoreTestUtils.getTrustedX509Certificates(KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + KEYSTORE_FILE_NAME, KEYSTORE_PASSWORD));

        X509ExtendedTrustManager trustManager = UnsafeX509ExtendedTrustManager.INSTANCE;

        assertThat(trustedCerts).hasSize(1);
        assertThat(trustManager.getAcceptedIssuers()).isEmpty();

        assertThatCode(() -> trustManager.checkServerTrusted(trustedCerts, "RSA", (SSLEngine) null))
                .doesNotThrowAnyException();

        assertThat(logCaptor.getDebugLogs())
                .hasSize(1)
                .contains("Accepting a server certificate: [CN=Prof Oak, OU=Oak Pokémon Research Lab, O=Oak Pokémon Research Lab, C=Pallet Town]");
    }

    @Test
    void checkServerTrustedWitSocket() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        LogCaptor logCaptor = LogCaptor.forClass(UnsafeX509ExtendedTrustManager.class);

        X509Certificate[] trustedCerts = KeyStoreTestUtils.getTrustedX509Certificates(KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + KEYSTORE_FILE_NAME, KEYSTORE_PASSWORD));

        X509ExtendedTrustManager trustManager = UnsafeX509ExtendedTrustManager.INSTANCE;

        assertThat(trustedCerts).hasSize(1);
        assertThat(trustManager.getAcceptedIssuers()).isEmpty();

        assertThatCode(() -> trustManager.checkServerTrusted(trustedCerts, "RSA", (Socket) null))
                .doesNotThrowAnyException();

        assertThat(logCaptor.getDebugLogs())
                .hasSize(1)
                .contains("Accepting a server certificate: [CN=Prof Oak, OU=Oak Pokémon Research Lab, O=Oak Pokémon Research Lab, C=Pallet Town]");
    }

    @Test
    void checkClientTrustedDoesNotLogAnythingWhenDebugLevelIsDisabled() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        LogCaptor logCaptor = LogCaptor.forClass(UnsafeX509ExtendedTrustManager.class);
        logCaptor.setLogLevelToInfo();

        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        X509ExtendedTrustManager trustManager = UnsafeX509ExtendedTrustManager.INSTANCE;
        X509Certificate[] trustedCerts = KeyStoreTestUtils.getTrustedX509Certificates(trustStore);

        assertThat(trustManager).isNotNull();
        assertThat(trustManager.getAcceptedIssuers()).isEmpty();
        assertThat(trustedCerts).hasSize(1);

        assertThatCode(() -> trustManager.checkClientTrusted(trustedCerts, "RSA"))
                .doesNotThrowAnyException();

        assertThat(logCaptor.getDebugLogs()).isEmpty();
        logCaptor.resetLogLevel();
    }

    @Test
    void checkClientTrustedWithSslEngineDoesNotLogAnythingWhenDebugLevelIsDisabled() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        LogCaptor logCaptor = LogCaptor.forClass(UnsafeX509ExtendedTrustManager.class);
        logCaptor.setLogLevelToInfo();

        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        X509ExtendedTrustManager trustManager = UnsafeX509ExtendedTrustManager.INSTANCE;
        X509Certificate[] trustedCerts = KeyStoreTestUtils.getTrustedX509Certificates(trustStore);

        assertThat(trustManager).isNotNull();
        assertThat(trustManager.getAcceptedIssuers()).isEmpty();
        assertThat(trustedCerts).hasSize(1);

        assertThatCode(() -> trustManager.checkClientTrusted(trustedCerts, "RSA", (SSLEngine) null))
                .doesNotThrowAnyException();

        assertThat(logCaptor.getDebugLogs()).isEmpty();
        logCaptor.resetLogLevel();
    }

    @Test
    void checkClientTrustedWithSocketDoesNotLogAnythingWhenDebugLevelIsDisabled() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        LogCaptor logCaptor = LogCaptor.forClass(UnsafeX509ExtendedTrustManager.class);
        logCaptor.setLogLevelToInfo();

        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        X509ExtendedTrustManager trustManager = UnsafeX509ExtendedTrustManager.INSTANCE;
        X509Certificate[] trustedCerts = KeyStoreTestUtils.getTrustedX509Certificates(trustStore);

        assertThat(trustManager).isNotNull();
        assertThat(trustManager.getAcceptedIssuers()).isEmpty();
        assertThat(trustedCerts).hasSize(1);

        assertThatCode(() -> trustManager.checkClientTrusted(trustedCerts, "RSA", (Socket) null))
                .doesNotThrowAnyException();

        assertThat(logCaptor.getDebugLogs()).isEmpty();
        logCaptor.resetLogLevel();
    }

    @Test
    void checkServerTrustedDoesNotLogAnythingWhenDebugLevelIsDisabled() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        LogCaptor logCaptor = LogCaptor.forClass(UnsafeX509ExtendedTrustManager.class);
        logCaptor.setLogLevelToInfo();

        X509Certificate[] trustedCerts = KeyStoreTestUtils.getTrustedX509Certificates(KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + KEYSTORE_FILE_NAME, KEYSTORE_PASSWORD));

        X509ExtendedTrustManager trustManager = UnsafeX509ExtendedTrustManager.INSTANCE;

        assertThat(trustedCerts).hasSize(1);
        assertThat(trustManager.getAcceptedIssuers()).isEmpty();

        assertThatCode(() -> trustManager.checkServerTrusted(trustedCerts, "RSA"))
                .doesNotThrowAnyException();

        assertThat(logCaptor.getDebugLogs()).isEmpty();
        logCaptor.resetLogLevel();
    }

    @Test
    void checkServerTrustedWithSslEngineDoesNotLogAnythingWhenDebugLevelIsDisabled() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        LogCaptor logCaptor = LogCaptor.forClass(UnsafeX509ExtendedTrustManager.class);
        logCaptor.setLogLevelToInfo();

        X509Certificate[] trustedCerts = KeyStoreTestUtils.getTrustedX509Certificates(KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + KEYSTORE_FILE_NAME, KEYSTORE_PASSWORD));

        X509ExtendedTrustManager trustManager = UnsafeX509ExtendedTrustManager.INSTANCE;

        assertThat(trustedCerts).hasSize(1);
        assertThat(trustManager.getAcceptedIssuers()).isEmpty();

        assertThatCode(() -> trustManager.checkServerTrusted(trustedCerts, "RSA", (SSLEngine) null))
                .doesNotThrowAnyException();

        assertThat(logCaptor.getDebugLogs()).isEmpty();
        logCaptor.resetLogLevel();
    }

    @Test
    void checkServerTrustedWithSocketDoesNotLogAnythingWhenDebugLevelIsDisabled() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        LogCaptor logCaptor = LogCaptor.forClass(UnsafeX509ExtendedTrustManager.class);
        logCaptor.setLogLevelToInfo();

        X509Certificate[] trustedCerts = KeyStoreTestUtils.getTrustedX509Certificates(KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + KEYSTORE_FILE_NAME, KEYSTORE_PASSWORD));

        X509ExtendedTrustManager trustManager = UnsafeX509ExtendedTrustManager.INSTANCE;

        assertThat(trustedCerts).hasSize(1);
        assertThat(trustManager.getAcceptedIssuers()).isEmpty();

        assertThatCode(() -> trustManager.checkServerTrusted(trustedCerts, "RSA", (Socket) null))
                .doesNotThrowAnyException();

        assertThat(logCaptor.getDebugLogs()).isEmpty();
        logCaptor.resetLogLevel();
    }

}
