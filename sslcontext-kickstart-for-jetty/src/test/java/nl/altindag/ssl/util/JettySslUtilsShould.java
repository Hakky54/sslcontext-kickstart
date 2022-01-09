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

package nl.altindag.ssl.util;

import nl.altindag.ssl.SSLFactory;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.junit.jupiter.api.Test;

import java.security.KeyStore;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Hakan Altindag
 */
class JettySslUtilsShould {

    private static final String IDENTITY_FILE_NAME = "identity.jks";
    private static final String TRUSTSTORE_FILE_NAME = "truststore.jks";

    private static final char[] IDENTITY_PASSWORD = "secret".toCharArray();
    private static final char[] TRUSTSTORE_PASSWORD = "secret".toCharArray();
    private static final String KEYSTORE_LOCATION = "keystore/";

    @Test
    void createJettySslContextFactoryForClientWithTrustMaterial() {
        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);

        SSLFactory sslFactory = SSLFactory.builder()
                .withTrustMaterial(trustStore)
                .build();

        assertThat(sslFactory.getSslContext()).isNotNull();

        assertThat(sslFactory.getKeyManager()).isNotPresent();

        assertThat(sslFactory.getTrustManager()).isNotNull();
        assertThat(sslFactory.getTrustedCertificates()).isNotEmpty();
        assertThat(sslFactory.getTrustManager()).isNotNull();
        assertThat(sslFactory.getHostnameVerifier()).isNotNull();

        SslContextFactory.Client sslContextFactory = JettySslUtils.forClient(sslFactory);
        assertThat(sslContextFactory.getSslContext()).isEqualTo(sslFactory.getSslContext());
        assertThat(sslContextFactory.getHostnameVerifier()).isEqualTo(sslContextFactory.getHostnameVerifier());

        assertThat(sslContextFactory.getIncludeCipherSuites())
                .containsExactlyInAnyOrder(sslFactory.getSslContext().getDefaultSSLParameters().getCipherSuites());
        assertThat(sslContextFactory.getIncludeProtocols())
                .containsExactlyInAnyOrder(sslFactory.getSslContext().getDefaultSSLParameters().getProtocols());
    }

    @Test
    void createJettySslContextFactoryForClientWithIdentityMaterialAndTrustMaterial() {
        KeyStore identity = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);
        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);

        SSLFactory sslFactory = SSLFactory.builder()
                .withIdentityMaterial(identity, IDENTITY_PASSWORD)
                .withTrustMaterial(trustStore)
                .build();

        assertThat(sslFactory.getSslContext()).isNotNull();

        assertThat(sslFactory.getKeyManager()).isPresent();

        assertThat(sslFactory.getTrustManager()).isNotNull();
        assertThat(sslFactory.getTrustedCertificates()).isNotEmpty();
        assertThat(sslFactory.getTrustManager()).isNotNull();
        assertThat(sslFactory.getHostnameVerifier()).isNotNull();

        SslContextFactory.Client sslContextFactory = JettySslUtils.forClient(sslFactory);
        assertThat(sslContextFactory.getSslContext()).isEqualTo(sslFactory.getSslContext());
        assertThat(sslContextFactory.getHostnameVerifier()).isEqualTo(sslContextFactory.getHostnameVerifier());

        assertThat(sslContextFactory.getIncludeCipherSuites())
                .containsExactlyInAnyOrder(sslFactory.getSslContext().getDefaultSSLParameters().getCipherSuites());
        assertThat(sslContextFactory.getIncludeProtocols())
                .containsExactlyInAnyOrder(sslFactory.getSslContext().getDefaultSSLParameters().getProtocols());
    }

    @Test
    void createJettySslContextFactoryForServerWithIdentityMaterialAndTrustMaterial() {
        KeyStore identity = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);
        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);

        SSLFactory sslFactory = SSLFactory.builder()
                .withIdentityMaterial(identity, IDENTITY_PASSWORD)
                .withTrustMaterial(trustStore)
                .build();

        assertThat(sslFactory.getSslContext()).isNotNull();

        assertThat(sslFactory.getKeyManager()).isPresent();

        assertThat(sslFactory.getTrustManager()).isNotNull();
        assertThat(sslFactory.getTrustedCertificates()).isNotEmpty();
        assertThat(sslFactory.getTrustManager()).isNotNull();
        assertThat(sslFactory.getHostnameVerifier()).isNotNull();

        SslContextFactory.Server sslContextFactory = JettySslUtils.forServer(sslFactory);
        assertThat(sslContextFactory.getSslContext()).isEqualTo(sslFactory.getSslContext());
        assertThat(sslContextFactory.getHostnameVerifier()).isEqualTo(sslContextFactory.getHostnameVerifier());

        assertThat(sslContextFactory.getIncludeCipherSuites())
                .containsExactlyInAnyOrder(sslFactory.getSslContext().getDefaultSSLParameters().getCipherSuites());
        assertThat(sslContextFactory.getIncludeProtocols())
                .containsExactlyInAnyOrder(sslFactory.getSslContext().getDefaultSSLParameters().getProtocols());
    }

    @Test
    void createJettySslContextFactoryForServerWithNeedClientAuthentication() {
        KeyStore identity = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);
        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);

        SSLFactory sslFactory = SSLFactory.builder()
                .withIdentityMaterial(identity, IDENTITY_PASSWORD)
                .withTrustMaterial(trustStore)
                .withNeedClientAuthentication()
                .build();

        SslContextFactory.Server sslContextFactory = JettySslUtils.forServer(sslFactory);
        assertThat(sslContextFactory.getNeedClientAuth()).isTrue();
        assertThat(sslContextFactory.getWantClientAuth()).isFalse();
    }

    @Test
    void createJettySslContextFactoryForServerWithWantClientAuthentication() {
        KeyStore identity = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);
        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);

        SSLFactory sslFactory = SSLFactory.builder()
                .withIdentityMaterial(identity, IDENTITY_PASSWORD)
                .withTrustMaterial(trustStore)
                .withWantClientAuthentication()
                .build();

        SslContextFactory.Server sslContextFactory = JettySslUtils.forServer(sslFactory);
        assertThat(sslContextFactory.getWantClientAuth()).isTrue();
        assertThat(sslContextFactory.getNeedClientAuth()).isFalse();
    }

}
