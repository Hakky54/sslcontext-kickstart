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

import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLContext;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509ExtendedTrustManager;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Collections;

import static nl.altindag.ssl.TestConstants.IDENTITY_FILE_NAME;
import static nl.altindag.ssl.TestConstants.IDENTITY_PASSWORD;
import static nl.altindag.ssl.TestConstants.KEYSTORE_LOCATION;
import static nl.altindag.ssl.TestConstants.TRUSTSTORE_FILE_NAME;
import static nl.altindag.ssl.TestConstants.TRUSTSTORE_PASSWORD;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Hakan Altindag
 */
class SSLContextUtilsShould {


    @Test
    void createSslContextFromList() {
        KeyStore identity = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);
        X509ExtendedKeyManager keyManager = KeyManagerUtils.createKeyManager(identity, IDENTITY_PASSWORD);

        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        X509ExtendedTrustManager trustManager = TrustManagerUtils.createTrustManager(trustStore);

        SSLContext sslContext = SSLContextUtils.createSslContext(Collections.singletonList(keyManager), Collections.singletonList(trustManager));
        assertThat(sslContext).isNotNull();
    }

    @Test
    void createSslContextFromCustomSecureRandomAndAndSslContextAlgorithmAndSecurityProviderName() {
        KeyStore identity = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);
        X509ExtendedKeyManager keyManager = KeyManagerUtils.createKeyManager(identity, IDENTITY_PASSWORD);

        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        X509ExtendedTrustManager trustManager = TrustManagerUtils.createTrustManager(trustStore);

        SSLContext sslContext = SSLContextUtils.createSslContext(
                Collections.singletonList(keyManager),
                Collections.singletonList(trustManager),
                new SecureRandom(),
                "TLS",
                "SunJSSE"
        );
        assertThat(sslContext).isNotNull();
    }

    @Test
    void createSslContextFromCustomSecureRandomAndAndSslContextAlgorithmAndSecurityProvider() {
        KeyStore identity = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);
        X509ExtendedKeyManager keyManager = KeyManagerUtils.createKeyManager(identity, IDENTITY_PASSWORD);

        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        X509ExtendedTrustManager trustManager = TrustManagerUtils.createTrustManager(trustStore);

        SSLContext sslContext = SSLContextUtils.createSslContext(
                Collections.singletonList(keyManager),
                Collections.singletonList(trustManager),
                new SecureRandom(),
                "TLS",
                Security.getProvider("SunJSSE")
        );
        assertThat(sslContext).isNotNull();
    }

    @Test
    void createSslContextFromEmptyKeyManagerAndTrustManager() {
        SSLContext sslContext = SSLContextUtils.createSslContext(
                Collections.emptyList(),
                Collections.emptyList(),
                new SecureRandom(),
                "TLS",
                Security.getProvider("SunJSSE")
        );
        assertThat(sslContext).isNotNull();
    }

    @Test
    void createSslContextFromEmptyKeyManagerAndTrustManagerWithOtherSslParameters() {
        SSLContext sslContext = SSLContextUtils.createSslContext(
                Collections.emptyList(),
                Collections.emptyList(),
                new SecureRandom(),
                "TLS",
                "SunJSSE"
        );
        assertThat(sslContext).isNotNull();
    }

}
