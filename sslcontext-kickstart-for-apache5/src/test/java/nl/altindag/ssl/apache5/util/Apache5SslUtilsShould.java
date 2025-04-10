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
package nl.altindag.ssl.apache5.util;

import nl.altindag.ssl.SSLFactory;
import nl.altindag.ssl.util.KeyStoreUtils;
import org.apache.hc.client5.http.ssl.TlsSocketStrategy;
import org.apache.hc.core5.http.nio.ssl.TlsStrategy;
import org.junit.jupiter.api.Test;

import java.security.KeyStore;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Hakan Altindag
 */
class Apache5SslUtilsShould {

    private static final String IDENTITY_FILE_NAME = "identity.jks";
    private static final String TRUSTSTORE_FILE_NAME = "truststore.jks";

    private static final char[] IDENTITY_PASSWORD = "secret".toCharArray();
    private static final char[] TRUSTSTORE_PASSWORD = "secret".toCharArray();
    private static final String KEYSTORE_LOCATION = "keystore/";

    @Test
    void createTlsStrategy() {
        KeyStore identity = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);
        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);

        SSLFactory sslFactory = SSLFactory.builder()
                .withIdentityMaterial(identity, IDENTITY_PASSWORD)
                .withTrustMaterial(trustStore)
                .build();

        TlsStrategy tlsStrategy = Apache5SslUtils.toTlsStrategy(sslFactory);
        assertThat(tlsStrategy).isNotNull();
    }

    @Test
    void createTlsSocketStrategy() {
        KeyStore identity = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);
        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);

        SSLFactory sslFactory = SSLFactory.builder()
                .withIdentityMaterial(identity, IDENTITY_PASSWORD)
                .withTrustMaterial(trustStore)
                .build();

        TlsSocketStrategy tlsSocketStrategy = Apache5SslUtils.toTlsSocketStrategy(sslFactory);
        assertThat(tlsSocketStrategy).isNotNull();
    }

}
