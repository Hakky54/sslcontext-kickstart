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

package nl.altindag.ssl.keymanager;

import nl.altindag.ssl.SSLFactory;
import nl.altindag.ssl.util.KeyManagerUtils;
import nl.altindag.ssl.util.KeyStoreUtils;
import nl.altindag.ssl.util.SSLSessionUtils;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.X509ExtendedKeyManager;
import java.io.IOException;
import java.net.URL;
import java.security.KeyStore;

import static nl.altindag.ssl.TestConstants.KEYSTORE_LOCATION;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;

/**
 * @author Hakan Altindag
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class HotSwappableX509ExtendedKeyManagerIT {

    private static SSLSocketFactory sslSocketFactory;
    private static SSLSessionContext sslSessionContext;
    private static X509ExtendedKeyManager keyManager;

    @BeforeAll
    static void setUpSSLSocketFactory() {
        KeyStore identityStoreWithBadSsl = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + "badssl-identity.p12", "badssl.com".toCharArray());
        X509ExtendedKeyManager keyManagerWithBadSsl = KeyManagerUtils.createKeyManager(identityStoreWithBadSsl, "badssl.com".toCharArray());
        keyManager = KeyManagerUtils.createSwappableKeyManager(keyManagerWithBadSsl);

        SSLFactory sslFactory = SSLFactory.builder()
                .withIdentityMaterial(keyManager)
                .withTrustMaterial(KEYSTORE_LOCATION + "badssl-truststore.p12", "badssl.com".toCharArray())
                .build();

        sslSocketFactory = sslFactory.getSslSocketFactory();
        sslSessionContext = sslFactory.getSslContext().getClientSessionContext();
    }

    @Test
    @Order(1)
    void executeHttpsRequestWithSslSocketFactoryContainingBadSslKeyManager() throws IOException {
        HttpsURLConnection connection = (HttpsURLConnection) new URL("https://client.badssl.com/").openConnection();
        connection.setSSLSocketFactory(sslSocketFactory);
        connection.setRequestMethod("GET");

        int statusCode = connection.getResponseCode();
        connection.disconnect();

        if (statusCode == 400) {
            fail("Certificate may have expired and needs to be updated");
        } else {
            assertThat(statusCode).isEqualTo(200);
        }
    }

    @Test
    @Order(2)
    void executeHttpsRequestWithExistingSslSocketFactoryContainingASwappedKeyManager() throws IOException {
        KeyStore identityStore = KeyStoreUtils.loadKeyStore("keystores-for-unit-tests/identity.jks", "secret".toCharArray());
        X509ExtendedKeyManager anotherKeyManager = KeyManagerUtils.createKeyManager(identityStore, "secret".toCharArray());

        KeyManagerUtils.swapKeyManager(keyManager, anotherKeyManager);
        SSLSessionUtils.invalidateCaches(sslSessionContext);

        HttpsURLConnection connection = (HttpsURLConnection) new URL("https://client.badssl.com/").openConnection();
        connection.setSSLSocketFactory(sslSocketFactory);
        connection.setRequestMethod("GET");

        int statusCode = connection.getResponseCode();
        connection.disconnect();

        assertThat(statusCode).isEqualTo(400);
    }

}
