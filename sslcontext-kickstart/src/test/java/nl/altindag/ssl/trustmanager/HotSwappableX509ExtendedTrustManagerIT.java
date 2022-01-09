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

import nl.altindag.ssl.SSLFactory;
import nl.altindag.ssl.util.KeyStoreUtils;
import nl.altindag.ssl.util.SSLSessionUtils;
import nl.altindag.ssl.util.TrustManagerUtils;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.X509ExtendedTrustManager;
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
class HotSwappableX509ExtendedTrustManagerIT {

    private static SSLSocketFactory sslSocketFactory;
    private static SSLSessionContext sslSessionContext;
    private static X509ExtendedTrustManager trustManager;

    @BeforeAll
    static void setUpSSLSocketFactory() {
        KeyStore trustStoreWithBadSsl = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + "badssl-truststore.p12", "badssl.com".toCharArray());
        X509ExtendedTrustManager trustManagerWithBadSsl = TrustManagerUtils.createTrustManager(trustStoreWithBadSsl);
        trustManager = TrustManagerUtils.createSwappableTrustManager(trustManagerWithBadSsl);

        SSLFactory sslFactory = SSLFactory.builder()
                .withIdentityMaterial(KEYSTORE_LOCATION + "badssl-identity.p12", "badssl.com".toCharArray())
                .withTrustMaterial(trustManager)
                .build();

        sslSocketFactory = sslFactory.getSslSocketFactory();
        sslSessionContext = sslFactory.getSslContext().getClientSessionContext();
    }

    @Test
    @Order(1)
    @Tag("it-with-badssl.com")
    void executeHttpsRequestWithSslSocketFactoryContainingBadSslTrustManager() throws IOException {
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
    @Tag("it-with-badssl.com")
    void executeHttpsRequestWithExistingSslSocketFactoryContainingASwappedUnsafeTrustManager() throws IOException {
        TrustManagerUtils.swapTrustManager(trustManager, TrustManagerUtils.createUnsafeTrustManager());
        SSLSessionUtils.invalidateCaches(sslSessionContext);

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

}
