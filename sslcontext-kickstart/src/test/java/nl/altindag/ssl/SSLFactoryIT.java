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

package nl.altindag.ssl;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsParameters;
import com.sun.net.httpserver.HttpsServer;
import nl.altindag.log.LogCaptor;
import nl.altindag.ssl.util.KeyManagerUtils;
import nl.altindag.ssl.util.KeyStoreUtils;
import nl.altindag.ssl.util.SSLSessionUtils;
import nl.altindag.ssl.util.TrustManagerUtils;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509ExtendedTrustManager;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.SocketException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.stream.Collectors;

import static nl.altindag.ssl.TestConstants.KEYSTORE_LOCATION;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * @author Hakan Altindag
 */
class SSLFactoryIT {

    private static final Logger LOGGER = LoggerFactory.getLogger(SSLFactoryIT.class);

    @Test
    void executeHttpsRequestWithMutualAuthentication() throws IOException {
        LogCaptor logCaptor = LogCaptor.forName("nl.altindag.ssl");

        SSLFactory sslFactory = SSLFactory.builder()
                .withIdentityMaterial(KEYSTORE_LOCATION + "badssl-identity.p12", "badssl.com".toCharArray())
                .withTrustMaterial(KEYSTORE_LOCATION + "badssl-truststore.p12", "badssl.com".toCharArray())
                .withTrustMaterial(KeyStoreUtils.createKeyStore()) // Adding additional trust material forces usage of CompositeX509ExtendedTrustManager and verbose logging
                .build();

        HttpsURLConnection connection = (HttpsURLConnection) new URL("https://client.badssl.com/").openConnection();
        connection.setSSLSocketFactory(sslFactory.getSslSocketFactory());
        connection.setHostnameVerifier(sslFactory.getHostnameVerifier());
        connection.setRequestMethod("GET");

        int statusCode = connection.getResponseCode();

        if (statusCode == 400) {
            LOGGER.warn("Certificate may have expired and needs to be updated");
        } else {
            assertThat(statusCode).isEqualTo(200);
            assertThat(logCaptor.getLogs()).containsExactly("Received the following server certificate: [CN=*.badssl.com, O=Lucas Garron Torres, L=Walnut Creek, ST=California, C=US]");
        }
    }

    @Test
    void executeRequestToTwoServersWithMutualAuthenticationWithSingleHttpClientAndSingleSslConfiguration() throws IOException {
        ExecutorService executorService = Executors.newSingleThreadExecutor();

        char[] keyStorePassword = "secret".toCharArray();
        SSLFactory sslFactoryForServerOne = SSLFactory.builder()
                .withIdentityMaterial("keystores-for-unit-tests/client-server/server-one/identity.jks", keyStorePassword)
                .withTrustMaterial("keystores-for-unit-tests/client-server/server-one/truststore.jks", keyStorePassword)
                .withNeedClientAuthentication()
                .withProtocols("TLSv1.2")
                .build();

        SSLFactory sslFactoryForServerTwo = SSLFactory.builder()
                .withIdentityMaterial("keystores-for-unit-tests/client-server/server-two/identity.jks", keyStorePassword)
                .withTrustMaterial("keystores-for-unit-tests/client-server/server-two/truststore.jks", keyStorePassword)
                .withNeedClientAuthentication()
                .withProtocols("TLSv1.2")
                .build();

        HttpsServer serverOne = ServerUtils.createServer(8443, sslFactoryForServerOne, executorService, "Hello from server one");
        HttpsServer serverTwo = ServerUtils.createServer(8444, sslFactoryForServerTwo, executorService, "Hello from server two");

        serverOne.start();
        serverTwo.start();

        SSLFactory sslFactoryForClient = SSLFactory.builder()
                .withIdentityMaterial("keystores-for-unit-tests/client-server/client-one/identity.jks", keyStorePassword)
                .withIdentityMaterial("keystores-for-unit-tests/client-server/client-two/identity.jks", keyStorePassword)
                .withTrustMaterial("keystores-for-unit-tests/client-server/client-one/truststore.jks", keyStorePassword)
                .withTrustMaterial("keystores-for-unit-tests/client-server/client-two/truststore.jks", keyStorePassword)
                .withProtocols("TLSv1.2")
                .build();

        Response response = executeRequest("https://localhost:8443/api/hello", sslFactoryForClient.getSslSocketFactory());

        assertThat(response.getStatusCode()).isEqualTo(200);
        assertThat(response.getBody()).contains("Hello from server one");

        response = executeRequest("https://localhost:8444/api/hello", sslFactoryForClient.getSslSocketFactory());

        assertThat(response.getStatusCode()).isEqualTo(200);
        assertThat(response.getBody()).contains("Hello from server two");

        serverOne.stop(0);
        serverTwo.stop(0);
        executorService.shutdownNow();
    }

    @Test
    void executeRequestToTwoServersWithMutualAuthenticationWithReroutingClientCertificates() throws IOException {
        ExecutorService executorService = Executors.newSingleThreadExecutor();

        char[] keyStorePassword = "secret".toCharArray();
        SSLFactory sslFactoryForServerOne = SSLFactory.builder()
                .withIdentityMaterial("keystores-for-unit-tests/client-server/server-one/identity.jks", keyStorePassword)
                .withTrustMaterial("keystores-for-unit-tests/client-server/server-one/truststore.jks", keyStorePassword)
                .withNeedClientAuthentication()
                .withSessionTimeout(1)
                .withProtocols("TLSv1.2")
                .build();

        SSLFactory sslFactoryForServerTwo = SSLFactory.builder()
                .withIdentityMaterial("keystores-for-unit-tests/client-server/server-two/identity.jks", keyStorePassword)
                .withTrustMaterial("keystores-for-unit-tests/client-server/server-two/truststore.jks", keyStorePassword)
                .withNeedClientAuthentication()
                .withSessionTimeout(1)
                .withProtocols("TLSv1.2")
                .build();

        HttpsServer serverOne = ServerUtils.createServer(8443, sslFactoryForServerOne, executorService, "Hello from server one");
        HttpsServer serverTwo = ServerUtils.createServer(8444, sslFactoryForServerTwo, executorService, "Hello from server two");

        serverOne.start();
        serverTwo.start();

        Map<String, List<String>> clientAliasesToHosts = new HashMap<>();
        clientAliasesToHosts.put("client-one", Collections.singletonList("https://localhost:8443/api/hello"));
        clientAliasesToHosts.put("client-two", Collections.singletonList("https://localhost:8444/api/hello"));

        SSLFactory sslFactoryForClient = SSLFactory.builder()
                .withIdentityMaterial("keystores-for-unit-tests/client-server/client-one/identity.jks", keyStorePassword)
                .withIdentityMaterial("keystores-for-unit-tests/client-server/client-two/identity.jks", keyStorePassword)
                .withTrustMaterial("keystores-for-unit-tests/client-server/client-one/truststore.jks", keyStorePassword)
                .withTrustMaterial("keystores-for-unit-tests/client-server/client-two/truststore.jks", keyStorePassword)
                .withClientIdentityRoute(clientAliasesToHosts)
                .build();

        SSLSocketFactory sslSocketFactoryWithCorrectClientRoutes = sslFactoryForClient.getSslSocketFactory();

        Response response = executeRequest("https://localhost:8443/api/hello", sslSocketFactoryWithCorrectClientRoutes);

        assertThat(response.getStatusCode()).isEqualTo(200);
        assertThat(response.getBody()).contains("Hello from server one");

        response = executeRequest("https://localhost:8444/api/hello", sslSocketFactoryWithCorrectClientRoutes);

        assertThat(response.getStatusCode()).isEqualTo(200);
        assertThat(response.getBody()).contains("Hello from server two");

        sslFactoryForClient = SSLFactory.builder()
                .withIdentityMaterial("keystores-for-unit-tests/client-server/client-one/identity.jks", keyStorePassword)
                .withIdentityMaterial("keystores-for-unit-tests/client-server/client-two/identity.jks", keyStorePassword)
                .withTrustMaterial("keystores-for-unit-tests/client-server/client-one/truststore.jks", keyStorePassword)
                .withTrustMaterial("keystores-for-unit-tests/client-server/client-two/truststore.jks", keyStorePassword)
                .withClientIdentityRoute("client-one", "https://localhost:8444/api/hello")
                .withClientIdentityRoute("client-two", "https://localhost:8443/api/hello")
                .build();

        SSLSocketFactory sslSocketFactoryWithIncorrectClientRoutes = sslFactoryForClient.getSslSocketFactory();
        assertThatThrownBy(() -> executeRequest("https://localhost:8443/api/hello", sslSocketFactoryWithIncorrectClientRoutes))
                .isInstanceOfAny(SocketException.class, SSLException.class);
        assertThatThrownBy(() -> executeRequest("https://localhost:8444/api/hello", sslSocketFactoryWithIncorrectClientRoutes))
                .isInstanceOfAny(SocketException.class, SSLException.class);

        serverOne.stop(0);
        serverTwo.stop(0);
        executorService.shutdownNow();
    }

    @Test
    @SuppressWarnings("OptionalGetWithoutIsPresent")
    void executeRequestToTwoServersWithMutualAuthenticationWithSwappingClientIdentityAndTrustMaterial() throws IOException, InterruptedException {
        ExecutorService executorService = Executors.newSingleThreadExecutor();

        char[] keyStorePassword = "secret".toCharArray();

        SSLFactory sslFactoryForServerOne = SSLFactory.builder()
                .withIdentityMaterial("keystores-for-unit-tests/client-server/server-one/identity.jks", keyStorePassword)
                .withTrustMaterial("keystores-for-unit-tests/client-server/server-one/truststore.jks", keyStorePassword)
                .withNeedClientAuthentication()
                .withProtocols("TLSv1.2")
                .build();

        SSLFactory sslFactoryForServerTwo = SSLFactory.builder()
                .withIdentityMaterial("keystores-for-unit-tests/client-server/server-two/identity.jks", keyStorePassword)
                .withTrustMaterial("keystores-for-unit-tests/client-server/server-two/truststore.jks", keyStorePassword)
                .withNeedClientAuthentication()
                .withProtocols("TLSv1.2")
                .build();

        HttpsServer serverOne = ServerUtils.createServer(8443, sslFactoryForServerOne, executorService, "Hello from server one");
        HttpsServer serverTwo = ServerUtils.createServer(8444, sslFactoryForServerTwo, executorService, "Hello from server two");

        serverOne.start();
        serverTwo.start();

        SSLFactory sslFactoryForClient = SSLFactory.builder()
                .withIdentityMaterial("keystores-for-unit-tests/client-server/client-one/identity.jks", keyStorePassword)
                .withTrustMaterial("keystores-for-unit-tests/client-server/client-one/truststore.jks", keyStorePassword)
                .withSwappableIdentityMaterial()
                .withSwappableTrustMaterial()
                .build();

        SSLSocketFactory sslSocketFactory = sslFactoryForClient.getSslSocketFactory();

        Response response = executeRequest("https://localhost:8443/api/hello", sslSocketFactory);
        assertThat(response.getStatusCode()).isEqualTo(200);
        assertThat(response.getBody()).contains("Hello from server one");

        assertThatThrownBy(() -> executeRequest("https://localhost:8444/api/hello", sslSocketFactory))
                .isInstanceOfAny(SocketException.class, SSLException.class);

        X509ExtendedKeyManager swappableKeyManager = sslFactoryForClient.getKeyManager().get();
        X509ExtendedKeyManager toBeSwappedKeyManager = KeyManagerUtils.createKeyManager(
                KeyStoreUtils.loadKeyStore("keystores-for-unit-tests/client-server/client-two/identity.jks", keyStorePassword), "secret".toCharArray()
        );

        KeyManagerUtils.swapKeyManager(swappableKeyManager, toBeSwappedKeyManager);

        X509ExtendedTrustManager swappableTrustManager = sslFactoryForClient.getTrustManager().get();
        X509ExtendedTrustManager toBeSwappedTrustManager = TrustManagerUtils.createTrustManager(
                KeyStoreUtils.loadKeyStore("keystores-for-unit-tests/client-server/client-two/truststore.jks", keyStorePassword)
        );

        TrustManagerUtils.swapTrustManager(swappableTrustManager, toBeSwappedTrustManager);

        SSLSessionUtils.invalidateCaches(sslFactoryForClient);

        assertThatThrownBy(() -> executeRequest("https://localhost:8443/api/hello", sslSocketFactory))
                .isInstanceOfAny(SocketException.class, SSLException.class);

        response = executeRequest("https://localhost:8444/api/hello", sslFactoryForClient.getSslSocketFactory());
        assertThat(response.getStatusCode()).isEqualTo(200);
        assertThat(response.getBody()).contains("Hello from server two");

        serverOne.stop(0);
        serverTwo.stop(0);
        executorService.shutdownNow();
    }

    private Response executeRequest(String url, SSLSocketFactory sslSocketFactory) throws IOException {
        HttpsURLConnection connection = (HttpsURLConnection) new URL(url).openConnection();
        connection.setSSLSocketFactory(sslSocketFactory);
        connection.setRequestMethod("GET");

        int statusCode = connection.getResponseCode();
        String body = new BufferedReader(new InputStreamReader(connection.getInputStream(), StandardCharsets.UTF_8))
                .lines()
                .collect(Collectors.joining("\n"));

        connection.disconnect();
        return new Response(statusCode, body);
    }


    private static final class Response {
        private final int statusCode;
        private final String body;

        Response(int statusCode, String body) {
            this.statusCode = statusCode;
            this.body = body;
        }

        public int getStatusCode() {
            return statusCode;
        }

        public String getBody() {
            return body;
        }
    }

}
