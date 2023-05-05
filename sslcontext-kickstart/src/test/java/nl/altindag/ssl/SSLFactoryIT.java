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
package nl.altindag.ssl;

import com.sun.net.httpserver.HttpsServer;
import nl.altindag.ssl.util.SSLFactoryUtils;
import nl.altindag.ssl.util.SSLSessionUtils;
import org.junit.jupiter.api.Test;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSocketFactory;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.SocketException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * @author Hakan Altindag
 */
class SSLFactoryIT {

    @Test
    void executeHttpsRequestWithMutualAuthentication() throws IOException {
        ExecutorService executorService = Executors.newSingleThreadExecutor();

        SSLFactory sslFactoryForServer = SSLFactory.builder()
                .withIdentityMaterial("keystore/client-server/server-one/identity.jks", "secret".toCharArray())
                .withTrustMaterial("keystore/client-server/server-one/truststore.jks", "secret".toCharArray())
                .withNeedClientAuthentication()
                .build();

        HttpsServer server = ServerUtils.createServer(8443, sslFactoryForServer, executorService, "Hello from server");
        server.start();

        SSLFactory sslFactoryForClient = SSLFactory.builder()
                .withIdentityMaterial("keystore/client-server/client-one/identity.jks", "secret".toCharArray())
                .withTrustMaterial("keystore/client-server/client-one/truststore.jks", "secret".toCharArray())
                .build();

        HttpsURLConnection connection = (HttpsURLConnection) new URL("https://localhost:8443/api/hello").openConnection();
        connection.setSSLSocketFactory(sslFactoryForClient.getSslSocketFactory());
        connection.setHostnameVerifier(sslFactoryForClient.getHostnameVerifier());
        connection.setRequestMethod("GET");

        int statusCode = connection.getResponseCode();
        assertThat(statusCode).isEqualTo(200);

        server.stop(0);
        executorService.shutdownNow();
    }

    @Test
    void executeRequestToTwoServersWithMutualAuthenticationWithSingleHttpClientAndSingleSslConfiguration() throws IOException {
        ExecutorService executorService = Executors.newSingleThreadExecutor();

        char[] keyStorePassword = "secret".toCharArray();
        SSLFactory sslFactoryForServerOne = SSLFactory.builder()
                .withIdentityMaterial("keystore/client-server/server-one/identity.jks", keyStorePassword)
                .withTrustMaterial("keystore/client-server/server-one/truststore.jks", keyStorePassword)
                .withNeedClientAuthentication()
                .withProtocols("TLSv1.2")
                .build();

        SSLFactory sslFactoryForServerTwo = SSLFactory.builder()
                .withIdentityMaterial("keystore/client-server/server-two/identity.jks", keyStorePassword)
                .withTrustMaterial("keystore/client-server/server-two/truststore.jks", keyStorePassword)
                .withNeedClientAuthentication()
                .withProtocols("TLSv1.2")
                .build();

        HttpsServer serverOne = ServerUtils.createServer(8443, sslFactoryForServerOne, executorService, "Hello from server one");
        HttpsServer serverTwo = ServerUtils.createServer(8444, sslFactoryForServerTwo, executorService, "Hello from server two");

        serverOne.start();
        serverTwo.start();

        SSLFactory sslFactoryForClient = SSLFactory.builder()
                .withIdentityMaterial("keystore/client-server/client-one/identity.jks", keyStorePassword)
                .withIdentityMaterial("keystore/client-server/client-two/identity.jks", keyStorePassword)
                .withTrustMaterial("keystore/client-server/client-one/truststore.jks", keyStorePassword)
                .withTrustMaterial("keystore/client-server/client-two/truststore.jks", keyStorePassword)
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
                .withIdentityMaterial("keystore/client-server/server-one/identity.jks", keyStorePassword)
                .withTrustMaterial("keystore/client-server/server-one/truststore.jks", keyStorePassword)
                .withNeedClientAuthentication()
                .withSessionTimeout(1)
                .withProtocols("TLSv1.2")
                .build();

        SSLFactory sslFactoryForServerTwo = SSLFactory.builder()
                .withIdentityMaterial("keystore/client-server/server-two/identity.jks", keyStorePassword)
                .withTrustMaterial("keystore/client-server/server-two/truststore.jks", keyStorePassword)
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
                .withIdentityMaterial("keystore/client-server/client-one/identity.jks", keyStorePassword)
                .withIdentityMaterial("keystore/client-server/client-two/identity.jks", keyStorePassword)
                .withTrustMaterial("keystore/client-server/client-one/truststore.jks", keyStorePassword)
                .withTrustMaterial("keystore/client-server/client-two/truststore.jks", keyStorePassword)
                .withIdentityRoute(clientAliasesToHosts)
                .build();

        SSLSocketFactory sslSocketFactoryWithCorrectClientRoutes = sslFactoryForClient.getSslSocketFactory();

        Response response = executeRequest("https://localhost:8443/api/hello", sslSocketFactoryWithCorrectClientRoutes);

        assertThat(response.getStatusCode()).isEqualTo(200);
        assertThat(response.getBody()).contains("Hello from server one");

        response = executeRequest("https://localhost:8444/api/hello", sslSocketFactoryWithCorrectClientRoutes);

        assertThat(response.getStatusCode()).isEqualTo(200);
        assertThat(response.getBody()).contains("Hello from server two");

        sslFactoryForClient = SSLFactory.builder()
                .withIdentityMaterial("keystore/client-server/client-one/identity.jks", keyStorePassword)
                .withIdentityMaterial("keystore/client-server/client-two/identity.jks", keyStorePassword)
                .withTrustMaterial("keystore/client-server/client-one/truststore.jks", keyStorePassword)
                .withTrustMaterial("keystore/client-server/client-two/truststore.jks", keyStorePassword)
                .withIdentityRoute("client-one", "https://localhost:8444/api/hello")
                .withIdentityRoute("client-two", "https://localhost:8443/api/hello")
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
    void executeRequestToTwoServersWithMutualAuthenticationWithSwappingClientIdentityAndTrustMaterial() throws IOException {
        ExecutorService executorService = Executors.newSingleThreadExecutor();

        char[] keyStorePassword = "secret".toCharArray();

        SSLFactory sslFactoryForServerOne = SSLFactory.builder()
                .withIdentityMaterial("keystore/client-server/server-one/identity.jks", keyStorePassword)
                .withTrustMaterial("keystore/client-server/server-one/truststore.jks", keyStorePassword)
                .withNeedClientAuthentication()
                .withProtocols("TLSv1.2")
                .build();

        SSLFactory sslFactoryForServerTwo = SSLFactory.builder()
                .withIdentityMaterial("keystore/client-server/server-two/identity.jks", keyStorePassword)
                .withTrustMaterial("keystore/client-server/server-two/truststore.jks", keyStorePassword)
                .withNeedClientAuthentication()
                .withProtocols("TLSv1.2")
                .build();

        HttpsServer serverOne = ServerUtils.createServer(8443, sslFactoryForServerOne, executorService, "Hello from server one");
        HttpsServer serverTwo = ServerUtils.createServer(8444, sslFactoryForServerTwo, executorService, "Hello from server two");

        serverOne.start();
        serverTwo.start();

        SSLFactory sslFactoryForClient = SSLFactory.builder()
                .withIdentityMaterial("keystore/client-server/client-one/identity.jks", keyStorePassword)
                .withTrustMaterial("keystore/client-server/client-one/truststore.jks", keyStorePassword)
                .withSwappableIdentityMaterial()
                .withSwappableTrustMaterial()
                .build();

        SSLSocketFactory sslSocketFactory = sslFactoryForClient.getSslSocketFactory();

        Response response = executeRequest("https://localhost:8443/api/hello", sslSocketFactory);
        assertThat(response.getStatusCode()).isEqualTo(200);
        assertThat(response.getBody()).contains("Hello from server one");

        assertThatThrownBy(() -> executeRequest("https://localhost:8444/api/hello", sslSocketFactory))
                .isInstanceOfAny(SocketException.class, SSLException.class);

        SSLFactory updatedSslFactoryForClient = SSLFactory.builder()
                .withIdentityMaterial("keystore/client-server/client-two/identity.jks", keyStorePassword)
                .withTrustMaterial("keystore/client-server/client-two/truststore.jks", keyStorePassword)
                .build();

        SSLFactoryUtils.reload(sslFactoryForClient, updatedSslFactoryForClient);

        assertThatThrownBy(() -> executeRequest("https://localhost:8443/api/hello", sslSocketFactory))
                .isInstanceOfAny(SocketException.class, SSLException.class);

        response = executeRequest("https://localhost:8444/api/hello", sslFactoryForClient.getSslSocketFactory());
        assertThat(response.getStatusCode()).isEqualTo(200);
        assertThat(response.getBody()).contains("Hello from server two");

        serverOne.stop(0);
        serverTwo.stop(0);
        executorService.shutdownNow();
    }

    @Test
    void executeRequestToTwoServersWithMutualAuthenticationWithSwappingClientIdentityAndTrustMaterialWhileDisablingInstantlyInvalidatingSslCaches() throws IOException {
        ExecutorService executorService = Executors.newSingleThreadExecutor();

        char[] keyStorePassword = "secret".toCharArray();

        SSLFactory sslFactoryForServerOne = SSLFactory.builder()
                .withIdentityMaterial("keystore/client-server/server-one/identity.jks", keyStorePassword)
                .withTrustMaterial("keystore/client-server/server-one/truststore.jks", keyStorePassword)
                .withNeedClientAuthentication()
                .withProtocols("TLSv1.2")
                .build();

        SSLFactory sslFactoryForServerTwo = SSLFactory.builder()
                .withIdentityMaterial("keystore/client-server/server-two/identity.jks", keyStorePassword)
                .withTrustMaterial("keystore/client-server/server-two/truststore.jks", keyStorePassword)
                .withNeedClientAuthentication()
                .withProtocols("TLSv1.2")
                .build();

        HttpsServer serverOne = ServerUtils.createServer(8443, sslFactoryForServerOne, executorService, "Hello from server one");
        HttpsServer serverTwo = ServerUtils.createServer(8444, sslFactoryForServerTwo, executorService, "Hello from server two");

        serverOne.start();
        serverTwo.start();

        SSLFactory sslFactoryForClient = SSLFactory.builder()
                .withIdentityMaterial("keystore/client-server/client-one/identity.jks", keyStorePassword)
                .withTrustMaterial("keystore/client-server/client-one/truststore.jks", keyStorePassword)
                .withSwappableIdentityMaterial()
                .withSwappableTrustMaterial()
                .build();

        SSLSocketFactory sslSocketFactory = sslFactoryForClient.getSslSocketFactory();

        Response response = executeRequest("https://localhost:8443/api/hello", sslSocketFactory);
        assertThat(response.getStatusCode()).isEqualTo(200);
        assertThat(response.getBody()).contains("Hello from server one");

        assertThatThrownBy(() -> executeRequest("https://localhost:8444/api/hello", sslSocketFactory))
                .isInstanceOfAny(SocketException.class, SSLException.class);

        SSLFactory updatedSslFactoryForClient = SSLFactory.builder()
                .withIdentityMaterial("keystore/client-server/client-two/identity.jks", keyStorePassword)
                .withTrustMaterial("keystore/client-server/client-two/truststore.jks", keyStorePassword)
                .build();

        SSLFactoryUtils.reload(sslFactoryForClient, updatedSslFactoryForClient, false);

        response = executeRequest("https://localhost:8443/api/hello", sslSocketFactory);
        assertThat(response.getStatusCode()).isEqualTo(200);
        assertThat(response.getBody()).contains("Hello from server one");

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
                .collect(Collectors.joining(System.lineSeparator()));

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
