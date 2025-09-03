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

import nl.altindag.ssl.server.service.Server;
import nl.altindag.ssl.util.KeyStoreUtils;
import nl.altindag.ssl.util.ProviderUtils;
import nl.altindag.ssl.util.SSLFactoryUtils;
import nl.altindag.ssl.util.SSLSessionUtils;
import nl.altindag.ssl.util.TrustManagerUtils;
import org.junit.jupiter.api.Test;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.X509ExtendedTrustManager;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.SocketException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CertificateException;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.catchThrowableOfType;

/**
 * @author Hakan Altindag
 */
class SSLFactoryIT {

    @Test
    void executeHttpsRequestWithMutualAuthentication() throws IOException {
        SSLFactory sslFactoryForServer = SSLFactory.builder()
                .withIdentityMaterial("keystore/client-server/server-one/identity.jks", "secret".toCharArray())
                .withTrustMaterial("keystore/client-server/server-one/truststore.jks", "secret".toCharArray())
                .withNeedClientAuthentication()
                .withProtocols("TLSv1.3")
                .build();

        Server server = Server.createDefault(sslFactoryForServer, 8999);

        SSLFactory sslFactoryForClient = SSLFactory.builder()
                .withIdentityMaterial("keystore/client-server/client-one/identity.jks", "secret".toCharArray())
                .withTrustMaterial("keystore/client-server/client-one/truststore.jks", "secret".toCharArray())
                .build();

        Response response = executeRequest("https://localhost:8999/api/hello", sslFactoryForClient.getSslSocketFactory());
        assertThat(response.getStatusCode()).isEqualTo(200);

        server.stop();
    }

    @Test
    void executeHttpsRequestWithMutualAuthenticationWhileHavingConcealedTrustMaterial() throws IOException {
        SSLFactory sslFactoryForServer = SSLFactory.builder()
                .withIdentityMaterial("keystore/client-server/server-one/identity.jks", "secret".toCharArray())
                .withTrustMaterial("keystore/client-server/server-one/truststore.jks", "secret".toCharArray())
                .withConcealedTrustMaterial()
                .withNeedClientAuthentication()
                .withProtocols("TLSv1.3")
                .build();

        Server server = Server.createDefault(sslFactoryForServer, 8998);

        SSLFactory sslFactoryForClient = SSLFactory.builder()
                .withIdentityMaterial("keystore/client-server/client-one/identity.jks", "secret".toCharArray())
                .withTrustMaterial("keystore/client-server/client-one/truststore.jks", "secret".toCharArray())
                .build();

        Response response = executeRequest("https://localhost:8998/api/hello", sslFactoryForClient.getSslSocketFactory());
        assertThat(response.getStatusCode()).isEqualTo(200);

        server.stop();
    }

    @Test
    void executeRequestToTwoServersWithMutualAuthenticationWithSingleHttpClientAndSingleSslConfiguration() throws IOException {
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

        Server serverOne = Server.createDefault(sslFactoryForServerOne, 8997, "Hello from server one");
        Server serverTwo = Server.createDefault(sslFactoryForServerTwo, 8996, "Hello from server two");

        SSLFactory sslFactoryForClient = SSLFactory.builder()
                .withIdentityMaterial("keystore/client-server/client-one/identity.jks", keyStorePassword)
                .withIdentityMaterial("keystore/client-server/client-two/identity.jks", keyStorePassword)
                .withTrustMaterial("keystore/client-server/client-one/truststore.jks", keyStorePassword)
                .withTrustMaterial("keystore/client-server/client-two/truststore.jks", keyStorePassword)
                .withProtocols("TLSv1.2")
                .build();

        Response response = executeRequest("https://localhost:8997/api/hello", sslFactoryForClient.getSslSocketFactory());

        assertThat(response.getStatusCode()).isEqualTo(200);
        assertThat(response.getBody()).contains("Hello from server one");

        response = executeRequest("https://localhost:8996/api/hello", sslFactoryForClient.getSslSocketFactory());

        assertThat(response.getStatusCode()).isEqualTo(200);
        assertThat(response.getBody()).contains("Hello from server two");

        serverOne.stop();
        serverTwo.stop();
    }

    @Test
    void executeRequestToTwoServersWithMutualAuthenticationWithReroutingClientCertificates() throws IOException {
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

        Server serverOne = Server.createDefault(sslFactoryForServerOne, 8995, "Hello from server one");
        Server serverTwo = Server.createDefault(sslFactoryForServerTwo, 8994, "Hello from server two");

        Map<String, List<String>> clientAliasesToHosts = new HashMap<>();
        clientAliasesToHosts.put("client-one", Collections.singletonList("https://localhost:8995/api/hello"));
        clientAliasesToHosts.put("client-two", Collections.singletonList("https://localhost:8994/api/hello"));

        SSLFactory sslFactoryForClient = SSLFactory.builder()
                .withIdentityMaterial("keystore/client-server/client-one/identity.jks", keyStorePassword)
                .withIdentityMaterial("keystore/client-server/client-two/identity.jks", keyStorePassword)
                .withTrustMaterial("keystore/client-server/client-one/truststore.jks", keyStorePassword)
                .withTrustMaterial("keystore/client-server/client-two/truststore.jks", keyStorePassword)
                .withIdentityRoute(clientAliasesToHosts)
                .build();

        SSLSocketFactory sslSocketFactoryWithCorrectClientRoutes = sslFactoryForClient.getSslSocketFactory();

        Response response = executeRequest("https://localhost:8995/api/hello", sslSocketFactoryWithCorrectClientRoutes);

        assertThat(response.getStatusCode()).isEqualTo(200);
        assertThat(response.getBody()).contains("Hello from server one");

        response = executeRequest("https://localhost:8994/api/hello", sslSocketFactoryWithCorrectClientRoutes);

        assertThat(response.getStatusCode()).isEqualTo(200);
        assertThat(response.getBody()).contains("Hello from server two");

        sslFactoryForClient = SSLFactory.builder()
                .withIdentityMaterial("keystore/client-server/client-one/identity.jks", keyStorePassword)
                .withIdentityMaterial("keystore/client-server/client-two/identity.jks", keyStorePassword)
                .withTrustMaterial("keystore/client-server/client-one/truststore.jks", keyStorePassword)
                .withTrustMaterial("keystore/client-server/client-two/truststore.jks", keyStorePassword)
                .withIdentityRoute("client-one", "https://localhost:8994/api/hello")
                .withIdentityRoute("client-two", "https://localhost:8995/api/hello")
                .build();

        SSLSocketFactory sslSocketFactoryWithIncorrectClientRoutes = sslFactoryForClient.getSslSocketFactory();
        assertThatThrownBy(() -> executeRequest("https://localhost:8995/api/hello", sslSocketFactoryWithIncorrectClientRoutes))
                .isInstanceOfAny(SocketException.class, SSLException.class);
        assertThatThrownBy(() -> executeRequest("https://localhost:8994/api/hello", sslSocketFactoryWithIncorrectClientRoutes))
                .isInstanceOfAny(SocketException.class, SSLException.class);

        serverOne.stop();
        serverTwo.stop();
    }

    @Test
    void executeRequestToTwoServersWithMutualAuthenticationWithSwappingClientIdentityAndTrustMaterial() throws IOException {
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

        Server serverOne = Server.createDefault(sslFactoryForServerOne, 8993, "Hello from server one");
        Server serverTwo = Server.createDefault(sslFactoryForServerTwo, 8992, "Hello from server two");

        SSLFactory sslFactoryForClient = SSLFactory.builder()
                .withIdentityMaterial("keystore/client-server/client-one/identity.jks", keyStorePassword)
                .withTrustMaterial("keystore/client-server/client-one/truststore.jks", keyStorePassword)
                .withSwappableIdentityMaterial()
                .withSwappableTrustMaterial()
                .build();

        SSLSocketFactory sslSocketFactory = sslFactoryForClient.getSslSocketFactory();

        Response response = executeRequest("https://localhost:8993/api/hello", sslSocketFactory);
        assertThat(response.getStatusCode()).isEqualTo(200);
        assertThat(response.getBody()).contains("Hello from server one");

        assertThatThrownBy(() -> executeRequest("https://localhost:8992/api/hello", sslSocketFactory))
                .isInstanceOfAny(SocketException.class, SSLException.class);

        SSLFactory updatedSslFactoryForClient = SSLFactory.builder()
                .withIdentityMaterial("keystore/client-server/client-two/identity.jks", keyStorePassword)
                .withTrustMaterial("keystore/client-server/client-two/truststore.jks", keyStorePassword)
                .build();

        SSLFactoryUtils.reload(sslFactoryForClient, updatedSslFactoryForClient);

        assertThatThrownBy(() -> executeRequest("https://localhost:8993/api/hello", sslSocketFactory))
                .isInstanceOfAny(SocketException.class, SSLException.class);

        response = executeRequest("https://localhost:8992/api/hello", sslFactoryForClient.getSslSocketFactory());
        assertThat(response.getStatusCode()).isEqualTo(200);
        assertThat(response.getBody()).contains("Hello from server two");

        serverOne.stop();
        serverTwo.stop();
    }

    @Test
    void executeRequestToTwoServersWithMutualAuthenticationWithSwappingClientIdentityAndTrustMaterialWhileDisablingInstantlyInvalidatingSslCaches() throws IOException {
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

        Server serverOne = Server.createDefault(sslFactoryForServerOne, 8991, "Hello from server one");
        Server serverTwo = Server.createDefault(sslFactoryForServerTwo, 8990, "Hello from server two");

        SSLFactory sslFactoryForClient = SSLFactory.builder()
                .withIdentityMaterial("keystore/client-server/client-one/identity.jks", keyStorePassword)
                .withTrustMaterial("keystore/client-server/client-one/truststore.jks", keyStorePassword)
                .withSwappableIdentityMaterial()
                .withSwappableTrustMaterial()
                .build();

        SSLSocketFactory sslSocketFactory = sslFactoryForClient.getSslSocketFactory();

        Response response = executeRequest("https://localhost:8991/api/hello", sslSocketFactory);
        assertThat(response.getStatusCode()).isEqualTo(200);
        assertThat(response.getBody()).contains("Hello from server one");

        assertThatThrownBy(() -> executeRequest("https://localhost:8990/api/hello", sslSocketFactory))
                .isInstanceOfAny(SocketException.class, SSLException.class);

        SSLFactory updatedSslFactoryForClient = SSLFactory.builder()
                .withIdentityMaterial("keystore/client-server/client-two/identity.jks", keyStorePassword)
                .withTrustMaterial("keystore/client-server/client-two/truststore.jks", keyStorePassword)
                .build();

        SSLFactoryUtils.reload(sslFactoryForClient, updatedSslFactoryForClient, false);

        response = executeRequest("https://localhost:8991/api/hello", sslSocketFactory);
        assertThat(response.getStatusCode()).isEqualTo(200);
        assertThat(response.getBody()).contains("Hello from server one");

        SSLSessionUtils.invalidateCaches(sslFactoryForClient);

        assertThatThrownBy(() -> executeRequest("https://localhost:8991/api/hello", sslSocketFactory))
                .isInstanceOfAny(SocketException.class, SSLException.class);

        response = executeRequest("https://localhost:8990/api/hello", sslFactoryForClient.getSslSocketFactory());
        assertThat(response.getStatusCode()).isEqualTo(200);
        assertThat(response.getBody()).contains("Hello from server two");

        serverOne.stop();
        serverTwo.stop();
    }

    @Test
    void throwInvalidAlgorithmParameterExceptionWhenUsingSingleTrustManagerWhichIsConstructedFromAnEmptyKeyStore() {
        SSLFactory sslFactoryForServer = SSLFactory.builder()
                .withIdentityMaterial("keystore/client-server/server-one/identity.jks", "secret".toCharArray())
                .withTrustMaterial("keystore/client-server/server-one/truststore.jks", "secret".toCharArray())
                .withNeedClientAuthentication()
                .build();

        Server server = Server.createDefault(sslFactoryForServer, 8989);

        KeyStore emptyKeyStore = KeyStoreUtils.createKeyStore();
        X509ExtendedTrustManager emptyTrustManager = TrustManagerUtils.createTrustManager(emptyKeyStore);

        SSLFactory sslFactoryForClient = SSLFactory.builder()
                .withTrustMaterial(emptyTrustManager)
                .build();

        SSLException sslException = catchThrowableOfType(() -> executeRequest("https://localhost:8989/api/hello", sslFactoryForClient.getSslSocketFactory()), SSLException.class);

        Throwable cause = sslException.getCause();
        assertThat(cause).isInstanceOf(RuntimeException.class);

        Throwable innerCause = cause.getCause();
        assertThat(innerCause).isInstanceOf(InvalidAlgorithmParameterException.class);
        assertThat(innerCause.getMessage()).contains("the trustAnchors parameter must be non-empty");

        server.stop();
    }

    @Test
    void throwCertificateExceptionWhenUsingMultipleTrustManagersWhichIsConstructedFromAnEmptyKeyStore() {
        SSLFactory sslFactoryForServer = SSLFactory.builder()
                .withIdentityMaterial("keystore/client-server/server-one/identity.jks", "secret".toCharArray())
                .withTrustMaterial("keystore/client-server/server-one/truststore.jks", "secret".toCharArray())
                .withNeedClientAuthentication()
                .build();

        Server server = Server.createDefault(sslFactoryForServer, 8988);

        KeyStore emptyKeyStore = KeyStoreUtils.createKeyStore();
        X509ExtendedTrustManager emptyTrustManager = TrustManagerUtils.createTrustManager(emptyKeyStore);

        SSLFactory sslFactoryForClient = SSLFactory.builder()
                .withTrustMaterial(emptyTrustManager)
                .withTrustMaterial(emptyTrustManager)
                .build();

        SSLException sslException = catchThrowableOfType(() -> executeRequest("https://localhost:8988/api/hello", sslFactoryForClient.getSslSocketFactory()), SSLException.class);

        Throwable cause = sslException.getCause();
        assertThat(cause).isInstanceOf(CertificateException.class);

        Throwable[] suppressed = cause.getSuppressed();
        assertThat(suppressed).hasSize(2);

        for (Throwable throwable : suppressed) {
            assertThat(throwable).isInstanceOf(CertificateException.class);
            assertThat(throwable.getCause()).isInstanceOf(InvalidAlgorithmParameterException.class);
            assertThat(throwable.getMessage()).contains("the trustAnchors parameter must be non-empty");
        }

        server.stop();
    }

    @Test
    void executeRequestToServerWithMutualAuthenticationWithSwappingCiphers() throws IOException {
        char[] keyStorePassword = "secret".toCharArray();

        SSLFactory sslFactoryForServer = SSLFactory.builder()
                .withIdentityMaterial("keystore/client-server/server-one/identity.jks", keyStorePassword)
                .withTrustMaterial("keystore/client-server/server-one/truststore.jks", keyStorePassword)
                .withNeedClientAuthentication()
                .withProtocols("TLSv1.2")
                .build();

        Server server = Server.createDefault(sslFactoryForServer, 8987, "Hello from server one");

        SSLFactory sslFactoryForClient = SSLFactory.builder()
                .withIdentityMaterial("keystore/client-server/client-one/identity.jks", keyStorePassword)
                .withTrustMaterial("keystore/client-server/client-one/truststore.jks", keyStorePassword)
                .withSwappableSslParameters()
                .build();

        SSLSocketFactory sslSocketFactory = sslFactoryForClient.getSslSocketFactory();

        Response response = executeRequest("https://localhost:8987/api/hello", sslSocketFactory);
        assertThat(response.getStatusCode()).isEqualTo(200);
        assertThat(response.getBody()).contains("Hello from server one");

        sslFactoryForClient.getSslParameters().setCipherSuites(new String[]{"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"});

        assertThatThrownBy(() -> executeRequest("https://localhost:8987/api/hello", sslSocketFactory))
                .isInstanceOfAny(SocketException.class, SSLException.class);

        server.stop();
    }

    @Test
    void swapCiphersWhileUsingNetty() throws Exception {
        SSLFactory sslFactoryForServer = SSLFactory.builder()
                .withIdentityMaterial("keystore/client-server/server-one/identity.jks", "secret".toCharArray())
                .withTrustMaterial("keystore/client-server/server-one/truststore.jks", "secret".toCharArray())
                .withNeedClientAuthentication()
                .withCiphers("TLS_DHE_RSA_WITH_AES_128_CBC_SHA")
                .withSwappableSslParameters()
                .build();

        SSLFactory sslFactoryForClient = SSLFactory.builder()
                .withIdentityMaterial("keystore/client-server/client-one/identity.jks", "secret".toCharArray())
                .withTrustMaterial("keystore/client-server/client-one/truststore.jks", "secret".toCharArray())
                .withCiphers("TLS_DHE_RSA_WITH_AES_256_CBC_SHA")
                .build();

        Provider provider = ProviderUtils.create(sslFactoryForServer);
        Security.insertProviderAt(provider, 1);
        Server server = Server.createDefault(sslFactoryForServer, 8986);

        assertThatThrownBy(() -> executeRequest("https://localhost:8986/api/hello", sslFactoryForClient.getSslSocketFactory()))
                .hasMessageContaining("Received fatal alert: handshake_failure");

        SSLParameters sslParameters = sslFactoryForServer.getSslParameters();
        sslParameters.setCipherSuites(sslFactoryForClient.getCiphers().toArray(new String[0]));

        Response response = executeRequest("https://localhost:8986/api/hello", sslFactoryForClient.getSslSocketFactory());
        assertThat(response.getStatusCode()).isEqualTo(200);

        server.stop();
        Security.removeProvider("Fenix");
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
