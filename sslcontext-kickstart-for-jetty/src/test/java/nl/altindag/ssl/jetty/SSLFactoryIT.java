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
package nl.altindag.ssl.jetty;

import nl.altindag.ssl.SSLFactory;
import nl.altindag.ssl.jetty.util.JettySslUtils;
import nl.altindag.ssl.server.service.Server;
import org.eclipse.jetty.client.HttpClient;
import org.eclipse.jetty.client.api.ContentResponse;
import org.eclipse.jetty.client.api.Request;
import org.eclipse.jetty.http.HttpMethod;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLParameters;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * @author Hakan Altindag
 */
class SSLFactoryIT {

    @Test
    void executeHttpsRequestWithMutualAuthentication() throws Exception {
        SSLFactory sslFactoryForServer = SSLFactory.builder()
                .withIdentityMaterial("keystore/client-server/server-one/identity.jks", "secret".toCharArray())
                .withTrustMaterial("keystore/client-server/server-one/truststore.jks", "secret".toCharArray())
                .withNeedClientAuthentication()
                .build();

        Server server = Server.createDefault(sslFactoryForServer);

        SSLFactory sslFactoryForClient = SSLFactory.builder()
                .withIdentityMaterial("keystore/client-server/client-one/identity.jks", "secret".toCharArray())
                .withTrustMaterial("keystore/client-server/client-one/truststore.jks", "secret".toCharArray())
                .build();

        SslContextFactory.Client sslContextFactory = JettySslUtils.forClient(sslFactoryForClient);

        HttpClient httpClient = new HttpClient(sslContextFactory);
        httpClient.start();

        ContentResponse contentResponse = httpClient.newRequest("https://localhost:8443/api/hello")
                .method(HttpMethod.GET)
                .send();

        httpClient.stop();

        int statusCode = contentResponse.getStatus();
        assertThat(statusCode).isEqualTo(200);

        server.stop();
    }

    @Test
    void swapCiphersWhileUsingJetty() throws Exception {
        SSLFactory sslFactoryForServer = SSLFactory.builder()
                .withIdentityMaterial("keystore/client-server/server-one/identity.jks", "secret".toCharArray())
                .withTrustMaterial("keystore/client-server/server-one/truststore.jks", "secret".toCharArray())
                .withNeedClientAuthentication()
                .withCiphers("TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256")
                .withSwappableSslParameters()
                .build();

        JettyServer jettyServer = new JettyServer(sslFactoryForServer);

        SSLFactory sslFactoryForClient = SSLFactory.builder()
                .withIdentityMaterial("keystore/client-server/client-one/identity.jks", "secret".toCharArray())
                .withTrustMaterial("keystore/client-server/client-one/truststore.jks", "secret".toCharArray())
                .build();

        SslContextFactory.Client sslContextFactory = JettySslUtils.forClient(sslFactoryForClient);
        HttpClient httpClient = new HttpClient(sslContextFactory);
        httpClient.start();

        Request request = httpClient.newRequest("https://localhost:8432/api/hello")
                .method(HttpMethod.GET);

        assertThatThrownBy(request::send).hasMessageContaining("Received fatal alert: handshake_failure");

        SSLParameters sslParameters = sslFactoryForServer.getSslParameters();
        sslParameters.setCipherSuites(sslFactoryForClient.getCiphers().toArray(new String[0]));

        ContentResponse contentResponse = httpClient.newRequest("https://localhost:8432/api/hello")
                .method(HttpMethod.GET)
                .send();

        int statusCode = contentResponse.getStatus();
        assertThat(statusCode).isEqualTo(200);

        httpClient.stop();
        jettyServer.stop();
    }

}
