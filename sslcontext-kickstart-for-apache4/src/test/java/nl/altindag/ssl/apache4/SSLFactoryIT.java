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
package nl.altindag.ssl.apache4;

import io.javalin.Javalin;
import nl.altindag.ssl.SSLFactory;
import nl.altindag.ssl.apache4.util.Apache4SslUtils;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.conn.socket.LayeredConnectionSocketFactory;
import org.apache.http.impl.client.HttpClients;
import org.junit.jupiter.api.Test;

import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;

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
                .build();

        Javalin server = ServerUtils.createServer(sslFactoryForServer);

        SSLFactory sslFactoryForClient = SSLFactory.builder()
                .withIdentityMaterial("keystore/client-server/client-one/identity.jks", "secret".toCharArray())
                .withTrustMaterial("keystore/client-server/client-one/truststore.jks", "secret".toCharArray())
                .build();

        LayeredConnectionSocketFactory socketFactory = Apache4SslUtils.toSocketFactory(sslFactoryForClient);

        HttpClient httpClient = HttpClients.custom()
                .setSSLSocketFactory(socketFactory)
                .build();

        HttpGet request = new HttpGet("https://localhost:8443/api/hello");
        HttpResponse response = httpClient.execute(request);

        int statusCode = response.getStatusLine().getStatusCode();
        assertThat(statusCode).isEqualTo(200);

        server.stop();
    }

}
