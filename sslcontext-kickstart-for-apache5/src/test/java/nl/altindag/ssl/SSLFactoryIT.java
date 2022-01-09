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

package nl.altindag.ssl;

import nl.altindag.log.LogCaptor;
import nl.altindag.ssl.util.Apache5SslUtils;
import nl.altindag.ssl.util.KeyStoreUtils;
import org.apache.hc.client5.http.async.methods.SimpleHttpResponse;
import org.apache.hc.client5.http.async.methods.SimpleResponseConsumer;
import org.apache.hc.client5.http.classic.HttpClient;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.impl.async.CloseableHttpAsyncClient;
import org.apache.hc.client5.http.impl.async.HttpAsyncClients;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManager;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.impl.nio.PoolingAsyncClientConnectionManager;
import org.apache.hc.client5.http.impl.nio.PoolingAsyncClientConnectionManagerBuilder;
import org.apache.hc.client5.http.socket.LayeredConnectionSocketFactory;
import org.apache.hc.core5.http.HttpResponse;
import org.apache.hc.core5.http.Method;
import org.apache.hc.core5.http.nio.support.BasicRequestProducer;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;

/**
 * @author Hakan Altindag
 */
class SSLFactoryIT {

    @Test
    @Tag("it-with-badssl.com")
    void executeHttpsRequestWithMutualAuthentication() throws IOException {
        LogCaptor logCaptor = LogCaptor.forName("nl.altindag.ssl");

        SSLFactory sslFactory = SSLFactory.builder()
                .withIdentityMaterial("keystore/badssl-identity.p12", "badssl.com".toCharArray())
                .withTrustMaterial("keystore/badssl-truststore.p12", "badssl.com".toCharArray())
                .withTrustMaterial(KeyStoreUtils.createKeyStore()) // Adding additional trust material forces usage of CompositeX509ExtendedTrustManager and verbose logging
                .build();

        LayeredConnectionSocketFactory socketFactory = Apache5SslUtils.toSocketFactory(sslFactory);
        PoolingHttpClientConnectionManager connectionManager = PoolingHttpClientConnectionManagerBuilder.create()
                .setSSLSocketFactory(socketFactory)
                .build();

        HttpClient httpClient = HttpClients.custom()
                .setConnectionManager(connectionManager)
                .build();

        HttpGet request = new HttpGet("https://client.badssl.com/");
        HttpResponse response = httpClient.execute(request);

        logCaptor.close();

        int statusCode = response.getCode();
        if (statusCode == 400) {
            fail("Certificate may have expired and needs to be updated");
        } else {
            assertThat(statusCode).isEqualTo(200);
            assertThat(logCaptor.getLogs()).contains("Received the following server certificate: [CN=*.badssl.com, O=Lucas Garron Torres, L=Walnut Creek, ST=California, C=US]");
        }
    }

    @Test
    @Tag("it-with-badssl.com")
    void executeHttpsRequestWithMutualAuthenticationForAsyncClient() throws IOException, URISyntaxException, InterruptedException, ExecutionException, TimeoutException {
        LogCaptor logCaptor = LogCaptor.forName("nl.altindag.ssl");

        SSLFactory sslFactory = SSLFactory.builder()
                .withIdentityMaterial("keystore/badssl-identity.p12", "badssl.com".toCharArray())
                .withTrustMaterial("keystore/badssl-truststore.p12", "badssl.com".toCharArray())
                .withTrustMaterial(KeyStoreUtils.createKeyStore()) // Adding additional trust material forces usage of CompositeX509ExtendedTrustManager and verbose logging
                .build();

        PoolingAsyncClientConnectionManager connectionManager = PoolingAsyncClientConnectionManagerBuilder.create()
                .setTlsStrategy(Apache5SslUtils.toTlsStrategy(sslFactory))
                .build();

        CloseableHttpAsyncClient httpAsyncClient = HttpAsyncClients.custom()
                .setConnectionManager(connectionManager)
                .build();

        httpAsyncClient.start();

        SimpleHttpResponse response = httpAsyncClient.execute(
                new BasicRequestProducer(Method.GET, new URI("https://client.badssl.com/")),
                SimpleResponseConsumer.create(), null, null, null)
                .get(10, TimeUnit.SECONDS);

        logCaptor.close();

        int statusCode = response.getCode();
        if (statusCode == 400) {
            fail("Certificate may have expired and needs to be updated");
        } else {
            assertThat(statusCode).isEqualTo(200);
            assertThat(logCaptor.getLogs()).contains("Received the following server certificate: [CN=*.badssl.com, O=Lucas Garron Torres, L=Walnut Creek, ST=California, C=US]");
        }
    }

}
